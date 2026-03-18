// Package alerts creates alerts, deduplicates them, and fires off notifications.
package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/VRCDN/guiltyspark/internal/collector/storage"
	"github.com/VRCDN/guiltyspark/internal/common/models"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type NotificationConfig struct {
	Webhook        WebhookConfig
	Email          EmailConfig
	Slack          SlackConfig
	Discord        DiscordConfig
	CustomWebhooks []CustomWebhookConfig
}

type WebhookConfig struct {
	Enabled  bool
	URL      string
	Secret   string
	MinLevel models.Severity // only fire for alerts at or above this severity; empty = all
}

type EmailConfig struct {
	Enabled  bool
	SMTPHost string
	SMTPPort int
	From     string
	To       []string
	Username string
	Password string
	MinLevel models.Severity
}

type SlackConfig struct {
	Enabled    bool
	WebhookURL string
	MinLevel   models.Severity
}

type DiscordConfig struct {
	Enabled    bool
	WebhookURL string
	Username   string
	MinLevel   models.Severity
}

// CustomWebhookConfig allows users to define arbitrary HTTP notifications with Go templates.
//
// Available template variables match the fields of alertTemplateData:
//
//	{{.ID}}         {{.AgentID}}     {{.RuleID}}     {{.RuleName}}
//	{{.Severity}}   {{.AlertType}}   {{.Message}}    {{.LogLine}}
//	{{.LogSource}}  {{.MatchedAt}}   {{.ReceivedAt}}
//
// Built-in template functions: upper, lower.
type CustomWebhookConfig struct {
	Name         string
	Enabled      bool
	URL          string
	Method       string            // default "POST"
	ContentType  string            // default "application/json"
	Secret       string            // HMAC-SHA256 signing key
	Headers      map[string]string // extra request headers
	BodyTemplate string
	MinLevel     models.Severity
}

type alertTemplateData struct {
	ID         string
	AgentID    string
	RuleID     string
	RuleName   string
	Severity   string
	AlertType  string
	Message    string
	LogLine    string
	LogSource  string
	MatchedAt  string
	ReceivedAt string
}

func alertToTemplateData(a *models.Alert) alertTemplateData {
	return alertTemplateData{
		ID:         a.ID,
		AgentID:    a.AgentID,
		RuleID:     a.RuleID,
		RuleName:   a.RuleName,
		Severity:   string(a.Severity),
		AlertType:  string(a.AlertType),
		Message:    a.Message,
		LogLine:    a.LogLine,
		LogSource:  a.LogSource,
		MatchedAt:  a.MatchedAt.UTC().Format(time.RFC3339),
		ReceivedAt: a.ReceivedAt.UTC().Format(time.RFC3339),
	}
}

var customWebhookFuncs = template.FuncMap{
	"upper": strings.ToUpper,
	"lower": strings.ToLower,
}

// severityLevel maps a Severity to a comparable integer. Empty string (unset) is treated as info.
func severityLevel(s models.Severity) int {
	switch s {
	case models.SeverityLow:
		return 1
	case models.SeverityMedium:
		return 2
	case models.SeverityHigh:
		return 3
	case models.SeverityCritical:
		return 4
	default: // info or empty
		return 0
	}
}

// dedupKey identifies a (agent, rule) pair for the dedup cache.
type dedupKey struct {
	agentID string
	ruleID  string
}

// Manager creates, deduplicates, and notifies for all alerts.
type Manager struct {
	store  storage.Storage
	cfg    NotificationConfig
	logger *slog.Logger

	// tracks the last fire time per (agent, rule) pair to suppress duplicates
	dedupMu     sync.Mutex
	dedupWindow time.Duration
	dedupCache  map[dedupKey]time.Time
}

// New creates an alert Manager.
func New(store storage.Storage, cfg NotificationConfig, dedupWindow time.Duration, logger *slog.Logger) *Manager {
	if dedupWindow == 0 {
		dedupWindow = 5 * time.Minute
	}
	m := &Manager{
		store:       store,
		cfg:         cfg,
		logger:      logger,
		dedupWindow: dedupWindow,
		dedupCache:  make(map[dedupKey]time.Time),
	}
	// clean up the dedup cache in the background so it doesn't grow forever
	go m.evictDedup()
	return m
}

func (m *Manager) evictDedup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		m.dedupMu.Lock()
		now := time.Now()
		for k, t := range m.dedupCache {
			if now.Sub(t) > m.dedupWindow*2 {
				delete(m.dedupCache, k)
			}
		}
		m.dedupMu.Unlock()
	}
}

// shouldSend checks the dedup cache. Returns false if we fired this (agent, rule) pair too recently.
// Agent online/offline alerts skip dedup entirely — no point suppressing those.
func (m *Manager) shouldSend(agentID, ruleID string, alertType models.AlertType) bool {
	if alertType == models.AlertTypeAgentOffline || alertType == models.AlertTypeAgentOnline {
		return true
	}
	key := dedupKey{agentID: agentID, ruleID: ruleID}
	m.dedupMu.Lock()
	defer m.dedupMu.Unlock()
	if last, ok := m.dedupCache[key]; ok && time.Since(last) < m.dedupWindow {
		return false
	}
	m.dedupCache[key] = time.Now()
	return true
}

// CreateFromLogEvent turns a matched log event into an alert. Returns nil if deduplicated.
func (m *Manager) CreateFromLogEvent(ctx context.Context, ev *models.LogEvent) (*models.Alert, error) {
	if !m.shouldSend(ev.AgentID, ev.RuleID, models.AlertTypeLogMatch) {
		return nil, nil
	}
	alert := &models.Alert{
		ID:         uuid.New().String(),
		AgentID:    ev.AgentID,
		RuleID:     ev.RuleID,
		RuleName:   ev.RuleName,
		Severity:   ev.Severity,
		AlertType:  models.AlertTypeLogMatch,
		Message:    fmt.Sprintf("[%s] %s matched on %s", strings.ToUpper(string(ev.Severity)), ev.RuleName, ev.LogSource),
		LogLine:    ev.LogLine,
		LogSource:  ev.LogSource,
		MatchedAt:  ev.MatchedAt,
		ReceivedAt: time.Now().UTC(),
	}
	return m.persist(ctx, alert)
}

// CreateAgentOffline fires an alert when an agent stops heartbeating.
func (m *Manager) CreateAgentOffline(ctx context.Context, agent *models.Agent) (*models.Alert, error) {
	alert := &models.Alert{
		ID:         uuid.New().String(),
		AgentID:    agent.ID,
		Severity:   models.SeverityHigh,
		AlertType:  models.AlertTypeAgentOffline,
		Message:    fmt.Sprintf("Agent %s (%s) went offline. Last seen: %s", agent.Hostname, agent.Region, agent.LastSeen.Format(time.RFC3339)),
		MatchedAt:  time.Now().UTC(),
		ReceivedAt: time.Now().UTC(),
	}
	return m.persist(ctx, alert)
}

// See above and work it out yourself — this is the opposite of CreateAgentOffline and fires when an agent comes back online.
func (m *Manager) CreateAgentOnline(ctx context.Context, agent *models.Agent) (*models.Alert, error) {
	alert := &models.Alert{
		ID:         uuid.New().String(),
		AgentID:    agent.ID,
		Severity:   models.SeverityInfo,
		AlertType:  models.AlertTypeAgentOnline,
		Message:    fmt.Sprintf("Agent %s (%s) came back online", agent.Hostname, agent.Region),
		MatchedAt:  time.Now().UTC(),
		ReceivedAt: time.Now().UTC(),
	}
	return m.persist(ctx, alert)
}

// persist writes the alert to storage and kicks off notifications in the background.
func (m *Manager) persist(ctx context.Context, alert *models.Alert) (*models.Alert, error) {
	if err := m.store.CreateAlert(ctx, alert); err != nil {
		return nil, fmt.Errorf("save alert: %w", err)
	}
	go m.notify(alert)
	return alert, nil
}

func (m *Manager) GetAlert(ctx context.Context, id string) (*models.Alert, error) {
	return m.store.GetAlert(ctx, id)
}

func (m *Manager) ListAlerts(ctx context.Context, filter models.AlertFilter) ([]*models.Alert, error) {
	return m.store.ListAlerts(ctx, filter)
}

func (m *Manager) AcknowledgeAlert(ctx context.Context, id, by string) error {
	return m.store.AcknowledgeAlert(ctx, id, by)
}

// Notifications

func (m *Manager) notify(alert *models.Alert) {
	level := severityLevel(alert.Severity)
	if m.cfg.Webhook.Enabled && level >= severityLevel(m.cfg.Webhook.MinLevel) {
		if err := m.sendWebhook(alert); err != nil {
			m.logger.Error("webhook notification failed", "error", err, "alert_id", alert.ID)
		}
	}
	if m.cfg.Email.Enabled && level >= severityLevel(m.cfg.Email.MinLevel) {
		if err := m.sendEmail(alert); err != nil {
			m.logger.Error("email notification failed", "error", err, "alert_id", alert.ID)
		}
	}
	if m.cfg.Slack.Enabled && level >= severityLevel(m.cfg.Slack.MinLevel) {
		if err := m.sendSlack(alert); err != nil {
			m.logger.Error("slack notification failed", "error", err, "alert_id", alert.ID)
		}
	}
	if m.cfg.Discord.Enabled && level >= severityLevel(m.cfg.Discord.MinLevel) {
		if err := m.sendDiscord(alert); err != nil {
			m.logger.Error("discord notification failed", "error", err, "alert_id", alert.ID)
		}
	}
	for _, cw := range m.cfg.CustomWebhooks {
		if !cw.Enabled || level < severityLevel(cw.MinLevel) {
			continue
		}
		if err := m.sendCustomWebhook(cw, alert); err != nil {
			m.logger.Error("custom webhook notification failed", "name", cw.Name, "error", err, "alert_id", alert.ID)
		}
	}
}

func (m *Manager) sendWebhook(alert *models.Alert) error {
	body, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, m.cfg.Webhook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GuiltySpark-Collector/1.0")

	if m.cfg.Webhook.Secret != "" {
		// sign the payload so the receiver can verify it came from us
		mac := hmac.New(sha256.New, []byte(m.cfg.Webhook.Secret))
		mac.Write(body)
		req.Header.Set("X-GuiltySpark-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

var emailTpl = template.Must(template.New("alert").Parse(`Subject: [GuiltySpark] {{.Severity}} - {{.Message}}
From: {{.From}}
To: {{.To}}
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

GuiltySpark Alert
=================
Type:     {{.AlertType}}
Severity: {{.Severity}}
Agent ID: {{.AgentID}}
Time:     {{.ReceivedAt}}

Message:
{{.Message}}
{{if .LogLine}}
Log Line:
{{.LogLine}}
{{end}}
{{if .LogSource}}
Source: {{.LogSource}}
{{end}}
`))

func (m *Manager) sendEmail(alert *models.Alert) error {
	cfg := m.cfg.Email
	if len(cfg.To) == 0 {
		return nil
	}

	var buf bytes.Buffer
	if err := emailTpl.Execute(&buf, map[string]interface{}{
		"AlertType":  alert.AlertType,
		"Severity":   strings.ToUpper(string(alert.Severity)),
		"AgentID":    alert.AgentID,
		"ReceivedAt": alert.ReceivedAt.Format(time.RFC3339),
		"Message":    alert.Message,
		"LogLine":    alert.LogLine,
		"LogSource":  alert.LogSource,
		"From":       cfg.From,
		"To":         strings.Join(cfg.To, ", "),
	}); err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.SMTPHost)
	}
	return smtp.SendMail(addr, auth, cfg.From, cfg.To, buf.Bytes())
}

type slackPayload struct {
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Color  string `json:"color"`
	Title  string `json:"title"`
	Text   string `json:"text"`
	Footer string `json:"footer"`
	Ts     int64  `json:"ts"`
}

func (m *Manager) sendSlack(alert *models.Alert) error {
	color := map[models.Severity]string{
		models.SeverityInfo:     "#36a64f",
		models.SeverityLow:      "#a8d8ea",
		models.SeverityMedium:   "#f0a500",
		models.SeverityHigh:     "#e74c3c",
		models.SeverityCritical: "#8e44ad",
	}[alert.Severity]
	if color == "" {
		color = "#cccccc"
	}

	text := fmt.Sprintf("*[%s]* %s", strings.ToUpper(string(alert.Severity)), alert.Message)
	if alert.LogLine != "" {
		text += fmt.Sprintf("\n```%s```", alert.LogLine)
	}

	payload := slackPayload{
		Text: fmt.Sprintf(":rotating_light: GuiltySpark Alert — Agent `%s`", alert.AgentID),
		Attachments: []slackAttachment{{
			Color:  color,
			Title:  fmt.Sprintf("[%s] %s", strings.ToUpper(string(alert.AlertType)), alert.Message),
			Text:   text,
			Footer: fmt.Sprintf("GuiltySpark • %s", alert.ReceivedAt.Format(time.RFC3339)),
			Ts:     alert.ReceivedAt.Unix(),
		}},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(m.cfg.Slack.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// ---- Discord ----------------------------------------------------------------

type discordEmbed struct {
	Title       string              `json:"title"`
	Description string              `json:"description,omitempty"`
	Color       int                 `json:"color"`
	Fields      []discordField      `json:"fields,omitempty"`
	Footer      *discordEmbedFooter `json:"footer,omitempty"`
	Timestamp   string              `json:"timestamp,omitempty"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordEmbedFooter struct {
	Text string `json:"text"`
}

type discordPayload struct {
	Username string         `json:"username,omitempty"`
	Embeds   []discordEmbed `json:"embeds"`
}

func (m *Manager) sendDiscord(alert *models.Alert) error {
	color := map[models.Severity]int{
		models.SeverityInfo:     0x36a64f,
		models.SeverityLow:      0xa8d8ea,
		models.SeverityMedium:   0xf0a500,
		models.SeverityHigh:     0xe74c3c,
		models.SeverityCritical: 0x8e44ad,
	}[alert.Severity]
	if color == 0 {
		color = 0xcccccc
	}

	fields := []discordField{
		{Name: "Agent ID", Value: alert.AgentID, Inline: true},
		{Name: "Severity", Value: strings.ToUpper(string(alert.Severity)), Inline: true},
		{Name: "Type", Value: string(alert.AlertType), Inline: true},
	}
	if alert.RuleName != "" {
		fields = append(fields, discordField{Name: "Rule", Value: alert.RuleName, Inline: true})
	}
	if alert.LogSource != "" {
		fields = append(fields, discordField{Name: "Source", Value: alert.LogSource, Inline: true})
	}

	desc := alert.Message
	if alert.LogLine != "" {
		desc += "\n```\n" + alert.LogLine + "\n```"
	}

	username := m.cfg.Discord.Username
	if username == "" {
		username = "GuiltySpark"
	}

	payload := discordPayload{
		Username: username,
		Embeds: []discordEmbed{{
			Title:       fmt.Sprintf("[%s] %s", strings.ToUpper(string(alert.AlertType)), strings.ToUpper(string(alert.Severity))),
			Description: desc,
			Color:       color,
			Fields:      fields,
			Footer:      &discordEmbedFooter{Text: "GuiltySpark • " + alert.ReceivedAt.Format(time.RFC3339)},
			Timestamp:   alert.ReceivedAt.UTC().Format(time.RFC3339),
		}},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(m.cfg.Discord.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// ---- Custom templated webhooks ----------------------------------------------

func (m *Manager) sendCustomWebhook(cfg CustomWebhookConfig, alert *models.Alert) error {
	tpl, err := template.New(cfg.Name).Funcs(customWebhookFuncs).Parse(cfg.BodyTemplate)
	if err != nil {
		return fmt.Errorf("parse body_template for %q: %w", cfg.Name, err)
	}
	var rendered bytes.Buffer
	if err := tpl.Execute(&rendered, alertToTemplateData(alert)); err != nil {
		return fmt.Errorf("execute body_template for %q: %w", cfg.Name, err)
	}

	contentType := cfg.ContentType
	if contentType == "" {
		contentType = "application/json"
	}

	var bodyBytes []byte
	if contentType == "application/json" {
		var doc interface{}
		if err := yaml.Unmarshal(rendered.Bytes(), &doc); err != nil {
			return fmt.Errorf("body_template for %q did not render to valid YAML: %w", cfg.Name, err)
		}
		bodyBytes, err = json.Marshal(doc)
		if err != nil {
			return fmt.Errorf("marshal rendered body to JSON for %q: %w", cfg.Name, err)
		}
	} else {
		bodyBytes = rendered.Bytes()
	}

	method := cfg.Method
	if method == "" {
		method = http.MethodPost
	}

	req, err := http.NewRequest(method, cfg.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "GuiltySpark-Collector/1.0")
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	if cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(cfg.Secret))
		mac.Write(bodyBytes)
		req.Header.Set("X-GuiltySpark-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("custom webhook %q returned HTTP %d", cfg.Name, resp.StatusCode)
	}
	return nil
}
