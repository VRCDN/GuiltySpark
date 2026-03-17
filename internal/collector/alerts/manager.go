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
)

// NotificationConfig groups the settings for all notification backends.
type NotificationConfig struct {
	Webhook WebhookConfig
	Email   EmailConfig
	Slack   SlackConfig
}

// WebhookConfig sets up the outbound HTTP webhook.
type WebhookConfig struct {
	Enabled bool
	URL     string
	Secret  string // HMAC-SHA256 key for request signing
}

// EmailConfig is the SMTP settings.
type EmailConfig struct {
	Enabled  bool
	SMTPHost string
	SMTPPort int
	From     string
	To       []string
	Username string
	Password string
}

// SlackConfig just needs a webhook URL.
type SlackConfig struct {
	Enabled    bool
	WebhookURL string
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

// CreateAgentOnline fires when a previously-offline agent comes back.
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

// GetAlert retrieves a single alert.
func (m *Manager) GetAlert(ctx context.Context, id string) (*models.Alert, error) {
	return m.store.GetAlert(ctx, id)
}

// ListAlerts queries alerts with optional filtering.
func (m *Manager) ListAlerts(ctx context.Context, filter models.AlertFilter) ([]*models.Alert, error) {
	return m.store.ListAlerts(ctx, filter)
}

// AcknowledgeAlert marks an alert as acknowledged.
func (m *Manager) AcknowledgeAlert(ctx context.Context, id, by string) error {
	return m.store.AcknowledgeAlert(ctx, id, by)
}

// Notifications

func (m *Manager) notify(alert *models.Alert) {
	if m.cfg.Webhook.Enabled {
		if err := m.sendWebhook(alert); err != nil {
			m.logger.Error("webhook notification failed", "error", err, "alert_id", alert.ID)
		}
	}
	if m.cfg.Email.Enabled {
		if err := m.sendEmail(alert); err != nil {
			m.logger.Error("email notification failed", "error", err, "alert_id", alert.ID)
		}
	}
	if m.cfg.Slack.Enabled {
		if err := m.sendSlack(alert); err != nil {
			m.logger.Error("slack notification failed", "error", err, "alert_id", alert.ID)
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
