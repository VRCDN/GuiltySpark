// Package agent is the top-level wiring for the GuiltySpark agent process.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/VRCDN/guiltyspark/internal/agent/audit"
	agentclient "github.com/VRCDN/guiltyspark/internal/agent/client"
	"github.com/VRCDN/guiltyspark/internal/agent/heartbeat"
	"github.com/VRCDN/guiltyspark/internal/agent/inventory"
	"github.com/VRCDN/guiltyspark/internal/agent/logreader"
	"github.com/VRCDN/guiltyspark/internal/agent/scanner"
	"github.com/VRCDN/guiltyspark/internal/common/models"
	"github.com/google/uuid"
)

// Duration wraps time.Duration so YAML can unmarshal duration strings ("30s", "1h", etc.).
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	dur, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

// LogSourceConfig is one entry from the log_sources config block.
type LogSourceConfig struct {
	Path string   `yaml:"path"`
	Tags []string `yaml:"tags"`
	Type string   `yaml:"type"` // "file" | "docker"
}

// Config is everything we read from the agent's YAML file.
type Config struct {
	Collector struct {
		URL     string   `yaml:"url"`
		Timeout Duration `yaml:"timeout"`
		TLS     struct {
			CACert     string `yaml:"ca_cert"`
			SkipVerify bool   `yaml:"skip_verify"`
		} `yaml:"tls"`
	} `yaml:"collector"`

	Auth struct {
		APIKey          string `yaml:"api_key"`
		RegistrationKey string `yaml:"registration_key"`
	} `yaml:"auth"`

	Agent struct {
		ID     string   `yaml:"id"`
		Tags   []string `yaml:"tags"`
		Region string   `yaml:"region"`
	} `yaml:"agent"`

	Heartbeat struct {
		Interval Duration `yaml:"interval"`
	} `yaml:"heartbeat"`

	LogSources []LogSourceConfig `yaml:"log_sources"`

	Docker struct {
		Enabled       bool     `yaml:"enabled"`
		Socket        string   `yaml:"socket"`
		ContainerTags []string `yaml:"container_tags"`
	} `yaml:"docker"`

	Inventory struct {
		Enabled  bool     `yaml:"enabled"`
		Interval Duration `yaml:"interval"`
	} `yaml:"inventory"`

	Audit struct {
		Enabled   bool `yaml:"enabled"`
		FileWatch struct {
			Enabled bool     `yaml:"enabled"`
			Paths   []string `yaml:"paths"`
		} `yaml:"file_watch"`
		Exec struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"exec"`
	} `yaml:"audit"`

	StateFile string `yaml:"state_file"`
	LogLevel  string `yaml:"log_level"`
	LogFormat string `yaml:"log_format"`
	LogFile   string `yaml:"log_file"`
}

// DefaultConfig returns reasonable defaults. Most get overridden by the config file.
func DefaultConfig() Config {
	var cfg Config
	cfg.Collector.URL = "http://localhost:9900"
	cfg.Collector.Timeout.Duration = 30 * time.Second
	cfg.Heartbeat.Interval.Duration = 30 * time.Second
	cfg.Inventory.Enabled = true
	cfg.Inventory.Interval.Duration = 1 * time.Hour
	cfg.Audit.Enabled = true
	cfg.Audit.FileWatch.Enabled = true
	cfg.Audit.FileWatch.Paths = []string{"/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"}
	cfg.Audit.Exec.Enabled = true
	cfg.Docker.Socket = "/var/run/docker.sock"
	cfg.Docker.ContainerTags = []string{"docker"}
	cfg.StateFile = "/var/lib/guiltyspark-agent/state.json"
	cfg.LogLevel = "info"
	cfg.LogFormat = "json"
	cfg.LogFile = "/var/log/guiltyspark/agent.log"
	// Non-existent paths are silently skipped. Tags reflect what each distro actually routes to each file.
	cfg.LogSources = []LogSourceConfig{
		// ── Debian / Ubuntu ─────────────────────────────────────────────────
		{Path: "/var/log/syslog", Tags: []string{"syslog", "cron", "daemon"}},
		{Path: "/var/log/auth.log", Tags: []string{"syslog", "sshd", "auth", "pam", "sudo"}},
		{Path: "/var/log/kern.log", Tags: []string{"syslog", "kernel"}},
		{Path: "/var/log/dpkg.log", Tags: []string{"syslog", "packages"}},
		// ── RHEL / CentOS / Fedora ───────────────────────────────────────────
		{Path: "/var/log/messages", Tags: []string{"syslog", "kernel", "cron", "daemon"}},
		{Path: "/var/log/secure", Tags: []string{"syslog", "sshd", "auth", "pam", "sudo"}},
		{Path: "/var/log/audit/audit.log", Tags: []string{"auth", "audit"}},
		// Alpine — BusyBox syslogd dumps everything here. Tag [syslog] only;
		// platform-scoped rules on the collector handle the rest.
		{Path: "/var/log/messages", Tags: []string{"syslog"}},
	}
	return cfg
}

// LoadConfig reads the YAML file and merges it on top of the defaults.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read agent config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse agent config: %w", err)
	}
	return cfg, nil
}

// State is what we write to disk so credentials survive a restart.
type State struct {
	AgentID      string `json:"agent_id"`
	APIKey       string `json:"api_key"`
	RulesVersion string `json:"rules_version"`
}

func loadState(path string) State {
	var s State
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	_ = json.Unmarshal(data, &s)
	return s
}

func saveState(path string, s State) error {
	if err := os.MkdirAll(dirOf(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Agent is the main struct — everything the agent needs to do its job.
type Agent struct {
	cfg    Config
	state  State
	logger *slog.Logger
	client *agentclient.Client
}

// New sets up the agent. Registration happens later in Run.
func New(cfg Config, logger *slog.Logger) (*Agent, error) {
	state := loadState(cfg.StateFile)

	// set up the HTTP client with whatever TLS settings we have
	clientCfg := agentclient.Config{
		CollectorURL: cfg.Collector.URL,
		APIKey:       state.APIKey,
		AgentID:      state.AgentID,
		CACertFile:   cfg.Collector.TLS.CACert,
		SkipVerify:   cfg.Collector.TLS.SkipVerify,
		Timeout:      cfg.Collector.Timeout.Duration,
	}
	c, err := agentclient.New(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}

	a := &Agent{cfg: cfg, state: state, logger: logger, client: c}
	return a, nil
}

// register introduces the agent to the collector and gets back credentials.
func (a *Agent) register(ctx context.Context) error {
	hostname, _ := os.Hostname()
	ips := collectIPAddresses()
	req := models.RegisterRequest{
		Hostname:        hostname,
		IPAddresses:     ips,
		Tags:            a.cfg.Agent.Tags,
		Version:         models.Version,
		Region:          a.cfg.Agent.Region,
		OS:              detectOS(),
		RegistrationKey: a.cfg.Auth.RegistrationKey,
	}
	resp, err := a.client.Register(ctx, req)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	a.state.AgentID = resp.AgentID
	a.state.APIKey = resp.APIKey
	if err := saveState(a.cfg.StateFile, a.state); err != nil {
		a.logger.Warn("save agent state", "error", err)
	}

	// rebuild the client now that we have a real API key
	clientCfg := agentclient.Config{
		CollectorURL: a.cfg.Collector.URL,
		APIKey:       a.state.APIKey,
		AgentID:      a.state.AgentID,
		CACertFile:   a.cfg.Collector.TLS.CACert,
		SkipVerify:   a.cfg.Collector.TLS.SkipVerify,
		Timeout:      a.cfg.Collector.Timeout.Duration,
	}
	c, err := agentclient.New(clientCfg)
	if err != nil {
		return fmt.Errorf("rebuild client: %w", err)
	}
	a.client = c
	a.logger.Info("agent registered", "agent_id", a.state.AgentID)
	return nil
}

// Run is the main loop — registers if needed, starts all the goroutines, then waits for shutdown.
func (a *Agent) Run(ctx context.Context) error {
	// first boot — we don't have credentials yet
	if a.state.AgentID == "" || a.state.APIKey == "" {
		if err := a.register(ctx); err != nil {
			return fmt.Errorf("registration failed: %w", err)
		}
	}

	// grab rules before we start scanning so we don't miss anything
	sc := scanner.New(a.logger)
	sc.SetOS(detectOSID())
	a.syncRules(ctx, sc)

	hb := heartbeat.New(a.client, a.state.AgentID, a.cfg.Heartbeat.Interval.Duration, a.logger)
	hb.SetRulesVersion(a.state.RulesVersion)

	sources := buildLogSources(a.cfg)
	logMgr := logreader.New(
		sources,
		a.cfg.Docker.Enabled,
		a.cfg.Docker.Socket,
		a.cfg.Docker.ContainerTags,
		a.logger,
	)

	// audit is optional — skip the whole subsystem if disabled
	var auditMgr *audit.Manager
	if a.cfg.Audit.Enabled {
		auditMgr = audit.New(
			a.state.AgentID,
			a.cfg.Audit.FileWatch.Enabled,
			a.cfg.Audit.FileWatch.Paths,
			a.cfg.Audit.Exec.Enabled,
			a.logger,
		)
	}

	invCollector := inventory.New(a.state.AgentID, a.logger)

	go hb.Run(ctx)

	// re-sync rules when the collector says they've changed
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hb.RulesUpdated():
				a.syncRules(ctx, sc)
				hb.SetRulesVersion(a.state.RulesVersion)
			}
		}
	}()

	go logMgr.Run(ctx)
	go sc.Run(ctx, logMgr.Lines())
	go a.runEventSender(ctx, sc.Events())

	if auditMgr != nil {
		go auditMgr.Run(ctx)
		go a.runAuditSender(ctx, auditMgr.Events())
	}

	if a.cfg.Inventory.Enabled {
		go a.runInventoryLoop(ctx, invCollector)
	}

	// block until we're told to stop
	<-ctx.Done()
	a.logger.Info("agent shutting down")
	return nil
}

func (a *Agent) syncRules(ctx context.Context, sc *scanner.Scanner) {
	resp, err := a.client.GetRules(ctx)
	if err != nil {
		a.logger.Warn("sync rules", "error", err)
		return
	}
	sc.UpdateRules(resp.Rules, resp.Version)
	a.state.RulesVersion = resp.Version
	_ = saveState(a.cfg.StateFile, a.state)
}

// runEventSender batches up to 100 events or flushes every 5 seconds, whichever comes first.

const (
	batchMaxSize = 100
	batchMaxWait = 5 * time.Second
)

func (a *Agent) runEventSender(ctx context.Context, events <-chan models.LogEvent) {
	var batch []models.LogEvent
	ticker := time.NewTicker(batchMaxWait)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		// stamp our agent ID on each event before sending
		for i := range batch {
			batch[i].AgentID = a.state.AgentID
		}
		if err := a.client.SendLogEvents(ctx, batch); err != nil {
			a.logger.Warn("send log events", "error", err, "count", len(batch))
		} else {
			a.logger.Debug("sent log events", "count", len(batch))
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case ev, ok := <-events:
			if !ok {
				flush()
				return
			}
			batch = append(batch, ev)
			if len(batch) >= batchMaxSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// runAuditSender is the same deal as runEventSender but for audit events.

func (a *Agent) runAuditSender(ctx context.Context, events <-chan models.AuditEvent) {
	var batch []models.AuditEvent
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		for i := range batch {
			batch[i].AgentID = a.state.AgentID
			if batch[i].ID == "" {
				batch[i].ID = uuid.New().String()
			}
		}
		if err := a.client.SendAuditEvents(ctx, batch); err != nil {
			a.logger.Warn("send audit events", "error", err, "count", len(batch))
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case ev, ok := <-events:
			if !ok {
				flush()
				return
			}
			batch = append(batch, ev)
			if len(batch) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (a *Agent) runInventoryLoop(ctx context.Context, col *inventory.Collector) {
	// collect right away, then tick on the interval
	a.collectAndSendInventory(ctx, col)

	ticker := time.NewTicker(a.cfg.Inventory.Interval.Duration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.collectAndSendInventory(ctx, col)
		}
	}
}

func (a *Agent) collectAndSendInventory(ctx context.Context, col *inventory.Collector) {
	a.logger.Info("collecting system inventory")
	inv, err := col.Collect(ctx)
	if err != nil {
		a.logger.Warn("collect inventory", "error", err)
		return
	}
	if err := a.client.SendInventory(ctx, inv); err != nil {
		a.logger.Warn("send inventory", "error", err)
		return
	}
	a.logger.Info("inventory sent")
}

func buildLogSources(cfg Config) []logreader.SourceConfig {
	var sources []logreader.SourceConfig
	for _, s := range cfg.LogSources {
		t := s.Type
		if t == "" {
			t = "file"
		}
		sources = append(sources, logreader.SourceConfig{
			Path: s.Path,
			Tags: s.Tags,
			Type: t,
		})
	}
	return sources
}

func collectIPAddresses() []string {
	// real IP collection is done in inventory via net.Interfaces()
	hostname, _ := os.Hostname()
	_ = hostname
	return nil
}

func net_interfaces() ([]string, error) {
	return nil, nil
}

func detectOS() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "linux"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return "linux"
}

// detectOSID reads ID= from /etc/os-release for platform rule matching.
func detectOSID() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "linux"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ID=") {
			return strings.ToLower(strings.Trim(strings.TrimPrefix(line, "ID="), `"`))
		}
	}
	return "linux"
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
