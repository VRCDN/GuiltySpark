// Package collector wires the collector's sub-systems together.
package collector

import (
	"context"
	"fmt"
	"log/slog"

	"os"
	"time"

	"github.com/VRCDN/guiltyspark/internal/collector/alerts"
	"github.com/VRCDN/guiltyspark/internal/collector/api"
	"github.com/VRCDN/guiltyspark/internal/collector/heartbeat"
	"github.com/VRCDN/guiltyspark/internal/collector/inventory"
	"github.com/VRCDN/guiltyspark/internal/collector/rules"
	"github.com/VRCDN/guiltyspark/internal/collector/storage"
	"github.com/VRCDN/guiltyspark/internal/common/models"
	"gopkg.in/yaml.v3"
)

// Config is everything we read from the collector's YAML file.
type Config struct {
	Server struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
		TLS  struct {
			Enabled  bool   `yaml:"enabled"`
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
		} `yaml:"tls"`
	} `yaml:"server"`

	Database struct {
		Path      string `yaml:"path"`
		Retention struct {
			Enabled bool     `yaml:"enabled"`
			MaxAge  Duration `yaml:"max_age"`
		} `yaml:"retention"`
	} `yaml:"database"`

	Auth struct {
		AdminAPIKey     string `yaml:"admin_api_key"`
		RegistrationKey string `yaml:"registration_key"`
	} `yaml:"auth"`

	Heartbeat struct {
		Timeout       Duration `yaml:"timeout"`
		CheckInterval Duration `yaml:"check_interval"`
	} `yaml:"heartbeat"`

	Alerts struct {
		DedupWindow   Duration `yaml:"dedup_window"`
		Notifications struct {
			Webhook struct {
				Enabled  bool            `yaml:"enabled"`
				URL      string          `yaml:"url"`
				Secret   string          `yaml:"secret"`
				MinLevel models.Severity `yaml:"min_level"`
			} `yaml:"webhook"`
			Email struct {
				Enabled  bool            `yaml:"enabled"`
				SMTPHost string          `yaml:"smtp_host"`
				SMTPPort int             `yaml:"smtp_port"`
				From     string          `yaml:"from"`
				To       []string        `yaml:"to"`
				Username string          `yaml:"username"`
				Password string          `yaml:"password"`
				MinLevel models.Severity `yaml:"min_level"`
			} `yaml:"email"`
			Slack struct {
				Enabled    bool            `yaml:"enabled"`
				WebhookURL string          `yaml:"webhook_url"`
				MinLevel   models.Severity `yaml:"min_level"`
			} `yaml:"slack"`
			Discord struct {
				Enabled    bool            `yaml:"enabled"`
				WebhookURL string          `yaml:"webhook_url"`
				Username   string          `yaml:"username"`
				MinLevel   models.Severity `yaml:"min_level"`
			} `yaml:"discord"`
			CustomWebhooks []struct {
				Name         string            `yaml:"name"`
				Enabled      bool              `yaml:"enabled"`
				URL          string            `yaml:"url"`
				Method       string            `yaml:"method"`
				ContentType  string            `yaml:"content_type"`
				Secret       string            `yaml:"secret"`
				Headers      map[string]string `yaml:"headers"`
				BodyTemplate string            `yaml:"body_template"`
				MinLevel     models.Severity   `yaml:"min_level"`
			} `yaml:"custom_webhooks"`
		} `yaml:"notifications"`
	} `yaml:"alerts"`

	Region    string `yaml:"region"`
	LogLevel  string `yaml:"log_level"`
	LogFormat string `yaml:"log_format"`
	LogFile   string `yaml:"log_file"`

	DefaultRulesFile string `yaml:"default_rules_file"`
}

// Duration wraps time.Duration so yaml.v3 can unmarshal it. The stdlib doesn't handle duration strings natively, so here we are.
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	dur, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

// DefaultConfig returns reasonable defaults. The config file overrides these.
func DefaultConfig() Config {
	var cfg Config
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.Port = 9900
	cfg.Database.Path = "/var/lib/guiltyspark/collector.db"
	cfg.Database.Retention.Enabled = true
	cfg.Database.Retention.MaxAge.Duration = 365 * 24 * time.Hour
	cfg.Heartbeat.Timeout.Duration = 90 * time.Second
	cfg.Heartbeat.CheckInterval.Duration = 30 * time.Second
	cfg.Alerts.DedupWindow.Duration = 5 * time.Minute
	cfg.LogLevel = "info"
	cfg.LogFormat = "json"
	cfg.LogFile = "/var/log/guiltyspark/collector.log"
	return cfg
}

// LoadConfig reads the YAML config and merges it on top of defaults.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// Collector is the root service — owns storage, the HTTP server, and the heartbeat monitor.
type Collector struct {
	cfg    Config
	logger *slog.Logger
	store  storage.Storage
	api    *api.Server
	hbMon  *heartbeat.Monitor
}

// New builds and wires up all the collector's components. Returns an error if storage won't open.
func New(cfg Config, logger *slog.Logger) (*Collector, error) {
	store, err := storage.NewSQLite(cfg.Database.Path)
	if err != nil {
		return nil, fmt.Errorf("open storage: %w", err)
	}

	// assemble the notification config from the flat YAML structure
	customWebhooks := make([]alerts.CustomWebhookConfig, 0, len(cfg.Alerts.Notifications.CustomWebhooks))
	for _, cw := range cfg.Alerts.Notifications.CustomWebhooks {
		customWebhooks = append(customWebhooks, alerts.CustomWebhookConfig{
			Name:         cw.Name,
			Enabled:      cw.Enabled,
			URL:          cw.URL,
			Method:       cw.Method,
			ContentType:  cw.ContentType,
			Secret:       cw.Secret,
			Headers:      cw.Headers,
			BodyTemplate: cw.BodyTemplate,
			MinLevel:     cw.MinLevel,
		})
	}

	notifCfg := alerts.NotificationConfig{
		Webhook: alerts.WebhookConfig{
			Enabled:  cfg.Alerts.Notifications.Webhook.Enabled,
			URL:      cfg.Alerts.Notifications.Webhook.URL,
			Secret:   cfg.Alerts.Notifications.Webhook.Secret,
			MinLevel: cfg.Alerts.Notifications.Webhook.MinLevel,
		},
		Email: alerts.EmailConfig{
			Enabled:  cfg.Alerts.Notifications.Email.Enabled,
			SMTPHost: cfg.Alerts.Notifications.Email.SMTPHost,
			SMTPPort: cfg.Alerts.Notifications.Email.SMTPPort,
			From:     cfg.Alerts.Notifications.Email.From,
			To:       cfg.Alerts.Notifications.Email.To,
			Username: cfg.Alerts.Notifications.Email.Username,
			Password: cfg.Alerts.Notifications.Email.Password,
			MinLevel: cfg.Alerts.Notifications.Email.MinLevel,
		},
		Slack: alerts.SlackConfig{
			Enabled:    cfg.Alerts.Notifications.Slack.Enabled,
			WebhookURL: cfg.Alerts.Notifications.Slack.WebhookURL,
			MinLevel:   cfg.Alerts.Notifications.Slack.MinLevel,
		},
		Discord: alerts.DiscordConfig{
			Enabled:    cfg.Alerts.Notifications.Discord.Enabled,
			WebhookURL: cfg.Alerts.Notifications.Discord.WebhookURL,
			Username:   cfg.Alerts.Notifications.Discord.Username,
			MinLevel:   cfg.Alerts.Notifications.Discord.MinLevel,
		},
		CustomWebhooks: customWebhooks,
	}

	alertsMgr := alerts.New(store, notifCfg, cfg.Alerts.DedupWindow.Duration, logger)
	rulesMgr := rules.New(store)
	hbMon := heartbeat.New(store, alertsMgr, cfg.Heartbeat.Timeout.Duration, cfg.Heartbeat.CheckInterval.Duration, logger)
	invStore := inventory.New(store)

	apiCfg := api.Config{
		Host:            cfg.Server.Host,
		Port:            cfg.Server.Port,
		TLSEnabled:      cfg.Server.TLS.Enabled,
		TLSCertFile:     cfg.Server.TLS.CertFile,
		TLSKeyFile:      cfg.Server.TLS.KeyFile,
		AdminAPIKey:     cfg.Auth.AdminAPIKey,
		RegistrationKey: cfg.Auth.RegistrationKey,
	}
	apiServer := api.New(apiCfg, store, rulesMgr, alertsMgr, hbMon, invStore, logger)

	return &Collector{
		cfg:    cfg,
		logger: logger,
		store:  store,
		api:    apiServer,
		hbMon:  hbMon,
	}, nil
}

// SeedRules loads the default rules on first start. Skips silently if the file doesn't exist or rules already exist.
func (c *Collector) SeedRules(ctx context.Context, path string) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read rules file: %w", err)
	}

	var file struct {
		Rules []models.Rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse rules file: %w", err)
	}

	rulesMgr := rules.New(c.store)
	if err := rulesMgr.SeedDefaultRules(ctx, file.Rules); err != nil {
		return fmt.Errorf("seed rules: %w", err)
	}
	c.logger.Info("default rules seeded", "count", len(file.Rules))
	return nil
}

// Run starts the heartbeat monitor, the data-retention pruner, and the HTTP server. Blocks until shutdown.
func (c *Collector) Run(ctx context.Context) error {
	go c.hbMon.Run(ctx)

	if c.cfg.Database.Retention.Enabled {
		go c.runPruner(ctx)
	}

	if err := c.api.Start(ctx); err != nil {
		return fmt.Errorf("api server: %w", err)
	}
	return nil
}

// runPruner runs the data-retention pruner on a 1-hour tick for the lifetime of ctx.
func (c *Collector) runPruner(ctx context.Context) {
	maxAge := c.cfg.Database.Retention.MaxAge.Duration
	// Run once at startup so an overdue purge isn't delayed by the first tick.
	c.pruneOnce(ctx, maxAge)

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.pruneOnce(ctx, maxAge)
		}
	}
}

func (c *Collector) pruneOnce(ctx context.Context, maxAge time.Duration) {
	stats, err := c.store.PruneOldData(ctx, maxAge)
	if err != nil {
		c.logger.Error("data retention pruning failed", "error", err)
		return
	}
	total := stats.Alerts + stats.LogEvents + stats.AuditEvents
	if total > 0 {
		c.logger.Info("data retention pruning completed",
			"alerts_deleted", stats.Alerts,
			"log_events_deleted", stats.LogEvents,
			"audit_events_deleted", stats.AuditEvents,
			"max_age", maxAge.String(),
		)
	}
}

// Close shuts down the database connection.
func (c *Collector) Close() error {
	return c.store.Close()
}
