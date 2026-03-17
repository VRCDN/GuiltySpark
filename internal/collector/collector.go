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
		Path string `yaml:"path"`
	} `yaml:"database"`

	Auth struct {
		AdminAPIKey string `yaml:"admin_api_key"`
	} `yaml:"auth"`

	Heartbeat struct {
		Timeout       Duration `yaml:"timeout"`
		CheckInterval Duration `yaml:"check_interval"`
	} `yaml:"heartbeat"`

	Alerts struct {
		DedupWindow   Duration `yaml:"dedup_window"`
		Notifications struct {
			Webhook struct {
				Enabled bool   `yaml:"enabled"`
				URL     string `yaml:"url"`
				Secret  string `yaml:"secret"`
			} `yaml:"webhook"`
			Email struct {
				Enabled  bool     `yaml:"enabled"`
				SMTPHost string   `yaml:"smtp_host"`
				SMTPPort int      `yaml:"smtp_port"`
				From     string   `yaml:"from"`
				To       []string `yaml:"to"`
				Username string   `yaml:"username"`
				Password string   `yaml:"password"`
			} `yaml:"email"`
			Slack struct {
				Enabled    bool   `yaml:"enabled"`
				WebhookURL string `yaml:"webhook_url"`
			} `yaml:"slack"`
		} `yaml:"notifications"`
	} `yaml:"alerts"`

	Region    string `yaml:"region"`
	LogLevel  string `yaml:"log_level"`
	LogFormat string `yaml:"log_format"`

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
	cfg.Server.Port = 8443
	cfg.Database.Path = "/var/lib/guiltyspark/collector.db"
	cfg.Heartbeat.Timeout.Duration = 90 * time.Second
	cfg.Heartbeat.CheckInterval.Duration = 30 * time.Second
	cfg.Alerts.DedupWindow.Duration = 5 * time.Minute
	cfg.LogLevel = "info"
	cfg.LogFormat = "json"
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
	notifCfg := alerts.NotificationConfig{
		Webhook: alerts.WebhookConfig{
			Enabled: cfg.Alerts.Notifications.Webhook.Enabled,
			URL:     cfg.Alerts.Notifications.Webhook.URL,
			Secret:  cfg.Alerts.Notifications.Webhook.Secret,
		},
		Email: alerts.EmailConfig{
			Enabled:  cfg.Alerts.Notifications.Email.Enabled,
			SMTPHost: cfg.Alerts.Notifications.Email.SMTPHost,
			SMTPPort: cfg.Alerts.Notifications.Email.SMTPPort,
			From:     cfg.Alerts.Notifications.Email.From,
			To:       cfg.Alerts.Notifications.Email.To,
			Username: cfg.Alerts.Notifications.Email.Username,
			Password: cfg.Alerts.Notifications.Email.Password,
		},
		Slack: alerts.SlackConfig{
			Enabled:    cfg.Alerts.Notifications.Slack.Enabled,
			WebhookURL: cfg.Alerts.Notifications.Slack.WebhookURL,
		},
	}

	alertsMgr := alerts.New(store, notifCfg, cfg.Alerts.DedupWindow.Duration, logger)
	rulesMgr := rules.New(store)
	hbMon := heartbeat.New(store, alertsMgr, cfg.Heartbeat.Timeout.Duration, cfg.Heartbeat.CheckInterval.Duration, logger)
	invStore := inventory.New(store)

	apiCfg := api.Config{
		Host:        cfg.Server.Host,
		Port:        cfg.Server.Port,
		TLSEnabled:  cfg.Server.TLS.Enabled,
		TLSCertFile: cfg.Server.TLS.CertFile,
		TLSKeyFile:  cfg.Server.TLS.KeyFile,
		AdminAPIKey: cfg.Auth.AdminAPIKey,
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

// Run starts the heartbeat monitor and the HTTP server. Blocks until shutdown.
func (c *Collector) Run(ctx context.Context) error {
	go c.hbMon.Run(ctx)

	if err := c.api.Start(ctx); err != nil {
		return fmt.Errorf("api server: %w", err)
	}
	return nil
}

// Close shuts down the database connection.
func (c *Collector) Close() error {
	return c.store.Close()
}
