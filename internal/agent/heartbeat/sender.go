// Package heartbeat handles the agent's periodic check-in with the collector.
package heartbeat

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/VRCDN/guiltyspark/internal/agent/client"
	"github.com/VRCDN/guiltyspark/internal/common/models"
)

// Sender pings the collector on a timer and signals when the collector says our rules are out of date.
type Sender struct {
	client       *client.Client
	agentID      string
	interval     time.Duration
	rulesVersion string
	logger       *slog.Logger
	rulesUpdated chan struct{}
}

// New creates a heartbeat Sender.
func New(c *client.Client, agentID string, interval time.Duration, logger *slog.Logger) *Sender {
	if interval == 0 {
		interval = 30 * time.Second
	}
	return &Sender{
		client:       c,
		agentID:      agentID,
		interval:     interval,
		logger:       logger,
		rulesUpdated: make(chan struct{}, 1),
	}
}

// RulesUpdated returns a channel that fires when the collector says the rules changed.
func (s *Sender) RulesUpdated() <-chan struct{} {
	return s.rulesUpdated
}

// SetRulesVersion updates what we tell the collector our current rule version is.
func (s *Sender) SetRulesVersion(v string) {
	s.rulesVersion = v
}

// Run starts ticking and blocks until ctx is cancelled.
func (s *Sender) Run(ctx context.Context) {
	s.logger.Info("heartbeat sender started", "interval", s.interval)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// don't wait for the first tick
	s.send(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.send(ctx)
		}
	}
}

func (s *Sender) send(ctx context.Context) {
	uptime := int64(0)
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		var secs float64
		_, _ = fmt.Sscanf(string(data), "%f", &secs)
		uptime = int64(secs)
	}

	req := models.HeartbeatRequest{
		AgentID:      s.agentID,
		Timestamp:    time.Now().UTC(),
		RulesVersion: s.rulesVersion,
		Uptime:       uptime,
	}

	resp, err := s.client.Heartbeat(ctx, req)
	if err != nil {
		s.logger.Warn("heartbeat failed", "error", err)
		return
	}

	s.logger.Debug("heartbeat ok", "rules_updated", resp.RulesUpdated, "rules_version", resp.RulesVersion)

	if resp.RulesUpdated {
		select {
		case s.rulesUpdated <- struct{}{}:
		default: // already pending
		}
	}
}
