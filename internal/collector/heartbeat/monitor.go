// Package heartbeat watches for agents that've gone quiet and fires offline alerts.
package heartbeat

import (
	"context"
	"log/slog"
	"time"

	"github.com/VRCDN/guiltyspark/internal/collector/alerts"
	"github.com/VRCDN/guiltyspark/internal/collector/storage"
	"github.com/VRCDN/guiltyspark/internal/common/models"
)

// Monitor ticks through all registered agents and marks anyone who hasn't checked in recently as offline.
type Monitor struct {
	store         storage.Storage
	alertManager  *alerts.Manager
	timeout       time.Duration
	checkInterval time.Duration
	logger        *slog.Logger
}

// New creates a heartbeat Monitor.
func New(store storage.Storage, alertMgr *alerts.Manager, timeout, checkInterval time.Duration, logger *slog.Logger) *Monitor {
	if timeout == 0 {
		timeout = 90 * time.Second
	}
	if checkInterval == 0 {
		checkInterval = 30 * time.Second
	}
	return &Monitor{
		store:         store,
		alertManager:  alertMgr,
		timeout:       timeout,
		checkInterval: checkInterval,
		logger:        logger,
	}
}

// Run starts the check loop. Blocks until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	m.logger.Info("heartbeat monitor started",
		"timeout", m.timeout,
		"check_interval", m.checkInterval,
	)
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("heartbeat monitor stopped")
			return
		case <-ticker.C:
			m.check(ctx)
		}
	}
}

// check scans all agents and fires offline alerts for anyone who's gone quiet.
func (m *Monitor) check(ctx context.Context) {
	agents, err := m.store.ListAgents(ctx)
	if err != nil {
		m.logger.Error("heartbeat monitor: list agents", "error", err)
		return
	}

	deadline := time.Now().Add(-m.timeout)
	for _, agent := range agents {
		wasOnline := agent.Status == models.AgentStatusOnline || agent.Status == models.AgentStatusUnknown
		isOnline := agent.LastSeen.After(deadline)

		switch {
		case !isOnline && wasOnline:
			// went offline
			m.logger.Warn("agent went offline",
				"agent_id", agent.ID,
				"hostname", agent.Hostname,
				"last_seen", agent.LastSeen,
			)
			if err := m.store.UpdateAgentLastSeen(ctx, agent.ID, agent.LastSeen, models.AgentStatusOffline); err != nil {
				m.logger.Error("update agent offline status", "error", err)
			}
			agent.Status = models.AgentStatusOffline
			if _, err := m.alertManager.CreateAgentOffline(ctx, agent); err != nil {
				m.logger.Error("create agent offline alert", "error", err)
			}

		case isOnline && agent.Status == models.AgentStatusOffline:
			// came back — this is mostly handled in the API handler, but we log it here too
			m.logger.Info("agent back online (detected by monitor)",
				"agent_id", agent.ID,
				"hostname", agent.Hostname,
			)
		}
	}
}

// RecordHeartbeat is called by the API handler on every heartbeat. Updates last_seen
// and handles the offline → online transition.
func (m *Monitor) RecordHeartbeat(ctx context.Context, agentID string) error {
	agent, err := m.store.GetAgent(ctx, agentID)
	if err != nil || agent == nil {
		return err
	}

	wasOffline := agent.Status == models.AgentStatusOffline
	if err := m.store.UpdateAgentLastSeen(ctx, agentID, time.Now().UTC(), models.AgentStatusOnline); err != nil {
		return err
	}

	if wasOffline {
		m.logger.Info("agent came back online", "agent_id", agentID, "hostname", agent.Hostname)
		agent.Status = models.AgentStatusOnline
		if _, err := m.alertManager.CreateAgentOnline(ctx, agent); err != nil {
			m.logger.Error("create agent online alert", "error", err)
		}
	}
	return nil
}
