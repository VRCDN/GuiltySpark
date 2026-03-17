// Package storage defines the persistence interface all collector services use.
package storage

import (
	"context"
	"time"

	"github.com/VRCDN/guiltyspark/internal/common/models"
)

// Storage is the persistence interface. All implementations must be goroutine-safe.
type Storage interface {
	// agents

	CreateAgent(ctx context.Context, agent *models.Agent) error
	GetAgent(ctx context.Context, id string) (*models.Agent, error)
	GetAgentByAPIKey(ctx context.Context, apiKey string) (*models.Agent, error)
	ListAgents(ctx context.Context) ([]*models.Agent, error)
	UpdateAgent(ctx context.Context, agent *models.Agent) error
	DeleteAgent(ctx context.Context, id string) error
	UpdateAgentLastSeen(ctx context.Context, id string, t time.Time, status models.AgentStatus) error

	// rules

	CreateRule(ctx context.Context, rule *models.Rule) error
	GetRule(ctx context.Context, id string) (*models.Rule, error)
	ListRules(ctx context.Context) ([]*models.Rule, error)
	UpdateRule(ctx context.Context, rule *models.Rule) error
	DeleteRule(ctx context.Context, id string) error
	// GetRulesVersion returns a short hash of the active rule set. Agents use it to detect changes without fetching the full list.
	GetRulesVersion(ctx context.Context) (string, error)

	// alerts

	CreateAlert(ctx context.Context, alert *models.Alert) error
	GetAlert(ctx context.Context, id string) (*models.Alert, error)
	ListAlerts(ctx context.Context, filter models.AlertFilter) ([]*models.Alert, error)
	AcknowledgeAlert(ctx context.Context, id, by string) error

	// inventory

	SaveInventory(ctx context.Context, inv *models.SystemInventory) error
	GetInventory(ctx context.Context, agentID string) (*models.SystemInventory, error)
	ListInventory(ctx context.Context) ([]*models.SystemInventory, error)

	// log events

	SaveLogEvent(ctx context.Context, event *models.LogEvent) error
	ListLogEvents(ctx context.Context, filter models.AlertFilter) ([]*models.LogEvent, error)

	// audit events

	SaveAuditEvent(ctx context.Context, event *models.AuditEvent) error
	ListAuditEvents(ctx context.Context, filter models.AuditEventFilter) ([]*models.AuditEvent, error)

	// Close releases storage resources.
	Close() error
}
