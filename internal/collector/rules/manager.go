// Package rules handles rule CRUD and version tracking.
package rules

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/VRCDN/guiltyspark/internal/collector/storage"
	"github.com/VRCDN/guiltyspark/internal/common/models"
	"github.com/google/uuid"
)

// Manager is a thin wrapper around the storage layer that adds validation and version tracking.
type Manager struct {
	store storage.Storage
}

// New creates a rule Manager.
func New(store storage.Storage) *Manager {
	return &Manager{store: store}
}

// CreateRule validates the rule (name, pattern) and saves it. Defaults to enabled if not specified.
func (m *Manager) CreateRule(ctx context.Context, req *models.Rule) (*models.Rule, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("rule name is required")
	}
	if req.Pattern == "" {
		return nil, fmt.Errorf("rule pattern is required")
	}
	if _, err := regexp.Compile(req.Pattern); err != nil {
		return nil, fmt.Errorf("invalid pattern: %w", err)
	}
	if req.Severity == "" {
		req.Severity = models.SeverityInfo
	}

	now := time.Now().UTC()
	rule := &models.Rule{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Description: req.Description,
		Pattern:     req.Pattern,
		Tags:        req.Tags,
		Severity:    req.Severity,
		Enabled:     req.Enabled,
		CreatedAt:   now,
		UpdatedAt:   now,
		Version:     1,
	}
	if !rule.Enabled && req.Enabled {
		rule.Enabled = true
	}
	// default to enabled — if you created a rule you probably want it on
	if !req.Enabled && req.Name != "" {
		rule.Enabled = true
	}

	if err := m.store.CreateRule(ctx, rule); err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}
	return rule, nil
}

// GetRule retrieves a rule by ID.
func (m *Manager) GetRule(ctx context.Context, id string) (*models.Rule, error) {
	r, err := m.store.GetRule(ctx, id)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("rule not found: %s", id)
	}
	return r, nil
}

// ListRules returns all rules.
func (m *Manager) ListRules(ctx context.Context) ([]*models.Rule, error) {
	return m.store.ListRules(ctx)
}

// UpdateRule applies partial updates to an existing rule. Only non-zero fields are changed.
func (m *Manager) UpdateRule(ctx context.Context, id string, req *models.Rule) (*models.Rule, error) {
	existing, err := m.store.GetRule(ctx, id)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("rule not found: %s", id)
	}

	if req.Pattern != "" && req.Pattern != existing.Pattern {
		if _, err := regexp.Compile(req.Pattern); err != nil {
			return nil, fmt.Errorf("invalid pattern: %w", err)
		}
		existing.Pattern = req.Pattern
	}
	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Description != "" {
		existing.Description = req.Description
	}
	if len(req.Tags) > 0 {
		existing.Tags = req.Tags
	}
	if req.Severity != "" {
		existing.Severity = req.Severity
	}
	existing.Enabled = req.Enabled
	existing.UpdatedAt = time.Now().UTC()

	if err := m.store.UpdateRule(ctx, existing); err != nil {
		return nil, err
	}
	return existing, nil
}

// DeleteRule removes a rule by ID.
func (m *Manager) DeleteRule(ctx context.Context, id string) error {
	existing, err := m.store.GetRule(ctx, id)
	if err != nil {
		return err
	}
	if existing == nil {
		return fmt.Errorf("rule not found: %s", id)
	}
	return m.store.DeleteRule(ctx, id)
}

// GetRulesVersion returns a short hash of the active rule set for agents to compare against.
func (m *Manager) GetRulesVersion(ctx context.Context) (string, error) {
	return m.store.GetRulesVersion(ctx)
}

// GetRulesResponse returns the enabled rules and the current version hash for agent sync.
func (m *Manager) GetRulesResponse(ctx context.Context) (*models.RulesResponse, error) {
	rules, err := m.store.ListRules(ctx)
	if err != nil {
		return nil, err
	}
	version, err := m.store.GetRulesVersion(ctx)
	if err != nil {
		return nil, err
	}

	var enabled []models.Rule
	for _, r := range rules {
		if r.Enabled {
			enabled = append(enabled, *r)
		}
	}
	return &models.RulesResponse{
		Rules:   enabled,
		Version: version,
	}, nil
}

// SeedDefaultRules adds default rules on first start. Does nothing if any rules already exist.
func (m *Manager) SeedDefaultRules(ctx context.Context, rules []models.Rule) error {
	existing, err := m.store.ListRules(ctx)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return nil // already seeded
	}
	for i := range rules {
		if _, err := m.CreateRule(ctx, &rules[i]); err != nil {
			return fmt.Errorf("seed rule %q: %w", rules[i].Name, err)
		}
	}
	return nil
}
