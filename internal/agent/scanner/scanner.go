// Package scanner matches log lines against rules. A rule only runs on sources that share at least one tag with it.
package scanner

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/VRCDN/guiltyspark/internal/agent/logreader"
	"github.com/VRCDN/guiltyspark/internal/common/models"
	"github.com/google/uuid"
)

// compiledRule is a rule with its regex already compiled.
type compiledRule struct {
	models.Rule
	re *regexp.Regexp
}

// Scanner holds the active rule set and matches incoming log lines against it.
type Scanner struct {
	mu      sync.RWMutex
	rules   []compiledRule
	version string
	osID    string // lowercase /etc/os-release ID, e.g. "alpine", "debian"

	events chan models.LogEvent
	logger *slog.Logger
}

func New(logger *slog.Logger) *Scanner {
	return &Scanner{
		events: make(chan models.LogEvent, 4096),
		logger: logger,
	}
}

// Events returns the output channel. Drain it or matched events get dropped.
func (s *Scanner) Events() <-chan models.LogEvent {
	return s.events
}

// SetOS sets the OS ID used to match against platform-scoped rules. Call before UpdateRules.
func (s *Scanner) SetOS(osID string) {
	s.mu.Lock()
	s.osID = strings.ToLower(osID)
	s.mu.Unlock()
}

// UpdateRules swaps in a new rule set. Safe to call from any goroutine.
func (s *Scanner) UpdateRules(rules []models.Rule, version string) {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			s.logger.Warn("compile rule pattern", "rule_id", r.ID, "pattern", r.Pattern, "error", err)
			continue
		}
		compiled = append(compiled, compiledRule{Rule: r, re: re})
	}

	s.mu.Lock()
	s.rules = compiled
	s.version = version
	s.mu.Unlock()

	s.logger.Info("rules updated", "count", len(compiled), "version", version)
}

func (s *Scanner) Version() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

// Run reads log lines and scans them until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context, lines <-chan logreader.LogLine) {
	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-lines:
			if !ok {
				return
			}
			s.scan(line)
		}
	}
}

// scan runs one log line through all active rules.
func (s *Scanner) scan(line logreader.LogLine) {
	s.mu.RLock()
	rules := s.rules
	osID := s.osID
	s.mu.RUnlock()

	for _, r := range rules {
		if !tagsOverlap(r.Tags, line.Tags) {
			continue
		}
		if !platformMatches(r.Platforms, osID) {
			continue
		}
		match := r.re.FindStringSubmatch(line.Line)
		if match == nil {
			continue
		}
		captures := extractCaptures(r.re, match)
		event := models.LogEvent{
			ID:        uuid.New().String(),
			RuleID:    r.ID,
			RuleName:  r.Name,
			Severity:  r.Severity,
			LogSource: line.Source,
			LogLine:   truncate(line.Line, 4096),
			Captures:  captures,
			MatchedAt: time.Now().UTC(),
		}

		select {
		case s.events <- event:
		default:
			// buffer full — drop rather than stall the log reader
			s.logger.Warn("event queue full, dropping match",
				"rule_id", r.ID,
				"source", line.Source,
			)
		}
	}
}

// tagsOverlap returns true if the rule and source share at least one tag.
func tagsOverlap(ruleTags, sourceTags []string) bool {
	if len(ruleTags) == 0 {
		return true // a rule with no tags applies to everything
	}
	for _, rt := range ruleTags {
		for _, st := range sourceTags {
			if strings.EqualFold(rt, st) {
				return true
			}
		}
	}
	return false
}

// platformMatches returns true if the rule is global (empty Platforms) or the OS matches.
func platformMatches(platforms []string, osID string) bool {
	if len(platforms) == 0 {
		return true
	}
	for _, p := range platforms {
		if strings.EqualFold(p, osID) {
			return true
		}
	}
	return false
}

// extractCaptures pulls named groups out of a regex match.
func extractCaptures(re *regexp.Regexp, match []string) map[string]string {
	names := re.SubexpNames()
	captures := make(map[string]string)
	for i, name := range names {
		if i == 0 || name == "" || i >= len(match) {
			continue
		}
		captures[name] = match[i]
	}
	return captures
}

// truncate caps a string at maxLen bytes.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
