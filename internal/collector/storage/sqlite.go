package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/VRCDN/guiltyspark/internal/common/models"
	_ "modernc.org/sqlite" // register sqlite3 driver
)

// SQLiteStorage implements the Storage interface using SQLite via the modernc driver (no CGO required).
type SQLiteStorage struct {
	db *sql.DB
}

// NewSQLite opens the database file (creating it if needed), enables WAL mode and foreign keys,
// then runs any pending schema migrations.
func NewSQLite(path string) (*SQLiteStorage, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// WAL mode lets reads proceed while a write is in progress — matters a lot with many concurrent agents
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return nil, fmt.Errorf("enable WAL: %w", err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		return nil, fmt.Errorf("enable FK: %w", err)
	}

	s := &SQLiteStorage{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// migrate applies each schema statement exactly once, tracked by index in the schema_version table.
// It's not a real migration framework, but it doesn't need to be.
func (s *SQLiteStorage) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY,
			applied_at DATETIME NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS agents (
			id           TEXT PRIMARY KEY,
			hostname     TEXT NOT NULL,
			ip_addresses TEXT NOT NULL DEFAULT '[]',
			region       TEXT NOT NULL DEFAULT '',
			tags         TEXT NOT NULL DEFAULT '[]',
			version      TEXT NOT NULL DEFAULT '',
			os           TEXT NOT NULL DEFAULT '',
			api_key      TEXT NOT NULL UNIQUE,
			last_seen    DATETIME NOT NULL,
			status       TEXT NOT NULL DEFAULT 'unknown',
			registered_at DATETIME NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS rules (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			pattern     TEXT NOT NULL,
			tags        TEXT NOT NULL DEFAULT '[]',
			severity    TEXT NOT NULL DEFAULT 'info',
			enabled     INTEGER NOT NULL DEFAULT 1,
			created_at  DATETIME NOT NULL,
			updated_at  DATETIME NOT NULL,
			version     INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS alerts (
			id               TEXT PRIMARY KEY,
			agent_id         TEXT NOT NULL,
			rule_id          TEXT NOT NULL DEFAULT '',
			rule_name        TEXT NOT NULL DEFAULT '',
			severity         TEXT NOT NULL,
			alert_type       TEXT NOT NULL DEFAULT 'log_match',
			message          TEXT NOT NULL,
			log_line         TEXT NOT NULL DEFAULT '',
			log_source       TEXT NOT NULL DEFAULT '',
			matched_at       DATETIME NOT NULL,
			received_at      DATETIME NOT NULL,
			acknowledged     INTEGER NOT NULL DEFAULT 0,
			acknowledged_by  TEXT NOT NULL DEFAULT '',
			acknowledged_at  DATETIME
		)`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_agent_id ON alerts(agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_received_at ON alerts(received_at)`,
		`CREATE TABLE IF NOT EXISTS inventory (
			agent_id     TEXT PRIMARY KEY,
			data         TEXT NOT NULL,
			collected_at DATETIME NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS log_events (
			id          TEXT PRIMARY KEY,
			agent_id    TEXT NOT NULL,
			rule_id     TEXT NOT NULL DEFAULT '',
			rule_name   TEXT NOT NULL DEFAULT '',
			severity    TEXT NOT NULL DEFAULT 'info',
			log_source  TEXT NOT NULL DEFAULT '',
			log_line    TEXT NOT NULL DEFAULT '',
			captures    TEXT NOT NULL DEFAULT '{}',
			matched_at  DATETIME NOT NULL,
			received_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_log_events_agent_id ON log_events(agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_log_events_received_at ON log_events(received_at)`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id           TEXT PRIMARY KEY,
			agent_id     TEXT NOT NULL,
			type         TEXT NOT NULL,
			timestamp    DATETIME NOT NULL,
			pid          INTEGER NOT NULL DEFAULT 0,
			uid          INTEGER NOT NULL DEFAULT 0,
			username     TEXT NOT NULL DEFAULT '',
			path         TEXT NOT NULL DEFAULT '',
			old_path     TEXT NOT NULL DEFAULT '',
			mode         TEXT NOT NULL DEFAULT '',
			command      TEXT NOT NULL DEFAULT '',
			args         TEXT NOT NULL DEFAULT '[]',
			work_dir     TEXT NOT NULL DEFAULT '',
			return_code  INTEGER NOT NULL DEFAULT 0,
			process_name TEXT NOT NULL DEFAULT '',
			parent_pid   INTEGER NOT NULL DEFAULT 0,
			received_at  DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_events_agent_id ON audit_events(agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp)`,
		// Migration 17: add platforms column to rules table for OS-specific rules.
		`ALTER TABLE rules ADD COLUMN platforms TEXT NOT NULL DEFAULT '[]'`,
	}

	for i, stmt := range migrations {
		// check if this migration has already run
		var count int
		if err := s.db.QueryRow(
			`SELECT COUNT(*) FROM schema_version WHERE version=?`, i,
		).Scan(&count); err != nil && err != sql.ErrNoRows {
			// expected to fail on migration 0 \u2014 schema_version doesn't exist yet
		}
		if count > 0 {
			continue
		}
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migration %d: %w", i, err)
		}
		// mark this migration as done (skip 0 since that's the table we're inserting into)
		if i > 0 {
			if _, err := s.db.Exec(
				`INSERT OR IGNORE INTO schema_version(version, applied_at) VALUES(?,?)`,
				i, time.Now().UTC(),
			); err != nil {
				return fmt.Errorf("record migration %d: %w", i, err)
			}
		}
	}
	return nil
}

// Close closes the database connection.
func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

// Helpers

func toJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func fromJSONStrings(raw string) []string {
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func fromJSONMap(raw string) map[string]string {
	out := make(map[string]string)
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func nullableTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return t.UTC()
}

func scanNullableTime(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05.999999999+00:00",
		"2006-01-02 15:04:05+00:00",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s.String); err == nil {
			return &t
		}
	}
	return nil
}

func parseTime(raw string) time.Time {
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05.999999999+00:00",
		"2006-01-02 15:04:05+00:00",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Agents

func (s *SQLiteStorage) CreateAgent(ctx context.Context, a *models.Agent) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agents(id,hostname,ip_addresses,region,tags,version,os,api_key,last_seen,status,registered_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Hostname, toJSON(a.IPAddresses), a.Region, toJSON(a.Tags),
		a.Version, a.OS, a.APIKey,
		a.LastSeen.UTC(), string(a.Status), a.RegisteredAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("create agent: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) GetAgent(ctx context.Context, id string) (*models.Agent, error) {
	return s.scanAgent(s.db.QueryRowContext(ctx,
		`SELECT id,hostname,ip_addresses,region,tags,version,os,api_key,last_seen,status,registered_at
		 FROM agents WHERE id=?`, id))
}

func (s *SQLiteStorage) GetAgentByAPIKey(ctx context.Context, apiKey string) (*models.Agent, error) {
	return s.scanAgent(s.db.QueryRowContext(ctx,
		`SELECT id,hostname,ip_addresses,region,tags,version,os,api_key,last_seen,status,registered_at
		 FROM agents WHERE api_key=?`, apiKey))
}

func (s *SQLiteStorage) scanAgent(row *sql.Row) (*models.Agent, error) {
	var a models.Agent
	var ipRaw, tagsRaw, lastSeen, registeredAt, status string
	if err := row.Scan(
		&a.ID, &a.Hostname, &ipRaw, &a.Region, &tagsRaw,
		&a.Version, &a.OS, &a.APIKey, &lastSeen, &status, &registeredAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan agent: %w", err)
	}
	a.IPAddresses = fromJSONStrings(ipRaw)
	a.Tags = fromJSONStrings(tagsRaw)
	a.LastSeen = parseTime(lastSeen)
	a.RegisteredAt = parseTime(registeredAt)
	a.Status = models.AgentStatus(status)
	return &a, nil
}

func (s *SQLiteStorage) ListAgents(ctx context.Context) ([]*models.Agent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,hostname,ip_addresses,region,tags,version,os,api_key,last_seen,status,registered_at
		 FROM agents ORDER BY hostname`)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer rows.Close()

	var agents []*models.Agent
	for rows.Next() {
		var a models.Agent
		var ipRaw, tagsRaw, lastSeen, registeredAt, status string
		if err := rows.Scan(
			&a.ID, &a.Hostname, &ipRaw, &a.Region, &tagsRaw,
			&a.Version, &a.OS, &a.APIKey, &lastSeen, &status, &registeredAt,
		); err != nil {
			return nil, fmt.Errorf("scan agent row: %w", err)
		}
		a.IPAddresses = fromJSONStrings(ipRaw)
		a.Tags = fromJSONStrings(tagsRaw)
		a.LastSeen = parseTime(lastSeen)
		a.RegisteredAt = parseTime(registeredAt)
		a.Status = models.AgentStatus(status)
		a.APIKey = "" // don't expose keys in list responses
		agents = append(agents, &a)
	}
	return agents, rows.Err()
}

func (s *SQLiteStorage) UpdateAgent(ctx context.Context, a *models.Agent) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET hostname=?,ip_addresses=?,region=?,tags=?,version=?,os=?,last_seen=?,status=?
		 WHERE id=?`,
		a.Hostname, toJSON(a.IPAddresses), a.Region, toJSON(a.Tags),
		a.Version, a.OS, a.LastSeen.UTC(), string(a.Status), a.ID,
	)
	return err
}

func (s *SQLiteStorage) DeleteAgent(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM agents WHERE id=?`, id)
	return err
}

func (s *SQLiteStorage) UpdateAgentLastSeen(ctx context.Context, id string, t time.Time, status models.AgentStatus) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET last_seen=?,status=? WHERE id=?`,
		t.UTC(), string(status), id,
	)
	return err
}

// Rules

func (s *SQLiteStorage) CreateRule(ctx context.Context, r *models.Rule) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rules(id,name,description,pattern,tags,platforms,severity,enabled,created_at,updated_at,version)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.Name, r.Description, r.Pattern, toJSON(r.Tags), toJSON(r.Platforms),
		string(r.Severity), boolInt(r.Enabled),
		r.CreatedAt.UTC(), r.UpdatedAt.UTC(), r.Version,
	)
	return err
}

func (s *SQLiteStorage) GetRule(ctx context.Context, id string) (*models.Rule, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,name,description,pattern,tags,platforms,severity,enabled,created_at,updated_at,version
		 FROM rules WHERE id=?`, id)
	return s.scanRule(row)
}

func (s *SQLiteStorage) scanRule(row *sql.Row) (*models.Rule, error) {
	var r models.Rule
	var tagsRaw, platformsRaw, createdAt, updatedAt string
	var enabledInt int
	if err := row.Scan(
		&r.ID, &r.Name, &r.Description, &r.Pattern, &tagsRaw, &platformsRaw,
		&r.Severity, &enabledInt, &createdAt, &updatedAt, &r.Version,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan rule: %w", err)
	}
	r.Tags = fromJSONStrings(tagsRaw)
	r.Platforms = fromJSONStrings(platformsRaw)
	r.Enabled = enabledInt != 0
	r.CreatedAt = parseTime(createdAt)
	r.UpdatedAt = parseTime(updatedAt)
	return &r, nil
}

func (s *SQLiteStorage) ListRules(ctx context.Context) ([]*models.Rule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,description,pattern,tags,platforms,severity,enabled,created_at,updated_at,version
		 FROM rules ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*models.Rule
	for rows.Next() {
		var r models.Rule
		var tagsRaw, platformsRaw, createdAt, updatedAt string
		var enabledInt int
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Description, &r.Pattern, &tagsRaw, &platformsRaw,
			&r.Severity, &enabledInt, &createdAt, &updatedAt, &r.Version,
		); err != nil {
			return nil, err
		}
		r.Tags = fromJSONStrings(tagsRaw)
		r.Platforms = fromJSONStrings(platformsRaw)
		r.Enabled = enabledInt != 0
		r.CreatedAt = parseTime(createdAt)
		r.UpdatedAt = parseTime(updatedAt)
		rules = append(rules, &r)
	}
	return rules, rows.Err()
}

func (s *SQLiteStorage) UpdateRule(ctx context.Context, r *models.Rule) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE rules SET name=?,description=?,pattern=?,tags=?,platforms=?,severity=?,enabled=?,updated_at=?,version=version+1
		 WHERE id=?`,
		r.Name, r.Description, r.Pattern, toJSON(r.Tags), toJSON(r.Platforms),
		string(r.Severity), boolInt(r.Enabled), time.Now().UTC(), r.ID,
	)
	return err
}

func (s *SQLiteStorage) DeleteRule(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE id=?`, id)
	return err
}

func (s *SQLiteStorage) GetRulesVersion(ctx context.Context) (string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,pattern FROM rules WHERE enabled=1 ORDER BY id`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	h := sha256.New()
	for rows.Next() {
		var id, pattern string
		if err := rows.Scan(&id, &pattern); err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s:%s\n", id, pattern)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16], nil
}

// Alerts

func (s *SQLiteStorage) CreateAlert(ctx context.Context, a *models.Alert) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO alerts(id,agent_id,rule_id,rule_name,severity,alert_type,message,log_line,log_source,matched_at,received_at,acknowledged,acknowledged_by,acknowledged_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.AgentID, a.RuleID, a.RuleName, string(a.Severity),
		string(a.AlertType), a.Message, a.LogLine, a.LogSource,
		a.MatchedAt.UTC(), a.ReceivedAt.UTC(),
		boolInt(a.Acknowledged), a.AcknowledgedBy, nullableTime(a.AcknowledgedAt),
	)
	return err
}

func (s *SQLiteStorage) GetAlert(ctx context.Context, id string) (*models.Alert, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,agent_id,rule_id,rule_name,severity,alert_type,message,log_line,log_source,
		        matched_at,received_at,acknowledged,acknowledged_by,acknowledged_at
		 FROM alerts WHERE id=?`, id)
	return s.scanAlert(row)
}

func (s *SQLiteStorage) scanAlert(row *sql.Row) (*models.Alert, error) {
	var a models.Alert
	var matchedAt, receivedAt string
	var acknowledgedInt int
	var ackAt sql.NullString
	if err := row.Scan(
		&a.ID, &a.AgentID, &a.RuleID, &a.RuleName, &a.Severity, &a.AlertType,
		&a.Message, &a.LogLine, &a.LogSource,
		&matchedAt, &receivedAt, &acknowledgedInt, &a.AcknowledgedBy, &ackAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	a.MatchedAt = parseTime(matchedAt)
	a.ReceivedAt = parseTime(receivedAt)
	a.Acknowledged = acknowledgedInt != 0
	a.AcknowledgedAt = scanNullableTime(ackAt)
	return &a, nil
}

func (s *SQLiteStorage) ListAlerts(ctx context.Context, filter models.AlertFilter) ([]*models.Alert, error) {
	var conditions []string
	var args []interface{}

	if filter.AgentID != "" {
		conditions = append(conditions, "agent_id=?")
		args = append(args, filter.AgentID)
	}
	if filter.Severity != "" {
		conditions = append(conditions, "severity=?")
		args = append(args, string(filter.Severity))
	}
	if filter.Acknowledged != nil {
		conditions = append(conditions, "acknowledged=?")
		args = append(args, boolInt(*filter.Acknowledged))
	}
	if filter.AlertType != "" {
		conditions = append(conditions, "alert_type=?")
		args = append(args, string(filter.AlertType))
	}
	if !filter.Since.IsZero() {
		conditions = append(conditions, "received_at>=?")
		args = append(args, filter.Since.UTC())
	}

	query := `SELECT id,agent_id,rule_id,rule_name,severity,alert_type,message,log_line,log_source,
	                 matched_at,received_at,acknowledged,acknowledged_by,acknowledged_at
	          FROM alerts`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY received_at DESC"
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
		if filter.Offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", filter.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*models.Alert
	for rows.Next() {
		var a models.Alert
		var matchedAt, receivedAt string
		var acknowledgedInt int
		var ackAt sql.NullString
		if err := rows.Scan(
			&a.ID, &a.AgentID, &a.RuleID, &a.RuleName, &a.Severity, &a.AlertType,
			&a.Message, &a.LogLine, &a.LogSource,
			&matchedAt, &receivedAt, &acknowledgedInt, &a.AcknowledgedBy, &ackAt,
		); err != nil {
			return nil, err
		}
		a.MatchedAt = parseTime(matchedAt)
		a.ReceivedAt = parseTime(receivedAt)
		a.Acknowledged = acknowledgedInt != 0
		a.AcknowledgedAt = scanNullableTime(ackAt)
		alerts = append(alerts, &a)
	}
	return alerts, rows.Err()
}

func (s *SQLiteStorage) AcknowledgeAlert(ctx context.Context, id, by string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE alerts SET acknowledged=1,acknowledged_by=?,acknowledged_at=? WHERE id=?`,
		by, now, id,
	)
	return err
}

// Inventory

func (s *SQLiteStorage) SaveInventory(ctx context.Context, inv *models.SystemInventory) error {
	data, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO inventory(agent_id,data,collected_at) VALUES(?,?,?)
		 ON CONFLICT(agent_id) DO UPDATE SET data=excluded.data,collected_at=excluded.collected_at`,
		inv.AgentID, string(data), inv.CollectedAt.UTC(),
	)
	return err
}

func (s *SQLiteStorage) GetInventory(ctx context.Context, agentID string) (*models.SystemInventory, error) {
	var dataRaw string
	if err := s.db.QueryRowContext(ctx,
		`SELECT data FROM inventory WHERE agent_id=?`, agentID,
	).Scan(&dataRaw); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	var inv models.SystemInventory
	if err := json.Unmarshal([]byte(dataRaw), &inv); err != nil {
		return nil, err
	}
	return &inv, nil
}

func (s *SQLiteStorage) ListInventory(ctx context.Context) ([]*models.SystemInventory, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM inventory ORDER BY agent_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var inventories []*models.SystemInventory
	for rows.Next() {
		var dataRaw string
		if err := rows.Scan(&dataRaw); err != nil {
			return nil, err
		}
		var inv models.SystemInventory
		if err := json.Unmarshal([]byte(dataRaw), &inv); err != nil {
			return nil, err
		}
		inventories = append(inventories, &inv)
	}
	return inventories, rows.Err()
}

// Log Events

func (s *SQLiteStorage) SaveLogEvent(ctx context.Context, e *models.LogEvent) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO log_events(id,agent_id,rule_id,rule_name,severity,log_source,log_line,captures,matched_at,received_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.AgentID, e.RuleID, e.RuleName, string(e.Severity),
		e.LogSource, e.LogLine, toJSON(e.Captures),
		e.MatchedAt.UTC(), time.Now().UTC(),
	)
	return err
}

func (s *SQLiteStorage) ListLogEvents(ctx context.Context, filter models.AlertFilter) ([]*models.LogEvent, error) {
	var conditions []string
	var args []interface{}

	if filter.AgentID != "" {
		conditions = append(conditions, "agent_id=?")
		args = append(args, filter.AgentID)
	}
	if !filter.Since.IsZero() {
		conditions = append(conditions, "received_at>=?")
		args = append(args, filter.Since.UTC())
	}

	query := `SELECT id,agent_id,rule_id,rule_name,severity,log_source,log_line,captures,matched_at,received_at FROM log_events`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY received_at DESC"
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*models.LogEvent
	for rows.Next() {
		var e models.LogEvent
		var capturesRaw, matchedAt string
		if err := rows.Scan(
			&e.ID, &e.AgentID, &e.RuleID, &e.RuleName, &e.Severity,
			&e.LogSource, &e.LogLine, &capturesRaw, &matchedAt, new(string),
		); err != nil {
			return nil, err
		}
		e.Captures = fromJSONMap(capturesRaw)
		e.MatchedAt = parseTime(matchedAt)
		events = append(events, &e)
	}
	return events, rows.Err()
}

// Audit Events

func (s *SQLiteStorage) SaveAuditEvent(ctx context.Context, e *models.AuditEvent) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO audit_events(id,agent_id,type,timestamp,pid,uid,username,path,old_path,mode,command,args,work_dir,return_code,process_name,parent_pid,received_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.AgentID, string(e.Type), e.Timestamp.UTC(),
		e.PID, e.UID, e.Username, e.Path, e.OldPath, e.Mode,
		e.Command, toJSON(e.Args), e.WorkDir, e.ReturnCode,
		e.ProcessName, e.ParentPID, time.Now().UTC(),
	)
	return err
}

func (s *SQLiteStorage) ListAuditEvents(ctx context.Context, filter models.AuditEventFilter) ([]*models.AuditEvent, error) {
	var conditions []string
	var args []interface{}

	if filter.AgentID != "" {
		conditions = append(conditions, "agent_id=?")
		args = append(args, filter.AgentID)
	}
	if filter.EventType != "" {
		conditions = append(conditions, "type=?")
		args = append(args, string(filter.EventType))
	}
	if filter.Username != "" {
		conditions = append(conditions, "username=?")
		args = append(args, filter.Username)
	}
	if !filter.Since.IsZero() {
		conditions = append(conditions, "timestamp>=?")
		args = append(args, filter.Since.UTC())
	}

	query := `SELECT id,agent_id,type,timestamp,pid,uid,username,path,old_path,mode,command,args,work_dir,return_code,process_name,parent_pid FROM audit_events`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY timestamp DESC"
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
		if filter.Offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", filter.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*models.AuditEvent
	for rows.Next() {
		var e models.AuditEvent
		var ts, argsRaw string
		if err := rows.Scan(
			&e.ID, &e.AgentID, &e.Type, &ts,
			&e.PID, &e.UID, &e.Username, &e.Path, &e.OldPath, &e.Mode,
			&e.Command, &argsRaw, &e.WorkDir, &e.ReturnCode,
			&e.ProcessName, &e.ParentPID,
		); err != nil {
			return nil, err
		}
		e.Timestamp = parseTime(ts)
		_ = json.Unmarshal([]byte(argsRaw), &e.Args)
		events = append(events, &e)
	}
	return events, rows.Err()
}

// Utilities

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// SortedRuleIDs returns rule IDs in a stable order for version hashing.
func SortedRuleIDs(rules []*models.Rule) []string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	sort.Strings(ids)
	return ids
}
