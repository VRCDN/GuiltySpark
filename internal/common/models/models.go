// Package models has all the types both binaries share — agents, rules, alerts, inventory, audit events, the works.
package models

import (
	"time"
)

// Version gets stamped in at build time via -ldflags. Falls back to "dev" if you forgot.
var Version = "dev"

// Agent

// AgentStatus is the three states an agent can be in.
type AgentStatus string

const (
	AgentStatusOnline  AgentStatus = "online"
	AgentStatusOffline AgentStatus = "offline"
	AgentStatusUnknown AgentStatus = "unknown"
)

// Agent is the collector's stored record of a monitored server.
type Agent struct {
	ID           string      `json:"id"`
	Hostname     string      `json:"hostname"`
	IPAddresses  []string    `json:"ip_addresses"`
	Region       string      `json:"region"`
	Tags         []string    `json:"tags"`
	Version      string      `json:"version"`
	OS           string      `json:"os,omitempty"`
	APIKey       string      `json:"api_key,omitempty"` // only returned at registration
	LastSeen     time.Time   `json:"last_seen"`
	Status       AgentStatus `json:"status"`
	RegisteredAt time.Time   `json:"registered_at"`
}

// RegisterRequest is what an agent sends when it shows up for the first time.
type RegisterRequest struct {
	Hostname        string   `json:"hostname"`
	IPAddresses     []string `json:"ip_addresses"`
	Tags            []string `json:"tags"`
	Version         string   `json:"version"`
	OS              string   `json:"os"`
	Region          string   `json:"region"`
	RegistrationKey string   `json:"registration_key,omitempty"`
}

// RegisterResponse hands back an agent ID and API key after registration.
type RegisterResponse struct {
	AgentID string `json:"agent_id"`
	APIKey  string `json:"api_key"`
}

// Heartbeat

// HeartbeatRequest is sent on every heartbeat tick.
type HeartbeatRequest struct {
	AgentID      string    `json:"agent_id"`
	Timestamp    time.Time `json:"timestamp"`
	RulesVersion string    `json:"rules_version"`
	Uptime       int64     `json:"uptime"` // seconds
}

// HeartbeatResponse lets the agent know if it needs to re-fetch rules.
type HeartbeatResponse struct {
	RulesUpdated bool   `json:"rules_updated"`
	RulesVersion string `json:"rules_version"`
}

// Rules

// Severity represents the impact level of a rule match.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Rule is a regex pattern matched against log lines. Tags scope it to the right log source;
// Platforms (optional) scopes it to specific OSes — empty means run everywhere.
type Rule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Pattern     string    `json:"pattern"`             // Go regex
	Tags        []string  `json:"tags"`                // log-source tags this rule applies to
	Platforms   []string  `json:"platforms,omitempty"` // OS IDs this rule applies to; empty = all
	Severity    Severity  `json:"severity"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Version     int64     `json:"version"`
}

// RulesResponse bundles the rule list with a short hash so agents know whether to reload
// without having to diff the whole thing.
type RulesResponse struct {
	Rules   []Rule `json:"rules"`
	Version string `json:"version"` // SHA-256 of enabled rule IDs+patterns
}

// Log Events

// LogEvent is what gets recorded when a rule matches a log line.
type LogEvent struct {
	ID        string            `json:"id"`
	AgentID   string            `json:"agent_id"`
	RuleID    string            `json:"rule_id"`
	RuleName  string            `json:"rule_name"`
	Severity  Severity          `json:"severity"`
	LogSource string            `json:"log_source"` // file path or "docker:<container>"
	LogLine   string            `json:"log_line"`
	Captures  map[string]string `json:"captures,omitempty"` // named regex groups
	MatchedAt time.Time         `json:"matched_at"`
}

// LogEventsRequest is a batch of log events — sent all at once to reduce HTTP round-trips.
type LogEventsRequest struct {
	Events []LogEvent `json:"events"`
}

// Alerts

// AlertType tracks where an alert came from.
type AlertType string

const (
	AlertTypeLogMatch     AlertType = "log_match"
	AlertTypeAgentOffline AlertType = "agent_offline"
	AlertTypeAgentOnline  AlertType = "agent_online"
	AlertTypeAuditEvent   AlertType = "audit_event"
)

// Alert is something the user probably wants to know about.
type Alert struct {
	ID             string     `json:"id"`
	AgentID        string     `json:"agent_id"`
	RuleID         string     `json:"rule_id,omitempty"`
	RuleName       string     `json:"rule_name,omitempty"`
	Severity       Severity   `json:"severity"`
	AlertType      AlertType  `json:"alert_type"`
	Message        string     `json:"message"`
	LogLine        string     `json:"log_line,omitempty"`
	LogSource      string     `json:"log_source,omitempty"`
	MatchedAt      time.Time  `json:"matched_at"`
	ReceivedAt     time.Time  `json:"received_at"`
	Acknowledged   bool       `json:"acknowledged"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
}

// AlertFilter narrows down which alerts you want.
type AlertFilter struct {
	AgentID      string
	Severity     Severity
	Acknowledged *bool
	AlertType    AlertType
	Since        time.Time
	Limit        int
	Offset       int
}

// Inventory

// SystemInventory is a point-in-time snapshot of everything we know about a server.
type SystemInventory struct {
	AgentID     string        `json:"agent_id"`
	CollectedAt time.Time     `json:"collected_at"`
	OS          OSInfo        `json:"os"`
	Hardware    HardwareInfo  `json:"hardware"`
	Network     NetworkInfo   `json:"network"`
	Packages    []PackageInfo `json:"packages"`
	Services    []ServiceInfo `json:"services"`
	Users       []UserInfo    `json:"users"`
}

// OSInfo is what we scraped from /etc/os-release and uname.
type OSInfo struct {
	Name          string `json:"name"`           // e.g. "Ubuntu"
	Version       string `json:"version"`        // e.g. "22.04 LTS"
	KernelVersion string `json:"kernel_version"` // e.g. "5.15.0-101-generic"
	Architecture  string `json:"architecture"`   // e.g. "x86_64"
	Hostname      string `json:"hostname"`
	Uptime        int64  `json:"uptime"` // seconds
}

// HardwareInfo is what we scraped from /proc/cpuinfo, /proc/meminfo, and statfs.
type HardwareInfo struct {
	CPUModel    string `json:"cpu_model"`
	CPUCores    int    `json:"cpu_cores"`
	CPUThreads  int    `json:"cpu_threads"`
	MemoryTotal int64  `json:"memory_total"` // bytes
	MemoryFree  int64  `json:"memory_free"`  // bytes
	DiskTotal   int64  `json:"disk_total"`   // bytes (root fs)
	DiskFree    int64  `json:"disk_free"`    // bytes
}

// NetworkInterface is a single NIC.
type NetworkInterface struct {
	Name        string   `json:"name"`
	MACAddress  string   `json:"mac_address"`
	IPAddresses []string `json:"ip_addresses"`
	IsUp        bool     `json:"is_up"`
}

// NetworkInfo holds interfaces, hostname, and DNS servers.
type NetworkInfo struct {
	Interfaces []NetworkInterface `json:"interfaces"`
	Hostname   string             `json:"hostname"`
	DNSServers []string           `json:"dns_servers"`
}

// PackageInfo is a single installed package.
type PackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Manager string `json:"manager"` // apt, rpm, snap, etc.
}

// ServiceInfo is a single systemd or OpenRC service.
type ServiceInfo struct {
	Name    string `json:"name"`
	Status  string `json:"status"`  // running, stopped, failed, unknown
	Enabled bool   `json:"enabled"` // starts on boot
}

// UserInfo is a single local user parsed from /etc/passwd.
type UserInfo struct {
	Username string `json:"username"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	HomeDir  string `json:"home_dir"`
	Shell    string `json:"shell"`
	IsSystem bool   `json:"is_system"` // UID < 1000 on most distros
}

// Audit Events

// AuditEventType classifies audit events.
type AuditEventType string

const (
	AuditEventFileCreate     AuditEventType = "file_create"
	AuditEventFileModify     AuditEventType = "file_modify"
	AuditEventFileDelete     AuditEventType = "file_delete"
	AuditEventFileRename     AuditEventType = "file_rename"
	AuditEventFilePermission AuditEventType = "file_permission"
	AuditEventFileOwnership  AuditEventType = "file_ownership"
	AuditEventExec           AuditEventType = "exec"
)

// AuditEvent is something security-relevant that happened on the host.
type AuditEvent struct {
	ID          string         `json:"id"`
	AgentID     string         `json:"agent_id"`
	Type        AuditEventType `json:"type"`
	Timestamp   time.Time      `json:"timestamp"`
	PID         int            `json:"pid,omitempty"`
	UID         int            `json:"uid,omitempty"`
	Username    string         `json:"username,omitempty"`
	Path        string         `json:"path,omitempty"`
	OldPath     string         `json:"old_path,omitempty"` // for renames
	Mode        string         `json:"mode,omitempty"`     // e.g. "0755"
	Command     string         `json:"command,omitempty"`
	Args        []string       `json:"args,omitempty"`
	WorkDir     string         `json:"work_dir,omitempty"`
	ReturnCode  int            `json:"return_code,omitempty"`
	ProcessName string         `json:"process_name,omitempty"`
	ParentPID   int            `json:"parent_pid,omitempty"`
}

// AuditEventsRequest is a batch of audit events — same batching story as log events.
type AuditEventsRequest struct {
	Events []AuditEvent `json:"events"`
}

// AuditEventFilter narrows down which audit events you want.
type AuditEventFilter struct {
	AgentID   string
	EventType AuditEventType
	Username  string
	Since     time.Time
	Limit     int
	Offset    int
}

// LogSource describes a log file or Docker source that agents should monitor.
type LogSource struct {
	ID   string   `json:"id"`
	Path string   `json:"path"` // file path or "" for docker sources
	Tags []string `json:"tags"` // matched against rule tags
	Type string   `json:"type"` // "file" | "docker"
}

// APIResponse wraps every API response so callers always get the same {success, data, error} shape.
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}
