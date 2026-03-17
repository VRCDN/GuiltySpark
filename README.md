# GuiltySpark

GuiltySpark monitors your fleet of Linux servers by collecting logs, tracking system inventory, and running real-time audit, all with a lightweight agent that phones home to a central collector. Alerts are dispatched via webhook, email, or Slack the moment something suspicious happens.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
  - [Collector](#collector)
  - [Agent](#agent)
  - [Docker](#docker)
  - [systemd](#systemd)
- [Configuration](#configuration)
  - [Collector Config](#collector-config)
  - [Agent Config](#agent-config)
- [Log Rules](#log-rules)
- [API Reference](#api-reference)
- [Building from Source](#building-from-source)
- [Security Notes](#security-notes)
- [License](#license)

---

## Features

| Category | Capability |
|---|---|
| **Log collection** | Tails any file (with rotation handling) and streams Docker container logs |
| **Rule engine** | Tag-scoped regex rules with named capture groups; synced from the collector |
| **Alerting** | Webhook (HMAC-signed), SMTP email, Slack; configurable deduplication window |
| **Heartbeat** | Agents report every 30 s; collector fires an alert if a host goes silent |
| **Inventory** | OS, kernel, CPU, memory, disk, packages (dpkg/rpm/snap), services, users |
| **File audit** | inotify-based watch of configured paths — create, write, delete, rename, chmod |
| **Exec audit** | Linux `NETLINK_AUDIT` socket — captures every `execve` with PID, UID, argv |
| **Storage** | Embedded SQLite — zero external dependencies, no database server needed |
| **Auth** | Admin API key for management; per-agent key issued at registration |
| **TLS** | Optional TLS on the collector; agents support custom CA certificates |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                Collector  (per region)                  │
│                                                         │
│  HTTP/TLS API ──► Rule Manager ──► Alert Manager        │
│                        │               │                │
│  Heartbeat Monitor      │          Webhook/Email/Slack  │
│  Inventory Store        │                               │
│  SQLite Storage ◄───────┘                               │
└───────────────────────────────┬─────────────────────────┘
                                │ HTTPS
          ┌─────────────────────┼────────────────────┐
          │                     │                    │
   ┌──────┴──────┐       ┌──────┴──────┐      ┌──────┴──────┐
   │   Agent 1   │       │   Agent 2   │      │   Agent N   │
   │             │       │             │      │             │
   │ Log Tailer  │       │ Log Tailer  │      │ Log Tailer  │
   │ Scanner     │       │ Scanner     │      │ Scanner     │
   │ Inventory   │       │ Inventory   │      │ Inventory   │
   │ Audit       │       │ Audit       │      │ Audit       │
   │ Heartbeat   │       │ Heartbeat   │      │ Heartbeat   │
   └─────────────┘       └─────────────┘      └─────────────┘
```

### Data Flow

1. **Registration** — Agent calls `POST /api/v1/agents/register` and receives a unique ID and API key.
2. **Heartbeat** — Every 30 s the agent sends a heartbeat; the response includes the current rules-version hash.
3. **Rule sync** — When the version hash changes, the agent fetches the new rule set and starts using it immediately.
4. **Log events** — Matched lines are batched (≤100 events or 5 s) and posted to the collector, which evaluates alert conditions.
5. **Inventory** — Full system snapshot sent every hour (configurable).
6. **Audit events** — File and exec events are batched (≤100 or 2 s) and streamed to the collector.
7. **Notifications** — Alert Manager deduplicates alerts per (agent, rule) and dispatches to configured channels.

---

## Quick Start

```bash
# 1 — Build
make build

# 2 — Run the collector (listens on :8080)
./bin/guiltyspark-collector \
    -config configs/collector.yaml \
    -rules  configs/default_rules.yaml

# 3 — Run an agent on any monitored host (must be root for audit access)
sudo ./bin/guiltyspark-agent -config configs/agent.yaml
```

The agent registers itself with the collector on first boot and stores its credentials in `agent-state.json`.

---

## Installation

### Automated (recommended)

```bash
# Install the collector on the aggregation host
curl -fsSL https://raw.githubusercontent.com/VRCDN/guiltyspark/main/scripts/install.sh | \
    sudo bash -s -- --collector

# Install the agent on each monitored host
curl -fsSL https://raw.githubusercontent.com/VRCDN/guiltyspark/main/scripts/install.sh | \
    sudo bash -s -- --agent --collector-url https://collector.example.com
```

The script:
- Downloads the appropriate binary for your architecture (`amd64` / `arm64`)
- Creates the `guiltyspark` system user
- Writes default config files under `/etc/guiltyspark/`
- Installs and enables a systemd unit

### Collector

```bash
sudo install -m 755 bin/guiltyspark-collector /usr/local/bin/
sudo mkdir -p /etc/guiltyspark /var/lib/guiltyspark
sudo cp configs/collector.yaml configs/default_rules.yaml /etc/guiltyspark/
```

Edit `/etc/guiltyspark/collector.yaml` — at minimum set `server.admin_api_key`.

### Agent

```bash
sudo install -m 755 bin/guiltyspark-agent /usr/local/bin/
sudo mkdir -p /etc/guiltyspark /var/lib/guiltyspark
sudo cp configs/agent.yaml /etc/guiltyspark/
```

Edit `/etc/guiltyspark/agent.yaml` — set `collector.url` and `collector.api_key` (leave empty for auto-registration).

### Docker

**Production** (collector + Traefik TLS):

```bash
# Copy and edit the env file
cp deployments/.env.example .env  # set COLLECTOR_DOMAIN, ACME_EMAIL, etc.

docker compose -f deployments/docker-compose.yml up -d
```

**Single-host development** (collector + agent on the same machine):

```bash
docker compose \
    -f deployments/docker-compose.yml \
    -f deployments/docker-compose.dev.yml \
    up --build
```

### systemd

```bash
# Collector
sudo cp deployments/guiltyspark-collector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now guiltyspark-collector

# Agent
sudo cp deployments/guiltyspark-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now guiltyspark-agent
```

---

## Configuration

### Collector Config

`/etc/guiltyspark/collector.yaml`:

```yaml
server:
  listen_addr:   "0.0.0.0:8080"
  admin_api_key: "your-strong-admin-key"
  # tls:
  #   cert_file: /etc/guiltyspark/tls/server.crt
  #   key_file:  /etc/guiltyspark/tls/server.key

storage:
  sqlite_path: "/var/lib/guiltyspark/collector.db"

heartbeat:
  timeout:        "90s"   # mark agent offline after this long without a ping
  check_interval: "30s"

alerts:
  dedup_window: "5m"      # suppress duplicate alerts within this window
  webhook:
    url:    "https://hooks.example.com/guiltyspark"
    secret: "hmac-signing-secret"
  # email:
  #   smtp_host: "smtp.example.com:587"
  #   from:      "guiltyspark@example.com"
  #   to:        ["ops@example.com"]
  # slack:
  #   webhook_url: "https://hooks.slack.com/services/..."

rules:
  seed_if_empty: true     # load default_rules.yaml when DB has no rules
```

### Agent Config

`/etc/guiltyspark/agent.yaml`:

```yaml
collector:
  url:     "https://collector.example.com"
  api_key: ""             # leave empty; agent self-registers on first boot
  # ca_cert: /etc/guiltyspark/tls/ca.crt

heartbeat:
  interval: "30s"

log_sources:
  - path: "/var/log/syslog"
    tags: ["syslog"]
  - path: "/var/log/auth.log"
    tags: ["auth", "sshd", "pam", "sudo"]
  - path: "/var/log/kern.log"
    tags: ["kernel"]
  - path: "/var/log/dpkg.log"
    tags: ["packages"]

docker:
  enabled: true
  socket:  "/var/run/docker.sock"

inventory:
  enabled:  true
  interval: "1h"

audit:
  exec_enabled: true
  file_enabled: true
  watch_paths:
    - "/etc"
    - "/bin"
    - "/usr/bin"
    - "/usr/sbin"

state_file: "/var/lib/guiltyspark/agent-state.json"
```

---

## Log Rules

Rules live in `configs/default_rules.yaml` (35 built-in rules) and can be managed live via the API. Each rule has:

| Field | Type | Description |
|---|---|---|
| `name` | string | Human-readable name |
| `description` | string | What the rule detects |
| `pattern` | string | Go regular expression (supports named groups `(?P<name>...)`) |
| `tags` | []string | Source tags this rule applies to (empty = apply to all) |
| `severity` | string | `info` / `low` / `medium` / `high` / `critical` |
| `enabled` | bool | Whether the rule is active |

**Tag scoping** — a rule with `tags: ["sshd"]` only fires when the log line comes from a source that also has the `sshd` tag. This prevents SSH rules from matching Docker logs and vice versa.

**Named captures** — capture groups are extracted and attached to the log event:

```yaml
pattern: 'Failed password for (?P<username>\S+) from (?P<ip>[\d.]+)'
```

### Managing Rules via API

```bash
BASE="https://collector.example.com"
KEY="your-admin-key"

# List all rules
curl -H "X-API-Key: $KEY" "$BASE/api/v1/rules"

# Create a rule
curl -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"name":"My Rule","pattern":"danger","tags":["syslog"],"severity":"high","enabled":true}' \
  "$BASE/api/v1/rules"

# Update a rule
curl -X PUT -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"enabled":false}' \
  "$BASE/api/v1/rules/<rule-id>"

# Delete a rule
curl -X DELETE -H "X-API-Key: $KEY" "$BASE/api/v1/rules/<rule-id>"
```

---

## API Reference

All endpoints accept and return `application/json`. Agent endpoints require `X-API-Key: <agent-key>`; admin endpoints require `X-API-Key: <admin-key>`.

### Agent Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/agents/register` | Register a new agent; returns agent ID and API key |
| `POST` | `/api/v1/agents/:id/heartbeat` | Send heartbeat; returns rules version hash |
| `GET` | `/api/v1/agents/:id/rules` | Fetch current rule set |
| `POST` | `/api/v1/agents/:id/events` | Submit log match events |
| `POST` | `/api/v1/agents/:id/inventory` | Submit system inventory snapshot |
| `POST` | `/api/v1/agents/:id/audit-events` | Submit file/exec audit events |

### Admin Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/agents` | List all registered agents |
| `GET` | `/api/v1/rules` | List all rules |
| `POST` | `/api/v1/rules` | Create a rule |
| `PUT` | `/api/v1/rules/:id` | Update a rule |
| `DELETE` | `/api/v1/rules/:id` | Delete a rule |
| `GET` | `/api/v1/alerts` | List alerts (supports `?severity=`, `?agent_id=`, `?acked=`) |
| `PUT` | `/api/v1/alerts/:id/acknowledge` | Acknowledge an alert |
| `GET` | `/api/v1/inventory/:agent_id` | Get latest inventory for an agent |
| `GET` | `/api/v1/audit-events` | List audit events |
| `GET` | `/api/v1/health` | Health check — returns component status |

---

## Building from Source

**Requirements:** Go 1.22+, Linux (for audit subsystem; other platforms build but exec-audit is no-op)

```bash
git clone https://github.com/VRCDN/guiltyspark.git
cd guiltyspark

# Build both binaries to ./bin/
make build

# Cross-compile for linux/arm64
make build GOARCH=arm64

# Run tests
make test

# Lint (requires golangci-lint)
make lint

# Build versioned release archives
make release VERSION=v1.0.0
```

### Makefile Targets

| Target | Description |
|---|---|
| `make build` | Build collector and agent to `./bin/` |
| `make test` | Run unit tests |
| `make test-coverage` | Tests with HTML coverage report |
| `make vet` | Run `go vet ./...` |
| `make lint` | Run `golangci-lint` |
| `make fmt` | Run `gofmt` |
| `make cert` | Generate a self-signed TLS cert for development |
| `make docker` | Build Docker images |
| `make docker-compose-up` | Start the collector stack |
| `make release` | Build + archive binaries for amd64 + arm64 |
| `make clean` | Remove build artifacts |

---

## Security Notes

- **Admin key** — treat it like a root password; rotate it if compromised.
- **Agent keys** — issued per agent at registration; revoke by deleting the agent via the API.
- **TLS** — strongly recommended in production. Use `make cert` to generate a self-signed cert for testing, or point `tls.cert_file` / `tls.key_file` at a real certificate.
- **Exec audit** — requires `CAP_AUDIT_READ` + `CAP_AUDIT_WRITE` (or running as root). The systemd unit grants these via `AmbientCapabilities`.
- **Docker socket** — mounting `/var/run/docker.sock` grants root-equivalent access; ensure the collector host is trusted.
- **Webhook HMAC** — the collector signs every outbound webhook payload with HMAC-SHA256 using `alerts.webhook.secret`. Verify the `X-GuiltySpark-Signature` header on your receiver.

---

## License

GNU GPLv3 — see [LICENSE](LICENSE).
