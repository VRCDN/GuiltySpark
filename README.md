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
│                         │               │               │
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

# 2 — Run the collector (listens on :9900)
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
curl -fsSL https://raw.githubusercontent.com/VRCDN/GuiltySpark/main/scripts/install.sh | \
    sudo sh -s -- --collector \
        --admin-key <admin-key> \
        --reg-key <registration-key>

# Install the agent on each monitored host
# --reg-key must match the registration_key set during the collector install
curl -fsSL https://raw.githubusercontent.com/VRCDN/GuiltySpark/main/scripts/install.sh | \
    sudo sh -s -- --agent \
        --collector-url http://collector.example.com:9900 \
        --reg-key <registration-key>
```

The script:
- Downloads the appropriate binary for your architecture (`amd64` / `arm64`)
- Creates the `guiltyspark` system user
- Writes default config files under `/etc/guiltyspark/`
- Installs and enables a systemd or OpenRC unit

#### All install options

| Flag | Default | Description |
|---|---|---|
| `--collector` | — | Act on the collector component |
| `--agent` | — | Act on the agent component |
| `--install` | ✓ | Install the selected component(s) *(default mode)* |
| `--upgrade` | — | Stop service, replace binary, restart — config untouched |
| `--uninstall` | — | Remove binary and service unit |
| `--purge` | — | Also remove config files and data (use with `--uninstall`) |
| `--version VER` | `latest` | Release version to download (e.g. `v1.1.0`) |
| `--host HOST` | `0.0.0.0` | Collector listen address |
| `--port PORT` | `9900` | Collector listen port |
| `--collector-url URL` | — | Collector URL written into the agent config |
| `--admin-key KEY` | — | Admin API key (collector install) |
| `--reg-key KEY` | — | Registration key — must match on both collector and agent |
| `--agent-key KEY` | — | Pre-shared agent API key (optional) |
| `--config-dir DIR` | `/etc/guiltyspark` | Config directory |
| `--data-dir DIR` | `/var/lib/guiltyspark` | Data/state directory |
| `--no-init` | — | Skip init system registration (systemd / OpenRC) |

#### Upgrade

```bash
# Upgrade collector and agent to the latest release (config untouched)
curl -fsSL https://raw.githubusercontent.com/VRCDN/GuiltySpark/main/scripts/install.sh | \
    sudo sh -s -- --collector --agent --upgrade

# Upgrade agent to a specific version
curl -fsSL https://raw.githubusercontent.com/VRCDN/GuiltySpark/main/scripts/install.sh | \
    sudo sh -s -- --agent --upgrade --version v1.1.0
```

#### Uninstall

```bash
# Remove binary and service unit (keep config and data)
curl -fsSL https://raw.githubusercontent.com/VRCDN/GuiltySpark/main/scripts/install.sh | \
    sudo sh -s -- --agent --uninstall

# Full removal including config files and database
curl -fsSL https://raw.githubusercontent.com/VRCDN/GuiltySpark/main/scripts/install.sh | \
    sudo sh -s -- --collector --agent --uninstall --purge
```

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
  host: "0.0.0.0"
  port: 9900
  # tls:
  #   enabled: true
  #   cert_file: /etc/guiltyspark/tls/server.crt
  #   key_file:  /etc/guiltyspark/tls/server.key

database:
  path: "/var/lib/guiltyspark/collector.db"

auth:
  # Required for all admin API requests.
  admin_api_key: "your-strong-admin-key"
  # Agents must supply this key when registering.
  # Leave blank to allow any agent to register (not recommended).
  registration_key: "your-strong-registration-key"

heartbeat:
  timeout:        "90s"   # mark agent offline after this long without a ping
  check_interval: "30s"

alerts:
  dedup_window: "5m"      # suppress duplicate alerts within this window
  notifications:
    webhook:
      enabled: true
      url:    "https://hooks.example.com/guiltyspark"
      secret: "hmac-signing-secret"
    # discord:
    #   enabled: true
    #   webhook_url: "https://discord.com/api/webhooks/<id>/<token>"
    #   username: "GuiltySpark"   # optional bot display name override
    # slack:
    #   enabled: true
    #   webhook_url: "https://hooks.slack.com/services/..."
    # email:
    #   enabled: true
    #   smtp_host: "smtp.example.com"
    #   smtp_port: 587
    #   from:      "guiltyspark@example.com"
    #   to:        ["ops@example.com"]
    # custom_webhooks:
    #   - name: "PagerDuty"
    #     enabled: true
    #     url: "https://events.pagerduty.com/v2/enqueue"
    #     headers:
    #       Authorization: "Token token=YOUR_KEY"
    #     body_template: |
    #       routing_key: "YOUR_ROUTING_KEY"
    #       event_action: "trigger"
    #       payload:
    #         summary: "{{ .Message }}"
    #         severity: "{{ lower .Severity }}"
    #         source: "{{ .AgentID }}"
    #         custom_details:
    #           rule_name: "{{ .RuleName }}"
    #           alert_type: "{{ .AlertType }}"
    #           log_line: "{{ .LogLine }}"
    #   - name: "Teams"
    #     enabled: true
    #     url: "https://outlook.office.com/webhook/..."
    #     body_template: |
    #       "@type": "MessageCard"
    #       "@context": "http://schema.org/extensions"
    #       themeColor: "e74c3c"
    #       summary: "{{ .Message }}"
    #       sections:
    #         - activityTitle: "[{{ upper .Severity }}] {{ .AlertType }}"
    #           activityText: "{{ .Message }}"
    #           facts:
    #             - name: Agent
    #               value: "{{ .AgentID }}"
    #             - name: Rule
    #               value: "{{ .RuleName }}"
### Agent Config

`/etc/guiltyspark/agent.yaml`:

```yaml
collector:
  url: "https://collector.example.com:9900"
  timeout: "30s"
  tls:
    # ca_cert: /etc/guiltyspark/tls/ca.crt
    skip_verify: false

auth:
  # Populated automatically after first registration.
  api_key: ""
  # Must match the collector's auth.registration_key.
  registration_key: "your-strong-registration-key"

agent:
  tags:
    - "production"
    - "linux"
  region: "us-east-1"

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
  enabled: true
  exec:
    enabled: true
  file_watch:
    enabled: true
    paths:
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
BASE="https://collector.example.com:9900"
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
git clone https://github.com/VRCDN/GuiltySpark.git
cd GuiltySpark

# Build both binaries to ./bin/
make build

# Cross-compile for linux/arm64
GOARCH=arm64 make build

# Run tests
make test

# Lint (requires golangci-lint)
make lint

# Build release binaries for all supported platforms (dist/)
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
- **Registration key** — controls which agents are allowed to join. Set `auth.registration_key` on the collector and supply the same value via `--reg-key` (or `auth.registration_key` in agent.yaml) on each agent. Without it, any host that can reach the collector can register.
- **Agent keys** — issued per agent at registration; revoke by deleting the agent via the API.
- **TLS** — strongly recommended in production. Use `make cert` to generate a self-signed cert for testing, or point `tls.cert_file` / `tls.key_file` at a real certificate.
- **Exec audit** — requires `CAP_AUDIT_READ` + `CAP_AUDIT_WRITE` (or running as root). The systemd unit grants these via `AmbientCapabilities`.
- **Docker socket** — mounting `/var/run/docker.sock` grants root-equivalent access; ensure the collector host is trusted.
- **Webhook HMAC** — the collector signs every outbound webhook payload with HMAC-SHA256 using `alerts.notifications.webhook.secret`. Verify the `X-GuiltySpark-Signature` header on your receiver.
- **Discord** — use `alerts.notifications.discord.webhook_url`. No signing is applied (Discord handles auth via the URL token). The bot display name defaults to `GuiltySpark` and can be overridden with `discord.username`.
- **Custom webhooks** — `alerts.notifications.custom_webhooks` accepts a list of fully templated HTTP requests. Each entry has a `body_template` written in [Go `text/template`](https://pkg.go.dev/text/template) syntax that renders to a YAML document, which is automatically converted to JSON before sending. Set `content_type` to anything other than `application/json` to send the rendered text verbatim. Available template variables: `.ID`, `.AgentID`, `.RuleID`, `.RuleName`, `.Severity`, `.AlertType`, `.Message`, `.LogLine`, `.LogSource`, `.MatchedAt`, `.ReceivedAt`. Built-in functions: `upper`, `lower`. Custom headers and optional HMAC signing (`secret`) are also supported.

---

## License

GNU GPLv3 — see [LICENSE](LICENSE).
