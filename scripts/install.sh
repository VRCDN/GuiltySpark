#!/bin/sh
# GuiltySpark install script
# Installs, upgrades, or uninstalls guiltyspark-collector and/or guiltyspark-agent.
# Supports: Debian/Ubuntu (apt), Arch Linux (pacman), Alpine Linux (apk),
#           RHEL/CentOS/Fedora (dnf/yum).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/VRCDN/GuiltySpark/main/scripts/install.sh | \
#       sh -s -- [--collector] [--agent] [--install|--upgrade|--uninstall] [OPTIONS]
#
# Modes (pick one, default is --install):
#   --install          Install the selected component(s)
#   --upgrade          Stop service, replace binary, restart — config untouched
#   --uninstall        Remove binary and service unit
#
# Components (pick at least one):
#   --collector        Act on the collector
#   --agent            Act on the agent
#
# Install options:
#   --version VER      Release version to download (default: latest)
#   --host HOST        Collector listen address   (default: 0.0.0.0)
#   --port PORT        Collector listen port      (default: 9900)
#   --collector-url U  Collector URL written into the agent config
#   --admin-key KEY    Admin API key (collector install)
#   --reg-key KEY      Registration key — must match on both collector and agent
#   --agent-key KEY    Pre-shared agent API key (optional)
#   --config-dir DIR   Config directory       (default: /etc/guiltyspark)
#   --data-dir DIR     Data/state directory   (default: /var/lib/guiltyspark)
#   --no-init          Skip init system registration
#
# Uninstall options:
#   --purge            Also remove config files and data (default: keep them)
#
# --debug            Print extra diagnostic output
# --help             Show this help

set -eu

# ---- Defaults ---------------------------------------------------------------
INSTALL_COLLECTOR=false
INSTALL_AGENT=false
MODE="install"    # install | upgrade | uninstall
PURGE=false
VERSION="latest"
COLLECTOR_HOST="0.0.0.0"
COLLECTOR_PORT="9900"
COLLECTOR_URL=""
ADMIN_KEY=""
AGENT_KEY=""
REG_KEY=""
CONFIG_DIR="/etc/guiltyspark"
DATA_DIR="/var/lib/guiltyspark"
LOG_DIR="/var/log/guiltyspark"
BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
INITD_DIR="/etc/init.d"
NO_INIT=false
INIT_SYSTEM=""   # auto-detected: systemd | openrc | none
PKG_MANAGER=""   # auto-detected: apt | pacman | apk | dnf | yum | none
GITHUB_REPO="VRCDN/guiltyspark"
DEBUG=false

# ---- Colours ----------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
dbg()     { $DEBUG && echo -e "${YELLOW}[DBG]${NC}   $*" || true; }

# ---- Argument parsing -------------------------------------------------------
while [ "$#" -gt 0 ]; do
  case "$1" in
    --collector)     INSTALL_COLLECTOR=true; shift ;;
    --agent)         INSTALL_AGENT=true; shift ;;
    --install)       MODE="install"; shift ;;
    --upgrade)       MODE="upgrade"; shift ;;
    --uninstall)     MODE="uninstall"; shift ;;
    --purge)         PURGE=true; shift ;;
    --version)       VERSION="$2"; shift 2 ;;
    --host)          COLLECTOR_HOST="$2"; shift 2 ;;
    --port)          COLLECTOR_PORT="$2"; shift 2 ;;
    --collector-url) COLLECTOR_URL="$2"; shift 2 ;;
    --admin-key)     ADMIN_KEY="$2"; shift 2 ;;
    --agent-key)     AGENT_KEY="$2"; shift 2 ;;
    --reg-key)       REG_KEY="$2"; shift 2 ;;
    --config-dir)    CONFIG_DIR="$2"; shift 2 ;;
    --data-dir)      DATA_DIR="$2"; shift 2 ;;
    --no-init)       NO_INIT=true; shift ;;
    --no-systemd)    NO_INIT=true; shift ;; # legacy alias
    --debug)         DEBUG=true; shift ;;
    --help|-h)
      grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) error "Unknown argument: $1" ;;
  esac
done

if ! $INSTALL_COLLECTOR && ! $INSTALL_AGENT; then
  error "Specify at least one of --collector or --agent"
fi

# ---- Pre-flight / OS detection ---------------------------------------------
[ "$(uname -s)" = "Linux" ] || error "Only Linux is supported"
[ "$(id -u)" -eq 0 ]         || error "Please run as root (sudo)"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  *)        error "Unsupported architecture: $ARCH" ;;
esac

# Detect package manager
if command -v apt-get >/dev/null 2>&1; then
  PKG_MANAGER="apt"
elif command -v pacman >/dev/null 2>&1; then
  PKG_MANAGER="pacman"
elif command -v apk >/dev/null 2>&1; then
  PKG_MANAGER="apk"
elif command -v dnf >/dev/null 2>&1; then
  PKG_MANAGER="dnf"
elif command -v yum >/dev/null 2>&1; then
  PKG_MANAGER="yum"
else
  PKG_MANAGER="none"
fi
info "Detected package manager: ${PKG_MANAGER}"

# Detect init system
if [ -d /run/systemd/system ] || systemctl --version >/dev/null 2>&1; then
  INIT_SYSTEM="systemd"
elif command -v rc-service >/dev/null 2>&1; then
  INIT_SYSTEM="openrc"
else
  INIT_SYSTEM="none"
fi
info "Detected init system: ${INIT_SYSTEM}"

# Ensure curl is present
if ! command -v curl >/dev/null 2>&1; then
  info "Installing curl..."
  case "$PKG_MANAGER" in
    apt)    apt-get update -qq && apt-get install -y -q curl ;;
    pacman) pacman -Sy --noconfirm curl ;;
    apk)    apk add --no-cache curl ;;
    dnf)    dnf install -y curl ;;
    yum)    yum install -y curl ;;
    *)      error "curl not found and no supported package manager detected" ;;
  esac
fi

# ---- Resolve latest version -------------------------------------------------
resolve_version() {
  if [ "$VERSION" = "latest" ]; then
    info "Resolving latest release..."
    VERSION="$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
      | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')"
    [ -n "$VERSION" ] || error "Could not determine latest version"
    info "Latest version: ${VERSION}"
  fi
}

# ---- Download binary --------------------------------------------------------
download_binary() {
  local name="$1"
  local dest="${BIN_DIR}/${name}"
  local url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${name}-linux-${ARCH}"
  info "Downloading ${name} ${VERSION} (linux/${ARCH})..."
  curl -fsSL -o "${dest}.tmp" "$url"
  chmod 755 "${dest}.tmp"
  mv "${dest}.tmp" "${dest}"
  success "Installed ${dest}"
}

# ---- Create system user -----------------------------------------------------
ensure_user() {
  dbg "ensure_user: PKG_MANAGER=${PKG_MANAGER}"
  dbg "ensure_user: /etc/passwd entry: $(grep '^guiltyspark:' /etc/passwd 2>/dev/null || echo '(none)')"
  dbg "ensure_user: /etc/group  entry: $(grep '^guiltyspark:' /etc/group  2>/dev/null || echo '(none)')"

  # ---- Ensure the group exists (independent of the user check) ----
  if ! grep -q '^guiltyspark:' /etc/group 2>/dev/null; then
    dbg "ensure_user: creating group 'guiltyspark'"
    if [ "$PKG_MANAGER" = "apk" ]; then
      addgroup -S guiltyspark || error "Failed to create group 'guiltyspark'"
    else
      groupadd -r guiltyspark 2>/dev/null || \
      groupadd    guiltyspark            || \
      error "Failed to create group 'guiltyspark'"
    fi
    success "Created group 'guiltyspark'"
  else
    dbg "ensure_user: group 'guiltyspark' already exists"
  fi

  # ---- Ensure the user exists ----
  if id guiltyspark >/dev/null 2>&1; then
    dbg "ensure_user: user 'guiltyspark' already exists (id=$(id guiltyspark))"
    return 0
  fi

  dbg "ensure_user: creating user 'guiltyspark'"
  if [ "$PKG_MANAGER" = "apk" ]; then
    # adduser -S system  -D no-password  -H no-home  -G primary-group
    adduser -S -D -H -G guiltyspark guiltyspark || \
    error "Failed to create system user 'guiltyspark'"
  else
    useradd -r -s /bin/false -M -g guiltyspark guiltyspark 2>/dev/null || \
    useradd -r             -M -g guiltyspark guiltyspark            || \
    error "Failed to create system user 'guiltyspark'"
  fi
  success "Created system user 'guiltyspark'"
  dbg "ensure_user: post-create id: $(id guiltyspark 2>&1)"
}

# ---- Create directories -----------------------------------------------------
create_dirs() {
  mkdir -p "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}"
  # Use numeric UID:GID so chown works even if nscd/name-resolution is absent.
  local gs_uid gs_gid
  gs_uid="$(id -u guiltyspark 2>/dev/null)" || error "User 'guiltyspark' not found after ensure_user"
  gs_gid="$(id -g guiltyspark 2>/dev/null)" || error "Group for 'guiltyspark' not found after ensure_user"
  dbg "create_dirs: chown ${gs_uid}:${gs_gid} ${DATA_DIR} ${LOG_DIR}"
  chown "${gs_uid}:${gs_gid}" "${DATA_DIR}" "${LOG_DIR}"
  chmod 750 "${DATA_DIR}" "${LOG_DIR}"
}

# ---- Generate a random key --------------------------------------------------
gen_key() {
  head -c 32 /dev/urandom | base64 | tr -d '=+/' | head -c 40
}

# ---- Install collector ------------------------------------------------------
install_collector() {
  info "=== Installing GuiltySpark Collector ==="
  resolve_version
  ensure_user
  create_dirs
  download_binary "guiltyspark-collector"

  # Config
  if [ ! -f "${CONFIG_DIR}/collector.yaml" ]; then
    local admin_key="${ADMIN_KEY:-$(gen_key)}"
    local reg_key="${REG_KEY:-$(gen_key)}"
    info "Generated admin key:        ${admin_key}"
    info "Generated registration key: ${reg_key}"
    info "(save these — they are only shown once)"
    cat >"${CONFIG_DIR}/collector.yaml" <<EOF
server:
  host: "${COLLECTOR_HOST}"
  port: ${COLLECTOR_PORT}
  # tls:
  #   enabled: true
  #   cert_file: /etc/guiltyspark/tls/server.crt
  #   key_file:  /etc/guiltyspark/tls/server.key

database:
  path: "${DATA_DIR}/collector.db"

auth:
  admin_api_key: "${admin_key}"
  # Agents must supply this key in their registration request.
  registration_key: "${reg_key}"

heartbeat:
  timeout:        "90s"
  check_interval: "30s"

alerts:
  dedup_window: "5m"
  # notifications:
  #   webhook:
  #     enabled: true
  #     url:    "https://hooks.example.com/collector"
  #     secret: "changeme"
  #   discord:
  #     enabled: true
  #     webhook_url: "https://discord.com/api/webhooks/<id>/<token>"
  #   slack:
  #     enabled: true
  #     webhook_url: "https://hooks.slack.com/services/..."
  #   custom_webhooks:
  #     - name: "PagerDuty"
  #       enabled: true
  #       url: "https://events.pagerduty.com/v2/enqueue"
  #       headers:
  #         Authorization: "Token token=YOUR_KEY"
  #       body_template: |
  #         routing_key: "YOUR_ROUTING_KEY"
  #         event_action: "trigger"
  #         payload:
  #           summary: "{{ .Message }}"
  #           severity: "{{ lower .Severity }}"
  #           source: "{{ .AgentID }}"

log_level:  "info"
log_format: "json"
log_file:   "${LOG_DIR}/collector.log"

default_rules_file: "${CONFIG_DIR}/default_rules.yaml"
EOF
    chown root:guiltyspark "${CONFIG_DIR}/collector.yaml"
    chmod 640 "${CONFIG_DIR}/collector.yaml"
    success "Wrote ${CONFIG_DIR}/collector.yaml"
  else
    warn "${CONFIG_DIR}/collector.yaml already exists — skipping"
  fi

  # Default rules
  local rules_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/configs/default_rules.yaml"
  if [ ! -f "${CONFIG_DIR}/default_rules.yaml" ]; then
    curl -fsSL -o "${CONFIG_DIR}/default_rules.yaml" "$rules_url" \
      && success "Downloaded default_rules.yaml" \
      || warn "Could not download default_rules.yaml — create it manually"
  fi

  # Systemd
  if ! $NO_INIT; then
    case "$INIT_SYSTEM" in
      systemd)
        local svc_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/deployments/guiltyspark-collector.service"
        curl -fsSL -o "${SYSTEMD_DIR}/guiltyspark-collector.service" "$svc_url"
        systemctl daemon-reload
        systemctl enable --now guiltyspark-collector
        success "guiltyspark-collector enabled and started (systemd)"
        ;;
      openrc)
        local svc_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/deployments/guiltyspark-collector.openrc"
        curl -fsSL -o "${INITD_DIR}/guiltyspark-collector" "$svc_url"
        chmod 755 "${INITD_DIR}/guiltyspark-collector"
        rc-update add guiltyspark-collector default
        rc-service guiltyspark-collector start
        success "guiltyspark-collector enabled and started (OpenRC)"
        ;;
      *)
        warn "No supported init system found; start manually:"
        echo "  ${BIN_DIR}/guiltyspark-collector -config ${CONFIG_DIR}/collector.yaml -rules ${CONFIG_DIR}/default_rules.yaml"
        ;;
    esac
  else
    warn "--no-init set; start manually:"
    echo "  ${BIN_DIR}/guiltyspark-collector -config ${CONFIG_DIR}/collector.yaml -rules ${CONFIG_DIR}/default_rules.yaml"
  fi
}

# ---- Install agent ----------------------------------------------------------
install_agent() {
  info "=== Installing GuiltySpark Agent ==="
  [ -n "$COLLECTOR_URL" ] || error "--collector-url is required when installing the agent"
  resolve_version
  ensure_user
  create_dirs
  download_binary "guiltyspark-agent"

  if [ ! -f "${CONFIG_DIR}/agent.yaml" ]; then
    local agent_key="${AGENT_KEY:-}"

    # Build distro-appropriate log_sources block.
    local log_sources
    case "$PKG_MANAGER" in
      apt)
        log_sources='log_sources:
  - path: "/var/log/syslog"
    tags: ["syslog", "cron", "daemon"]
  - path: "/var/log/auth.log"
    tags: ["syslog", "sshd", "auth", "pam", "sudo"]
  - path: "/var/log/kern.log"
    tags: ["syslog", "kernel"]
  - path: "/var/log/dpkg.log"
    tags: ["syslog", "packages"]'
        ;;
      pacman)
        log_sources='log_sources:
  # Arch Linux: install rsyslog + routing config for these paths.
  - path: "/var/log/syslog"
    tags: ["syslog", "cron", "daemon"]
  - path: "/var/log/auth.log"
    tags: ["syslog", "sshd", "auth", "pam", "sudo"]
  - path: "/var/log/kern.log"
    tags: ["syslog", "kernel"]
  - path: "/var/log/pacman.log"
    tags: ["syslog", "packages"]'
        ;;
      apk)
        log_sources='log_sources:
  # Alpine / BusyBox syslogd: all facilities go to /var/log/messages.
  # The full tag union is required so that tag-scoped rules (sshd, pam,
  # sudo, kernel, cron …) can fire.  Rule patterns only match lines from
  # their respective daemons, so broad tags here cause no false positives.
  #
  # If you have syslog-ng installed and split facilities into separate files,
  # replace this block with per-file entries matching the Debian section.
  - path: "/var/log/messages"
    tags: ["syslog", "sshd", "auth", "pam", "sudo", "kernel", "cron", "daemon", "packages"]
  # With syslog-ng facility routing (optional):
  # - path: "/var/log/auth.log"
  #   tags: ["syslog", "sshd", "auth", "pam", "sudo"]
  # - path: "/var/log/kern.log"
  #   tags: ["syslog", "kernel"]'
        ;;
      dnf|yum)
        log_sources='log_sources:
  - path: "/var/log/messages"
    tags: ["syslog", "kernel", "cron", "daemon"]
  - path: "/var/log/secure"
    tags: ["syslog", "sshd", "auth", "pam", "sudo"]
  - path: "/var/log/audit/audit.log"
    tags: ["auth", "audit"]'
  - path: "/var/log/kern.log"
    tags: ["syslog", "kernel"]'
        ;;
      *)
        log_sources='log_sources:
  # Edit paths and tags to match your distribution.
  # On distros where one file receives all facilities (e.g. Alpine BusyBox
  # syslogd), list the full tag union so all rules can fire.
  - path: "/var/log/syslog"
    tags: ["syslog", "cron", "daemon"]
  - path: "/var/log/auth.log"
    tags: ["syslog", "sshd", "auth", "pam", "sudo"]
  - path: "/var/log/messages"
    tags: ["syslog", "sshd", "auth", "pam", "sudo", "kernel", "cron", "daemon", "packages"]
  - path: "/var/log/secure"
    tags: ["syslog", "sshd", "auth", "pam", "sudo"]'
        ;;
    esac

    cat >"${CONFIG_DIR}/agent.yaml" <<EOF
collector:
  url:     "${COLLECTOR_URL}"
  # ca_cert: /etc/guiltyspark/tls/ca.crt
  # tls_skip_verify: false

auth:
  api_key: "${agent_key}"
  # Must match the collector's auth.registration_key.
  registration_key: "${REG_KEY}"

heartbeat:
  interval: "30s"

${log_sources}

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

state_file: "${DATA_DIR}/agent-state.json"

log_level:  "info"
log_format: "json"
log_file:   "${LOG_DIR}/agent.log"
EOF
    chown root:root "${CONFIG_DIR}/agent.yaml" 2>/dev/null || true
    chmod 640 "${CONFIG_DIR}/agent.yaml"
    success "Wrote ${CONFIG_DIR}/agent.yaml"
  else
    warn "${CONFIG_DIR}/agent.yaml already exists — skipping"
  fi

  # ---- Logrotate -----------------------------------------------------------
  if [ -d /etc/logrotate.d ]; then
    local lr_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/deployments/logrotate.d/guiltyspark-agent"
    curl -fsSL -o /etc/logrotate.d/guiltyspark-agent "$lr_url" \
      && success "Installed logrotate config" \
      || warn "Could not download logrotate config — install manually from deployments/logrotate.d/"
  fi

  # ---- Syslog routing ------------------------------------------------------
  # On Arch (pacman) or Alpine (apk), help the user get plain-text log files.
  case "$PKG_MANAGER" in
    pacman)
      if command -v rsyslogd >/dev/null 2>&1 && [ -d /etc/rsyslog.d ]; then
        local rs_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/deployments/rsyslog.d/90-guiltyspark.conf"
        if [ ! -f /etc/rsyslog.d/90-guiltyspark.conf ]; then
          curl -fsSL -o /etc/rsyslog.d/90-guiltyspark.conf "$rs_url" \
            && success "Installed rsyslog routing config — restarting rsyslog..." \
            && (systemctl restart rsyslog 2>/dev/null || rc-service rsyslog restart 2>/dev/null || true) \
            || warn "Could not install rsyslog config"
        fi
      else
        warn "Arch Linux detected but rsyslog not found."
        warn "Install rsyslog ('pacman -S rsyslog') and drop"
        warn "deployments/rsyslog.d/90-guiltyspark.conf into /etc/rsyslog.d/"
        warn "to route auth/kern/syslog events to flat files the agent can read."
      fi
      ;;
    apk)
      if command -v syslog-ng >/dev/null 2>&1 && [ -d /etc/syslog-ng/conf.d ]; then
        local sng_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/deployments/syslog-ng/90-guiltyspark.conf"
        if [ ! -f /etc/syslog-ng/conf.d/90-guiltyspark.conf ]; then
          curl -fsSL -o /etc/syslog-ng/conf.d/90-guiltyspark.conf "$sng_url" \
            && success "Installed syslog-ng routing config — restarting syslog-ng..." \
            && (rc-service syslog-ng restart 2>/dev/null || systemctl restart syslog-ng 2>/dev/null || true) \
            || warn "Could not install syslog-ng config"
        fi
      else
        warn "Alpine detected without syslog-ng."
        warn "BusyBox syslogd writes to /var/log/messages (already in agent config)."
        warn "For auth.log / kern.log routing install syslog-ng:"
        warn "  apk add syslog-ng && rc-update add syslog-ng boot"
        warn "then drop deployments/syslog-ng/90-guiltyspark.conf into /etc/syslog-ng/conf.d/"
      fi
      ;;
  esac

  if ! $NO_INIT; then
    case "$INIT_SYSTEM" in
      systemd)
        local svc_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/deployments/guiltyspark-agent.service"
        curl -fsSL -o "${SYSTEMD_DIR}/guiltyspark-agent.service" "$svc_url"
        systemctl daemon-reload
        systemctl enable --now guiltyspark-agent
        success "guiltyspark-agent enabled and started (systemd)"
        ;;
      openrc)
        local svc_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/deployments/guiltyspark-agent.openrc"
        curl -fsSL -o "${INITD_DIR}/guiltyspark-agent" "$svc_url"
        chmod 755 "${INITD_DIR}/guiltyspark-agent"
        rc-update add guiltyspark-agent default
        rc-service guiltyspark-agent start
        success "guiltyspark-agent enabled and started (OpenRC)"
        ;;
      *)
        warn "No supported init system found; start manually:"
        echo "  ${BIN_DIR}/guiltyspark-agent -config ${CONFIG_DIR}/agent.yaml"
        ;;
    esac
  else
    warn "--no-init set; start manually:"
    echo "  ${BIN_DIR}/guiltyspark-agent -config ${CONFIG_DIR}/agent.yaml"
  fi
}

# ---- Service stop/start helpers --------------------------------------------
# Call with the bare service name, e.g. "guiltyspark-collector"
svc_stop() {
  local svc="$1"
  case "$INIT_SYSTEM" in
    systemd) systemctl stop "$svc" 2>/dev/null || true ;;
    openrc)  rc-service "$svc" stop 2>/dev/null || true ;;
  esac
}
svc_start() {
  local svc="$1"
  case "$INIT_SYSTEM" in
    systemd) systemctl start "$svc" ;;
    openrc)  rc-service "$svc" start ;;
    *) warn "No init system detected — start manually: ${BIN_DIR}/${svc}" ;;
  esac
}
svc_disable() {
  local svc="$1"
  case "$INIT_SYSTEM" in
    systemd)
      systemctl disable "$svc" 2>/dev/null || true
      rm -f "${SYSTEMD_DIR}/${svc}.service"
      systemctl daemon-reload
      ;;
    openrc)
      rc-update del "$svc" default 2>/dev/null || true
      rm -f "${INITD_DIR}/${svc}"
      ;;
  esac
}
svc_update_unit() {
  # Download the latest service unit and reload, without starting.
  local svc="$1"
  case "$INIT_SYSTEM" in
    systemd)
      curl -fsSL -o "${SYSTEMD_DIR}/${svc}.service" \
        "https://raw.githubusercontent.com/${GITHUB_REPO}/main/deployments/${svc}.service"
      systemctl daemon-reload
      ;;
    openrc)
      curl -fsSL -o "${INITD_DIR}/${svc}" \
        "https://raw.githubusercontent.com/${GITHUB_REPO}/main/deployments/${svc}.openrc"
      chmod 755 "${INITD_DIR}/${svc}"
      ;;
  esac
}

# ---- Upgrade collector ------------------------------------------------------
upgrade_collector() {
  info "=== Upgrading GuiltySpark Collector ==="
  resolve_version
  info "Stopping collector..."
  svc_stop "guiltyspark-collector"
  download_binary "guiltyspark-collector"
  svc_update_unit "guiltyspark-collector"
  info "Starting collector..."
  svc_start "guiltyspark-collector"
  success "Collector upgraded to ${VERSION}"
}

# ---- Upgrade agent ----------------------------------------------------------
upgrade_agent() {
  info "=== Upgrading GuiltySpark Agent ==="
  resolve_version
  info "Stopping agent..."
  svc_stop "guiltyspark-agent"
  download_binary "guiltyspark-agent"
  svc_update_unit "guiltyspark-agent"
  info "Starting agent..."
  svc_start "guiltyspark-agent"
  success "Agent upgraded to ${VERSION}"
}

# ---- Uninstall collector ----------------------------------------------------
uninstall_collector() {
  info "=== Uninstalling GuiltySpark Collector ==="
  svc_stop    "guiltyspark-collector"
  svc_disable "guiltyspark-collector"
  rm -f "${BIN_DIR}/guiltyspark-collector"
  success "Removed binary and service unit"
  if $PURGE; then
    rm -f "${CONFIG_DIR}/collector.yaml" "${CONFIG_DIR}/default_rules.yaml"
    rm -rf "${DATA_DIR}/collector.db" "${DATA_DIR}/collector.db-shm" "${DATA_DIR}/collector.db-wal"
    success "Purged collector config and database"
    warn "Data directory ${DATA_DIR} left in place (may be shared with agent)"
  else
    warn "Config and data left in place. Re-run with --purge to remove:"
    warn "  ${CONFIG_DIR}/collector.yaml"
    warn "  ${DATA_DIR}/collector.db"
  fi
}

# ---- Uninstall agent --------------------------------------------------------
uninstall_agent() {
  info "=== Uninstalling GuiltySpark Agent ==="
  svc_stop    "guiltyspark-agent"
  svc_disable "guiltyspark-agent"
  rm -f "${BIN_DIR}/guiltyspark-agent"
  rm -f /etc/logrotate.d/guiltyspark-agent 2>/dev/null || true
  success "Removed binary, service unit, and logrotate config"
  if $PURGE; then
    rm -f "${CONFIG_DIR}/agent.yaml"
    rm -f "${DATA_DIR}/agent-state.json"
    success "Purged agent config and state file"
    warn "Data directory ${DATA_DIR} left in place (may be shared with collector)"
  else
    warn "Config and state left in place. Re-run with --purge to remove:"
    warn "  ${CONFIG_DIR}/agent.yaml"
    warn "  ${DATA_DIR}/agent-state.json"
  fi
}

# ---- Main -------------------------------------------------------------------
case "$MODE" in
  install)
    $INSTALL_COLLECTOR && install_collector
    $INSTALL_AGENT     && install_agent
    echo
    success "GuiltySpark installation complete!"
    echo
    echo "  Config dir : ${CONFIG_DIR}"
    echo "  Data dir   : ${DATA_DIR}"
    echo "  Log dir    : ${LOG_DIR}"
    if $INSTALL_COLLECTOR; then
      echo
      echo "  Collector health: curl http://${COLLECTOR_HOST}:${COLLECTOR_PORT}/api/v1/health"
    fi
    ;;
  upgrade)
    $INSTALL_COLLECTOR && upgrade_collector
    $INSTALL_AGENT     && upgrade_agent
    echo
    success "Upgrade complete!"
    ;;
  uninstall)
    # Uninstall agent first so the collector is the last thing removed
    $INSTALL_AGENT     && uninstall_agent
    $INSTALL_COLLECTOR && uninstall_collector
    # If both were removed with --purge, try to clean up shared dirs if empty
    if $PURGE && $INSTALL_COLLECTOR && $INSTALL_AGENT; then
      rmdir "${DATA_DIR}" 2>/dev/null && success "Removed ${DATA_DIR}" || true
      rmdir "${LOG_DIR}"  2>/dev/null && success "Removed ${LOG_DIR}"  || true
      rmdir "${CONFIG_DIR}" 2>/dev/null && success "Removed ${CONFIG_DIR}" || true
      # Don't remove the system user — other things may depend on it
      warn "System user 'guiltyspark' left in place (remove manually if desired)"
    fi
    echo
    success "Uninstall complete!"
    ;;
esac