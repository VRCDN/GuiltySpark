#!/usr/bin/env bash
# GuiltySpark install script
# Installs guiltyspark-collector and/or guiltyspark-agent on a Linux host.
# Supports: Debian/Ubuntu (apt), Arch Linux (pacman), Alpine Linux (apk),
#           RHEL/CentOS/Fedora (dnf/yum).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/guiltyspark/guiltyspark/main/scripts/install.sh | \
#       bash -s -- [--collector] [--agent] [--version v1.0.0]
#
# Options:
#   --collector        Install the collector (default: false)
#   --agent            Install the agent     (default: false)
#   --version VER      Binary release version to install (default: latest)
#   --collector-url U  Collector URL for the agent config
#   --admin-key KEY    Admin API key (collector install)
#   --agent-key KEY    Pre-shared agent API key (optional)
#   --config-dir DIR   Config directory (default: /etc/guiltyspark)
#   --data-dir DIR     Data/state directory (default: /var/lib/guiltyspark)
#   --no-init          Skip init system (systemd/OpenRC) unit installation
#   --help             Show this help

set -euo pipefail

# ---- Defaults ---------------------------------------------------------------
INSTALL_COLLECTOR=false
INSTALL_AGENT=false
VERSION="latest"
COLLECTOR_URL=""
ADMIN_KEY=""
AGENT_KEY=""
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

# ---- Argument parsing -------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --collector)     INSTALL_COLLECTOR=true; shift ;;
    --agent)         INSTALL_AGENT=true; shift ;;
    --version)       VERSION="$2"; shift 2 ;;
    --collector-url) COLLECTOR_URL="$2"; shift 2 ;;
    --admin-key)     ADMIN_KEY="$2"; shift 2 ;;
    --agent-key)     AGENT_KEY="$2"; shift 2 ;;
    --config-dir)    CONFIG_DIR="$2"; shift 2 ;;
    --data-dir)      DATA_DIR="$2"; shift 2 ;;
    --no-init)       NO_INIT=true; shift ;;
    --no-systemd)    NO_INIT=true; shift ;; # legacy alias
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
[[ "$(uname -s)" == "Linux" ]] || error "Only Linux is supported"
[[ $EUID -eq 0 ]]              || error "Please run as root (sudo)"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  *)        error "Unsupported architecture: $ARCH" ;;
esac

# Detect package manager
if command -v apt-get &>/dev/null; then
  PKG_MANAGER="apt"
elif command -v pacman &>/dev/null; then
  PKG_MANAGER="pacman"
elif command -v apk &>/dev/null; then
  PKG_MANAGER="apk"
elif command -v dnf &>/dev/null; then
  PKG_MANAGER="dnf"
elif command -v yum &>/dev/null; then
  PKG_MANAGER="yum"
else
  PKG_MANAGER="none"
fi
info "Detected package manager: ${PKG_MANAGER}"

# Detect init system
if [[ -d /run/systemd/system ]] || systemctl --version &>/dev/null 2>&1; then
  INIT_SYSTEM="systemd"
elif command -v rc-service &>/dev/null; then
  INIT_SYSTEM="openrc"
else
  INIT_SYSTEM="none"
fi
info "Detected init system: ${INIT_SYSTEM}"

# Ensure curl is present
if ! command -v curl &>/dev/null; then
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
  if [[ "$VERSION" == "latest" ]]; then
    info "Resolving latest release..."
    VERSION="$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
      | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')"
    [[ -n "$VERSION" ]] || error "Could not determine latest version"
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
  if id guiltyspark &>/dev/null; then
    return 0
  fi
  # Alpine uses adduser with different flags (BusyBox)
  if [[ "$PKG_MANAGER" == "apk" ]]; then
    adduser -S -u 990 -h "${DATA_DIR}" -s /sbin/nologin guiltyspark 2>/dev/null || \
    adduser -S -h "${DATA_DIR}" -s /sbin/nologin guiltyspark
  else
    useradd -r -u 990 -m -d "${DATA_DIR}" -s /sbin/nologin guiltyspark 2>/dev/null || \
    useradd -r -m -d "${DATA_DIR}" -s /sbin/nologin guiltyspark
  fi
  success "Created system user 'guiltyspark'"
}

# ---- Create directories -----------------------------------------------------
create_dirs() {
  mkdir -p "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}"
  chown guiltyspark:guiltyspark "${DATA_DIR}" "${LOG_DIR}"
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
  if [[ ! -f "${CONFIG_DIR}/collector.yaml" ]]; then
    local admin_key="${ADMIN_KEY:-$(gen_key)}"
    info "Generated admin key: ${admin_key}"
    info "(save this — it is only shown once)"
    cat >"${CONFIG_DIR}/collector.yaml" <<EOF
server:
  listen_addr: "0.0.0.0:8080"
  admin_api_key: "${admin_key}"
  # tls:
  #   cert_file: /etc/guiltyspark/tls/server.crt
  #   key_file:  /etc/guiltyspark/tls/server.key

storage:
  sqlite_path: "${DATA_DIR}/collector.db"

heartbeat:
  timeout:        "90s"
  check_interval: "30s"

alerts:
  dedup_window: "5m"
  # webhook:
  #   url:    "https://hooks.example.com/collector"
  #   secret: "changeme"

rules:
  seed_if_empty: true
EOF
    chown root:guiltyspark "${CONFIG_DIR}/collector.yaml"
    chmod 640 "${CONFIG_DIR}/collector.yaml"
    success "Wrote ${CONFIG_DIR}/collector.yaml"
  else
    warn "${CONFIG_DIR}/collector.yaml already exists — skipping"
  fi

  # Default rules
  local rules_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/configs/default_rules.yaml"
  if [[ ! -f "${CONFIG_DIR}/default_rules.yaml" ]]; then
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
  [[ -n "$COLLECTOR_URL" ]] || error "--collector-url is required when installing the agent"
  resolve_version
  ensure_user
  create_dirs
  download_binary "guiltyspark-agent"

  if [[ ! -f "${CONFIG_DIR}/agent.yaml" ]]; then
    local agent_key="${AGENT_KEY:-}"

    # Build distro-appropriate log_sources block.
    local log_sources
    case "$PKG_MANAGER" in
      apt)
        log_sources='log_sources:
  - path: "/var/log/syslog"
    tags: ["syslog"]
  - path: "/var/log/auth.log"
    tags: ["syslog", "sshd", "pam", "auth"]
  - path: "/var/log/kern.log"
    tags: ["syslog", "kernel"]
  - path: "/var/log/dpkg.log"
    tags: ["syslog", "packages"]'
        ;;
      pacman)
        log_sources='log_sources:
  # Arch Linux: install rsyslog + the routing config at
  # /etc/rsyslog.d/90-guiltyspark.conf to populate these files.
  - path: "/var/log/syslog"
    tags: ["syslog"]
  - path: "/var/log/auth.log"
    tags: ["syslog", "sshd", "pam", "auth"]
  - path: "/var/log/kern.log"
    tags: ["syslog", "kernel"]
  - path: "/var/log/pacman.log"
    tags: ["syslog", "packages"]'
        ;;
      apk)
        log_sources='log_sources:
  # Alpine: BusyBox syslogd writes to /var/log/messages by default.
  # Install syslog-ng + /etc/syslog-ng/conf.d/90-guiltyspark.conf for
  # separate auth.log and kern.log routing.
  - path: "/var/log/messages"
    tags: ["syslog"]
  - path: "/var/log/auth.log"
    tags: ["syslog", "sshd", "pam", "auth"]
  - path: "/var/log/kern.log"
    tags: ["syslog", "kernel"]'
        ;;
      dnf|yum)
        log_sources='log_sources:
  - path: "/var/log/messages"
    tags: ["syslog"]
  - path: "/var/log/secure"
    tags: ["syslog", "sshd", "pam", "auth"]
  - path: "/var/log/audit/audit.log"
    tags: ["syslog", "auth", "audit"]
  - path: "/var/log/kern.log"
    tags: ["syslog", "kernel"]'
        ;;
      *)
        log_sources='log_sources:
  # Edit paths to match your distribution'"'"'s syslog output.
  - path: "/var/log/syslog"
    tags: ["syslog"]
  - path: "/var/log/auth.log"
    tags: ["syslog", "sshd", "pam", "auth"]
  - path: "/var/log/messages"
    tags: ["syslog"]
  - path: "/var/log/secure"
    tags: ["syslog", "sshd", "pam", "auth"]'
        ;;
    esac

    cat >"${CONFIG_DIR}/agent.yaml" <<EOF
collector:
  url:     "${COLLECTOR_URL}"
  api_key: "${agent_key}"
  # ca_cert: /etc/guiltyspark/tls/ca.crt
  # tls_skip_verify: false

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
EOF
    chown root:root "${CONFIG_DIR}/agent.yaml" 2>/dev/null || true
    chmod 640 "${CONFIG_DIR}/agent.yaml"
    success "Wrote ${CONFIG_DIR}/agent.yaml"
  else
    warn "${CONFIG_DIR}/agent.yaml already exists — skipping"
  fi

  # ---- Logrotate -----------------------------------------------------------
  if [[ -d /etc/logrotate.d ]]; then
    local lr_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/deployments/logrotate.d/guiltyspark-agent"
    curl -fsSL -o /etc/logrotate.d/guiltyspark-agent "$lr_url" \
      && success "Installed logrotate config" \
      || warn "Could not download logrotate config — install manually from deployments/logrotate.d/"
  fi

  # ---- Syslog routing ------------------------------------------------------
  # On Arch (pacman) or Alpine (apk), help the user get plain-text log files.
  case "$PKG_MANAGER" in
    pacman)
      if command -v rsyslogd &>/dev/null && [[ -d /etc/rsyslog.d ]]; then
        local rs_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/deployments/rsyslog.d/90-guiltyspark.conf"
        if [[ ! -f /etc/rsyslog.d/90-guiltyspark.conf ]]; then
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
      if command -v syslog-ng &>/dev/null && [[ -d /etc/syslog-ng/conf.d ]]; then
        local sng_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/deployments/syslog-ng/90-guiltyspark.conf"
        if [[ ! -f /etc/syslog-ng/conf.d/90-guiltyspark.conf ]]; then
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

# ---- Main -------------------------------------------------------------------
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
  echo "  Collector health: curl http://localhost:8080/health"
fi
