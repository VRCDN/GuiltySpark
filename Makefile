.PHONY: all build build-collector build-agent test test-coverage lint vet fmt clean cert \
        docker docker-alpine docker-compose-up docker-compose-down \
        install-agent install-collector uninstall-agent uninstall-collector \
        install-systemd-agent install-systemd-collector \
        install-openrc-agent install-openrc-collector \
        install-deps release deps help \
        _setup-agent-dirs _setup-collector-dirs \
        _install-agent-config _install-collector-config \
        _start-agent-service _start-collector-service

BINARY_COLLECTOR := bin/guiltyspark-collector
BINARY_AGENT     := bin/guiltyspark-agent
MODULE           := github.com/VRCDN/guiltyspark
VERSION          ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS          := -ldflags "-s -w -X $(MODULE)/internal/common/models.Version=$(VERSION)"
GO               := go
GOFLAGS          :=
# CGO_ENABLED=0 ensures fully static binaries with no glibc dependency.
# This is required for musl/Alpine targets and is safe everywhere because
# the project uses modernc/sqlite (pure Go) — no CGO anywhere.
CGO_ENABLED      ?= 0

# ---- Native installation paths (override on the command line if needed) ----
PREFIX        ?= /usr/local
BIN_DIR       ?= $(PREFIX)/bin
CONFIG_DIR    ?= /etc/guiltyspark
DATA_DIR      ?= /var/lib/guiltyspark
LOG_DIR       ?= /var/log/guiltyspark
LOGROTATE_DIR ?= /etc/logrotate.d
INITD_DIR     ?= /etc/init.d
SYSTEMD_DIR   ?= /etc/systemd/system
# INIT: which init system to register the service with.
#   auto     — detect systemd first, then OpenRC, then warn
#   systemd  — always use systemd
#   openrc   — always use OpenRC
#   none     — install binary + config only; do not register a service
INIT          ?= auto
# COLLECTOR_URL: written into the generated agent.yaml (can be overridden)
COLLECTOR_URL ?= https://collector.example.com:8080

# Resolve INIT=auto at make-time so sub-make calls share the same value.
_DETECTED_INIT := $(shell \
  if [ -d /run/systemd/system ] || systemctl --version >/dev/null 2>&1; then echo systemd; \
  elif command -v rc-service >/dev/null 2>&1; then echo openrc; \
  else echo none; fi)
_RESOLVED_INIT := $(if $(filter auto,$(INIT)),$(_DETECTED_INIT),$(INIT))

all: build

## deps: download and tidy dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

## build: build both binaries
build: deps
	@mkdir -p bin
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath $(LDFLAGS) -o $(BINARY_COLLECTOR) ./cmd/collector
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath $(LDFLAGS) -o $(BINARY_AGENT)     ./cmd/agent
	@echo "Build complete: $(BINARY_COLLECTOR) $(BINARY_AGENT)"

## build-collector: build collector only
build-collector:
	@mkdir -p bin
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath $(LDFLAGS) -o $(BINARY_COLLECTOR) ./cmd/collector

## build-agent: build agent only
build-agent:
	@mkdir -p bin
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath $(LDFLAGS) -o $(BINARY_AGENT) ./cmd/agent

## test: run tests
test:
	$(GO) test -v -race ./...

## test-coverage: run tests with coverage
test-coverage:
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: run linters (requires golangci-lint)
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed. Run: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin"; exit 1; }
	golangci-lint run ./...

## vet: run go vet
vet:
	$(GO) vet ./...

## fmt: format code
fmt:
	$(GO) fmt ./...

## clean: remove build artifacts
clean:
	rm -rf bin/ coverage.out coverage.html

## cert: generate self-signed TLS certificate for development
cert:
	@mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -keyout certs/collector.key -out certs/collector.crt \
		-days 365 -nodes -subj "/CN=guiltyspark-collector" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
	@echo "Generated: certs/collector.crt  certs/collector.key"

## docker: build Debian-slim Docker images for the collector and agent
docker:
	docker build -t guiltyspark-collector:$(VERSION) -f deployments/Dockerfile.collector .
	docker build -t guiltyspark-agent:$(VERSION)     -f deployments/Dockerfile.agent     .

## docker-alpine: build Alpine-based Docker images (smaller footprint, musl libc)
docker-alpine:
	docker build --build-arg VERSION=$(VERSION) \
		-t guiltyspark-collector:$(VERSION)-alpine \
		-f deployments/Dockerfile.collector.alpine .
	docker build --build-arg VERSION=$(VERSION) \
		-t guiltyspark-agent:$(VERSION)-alpine \
		-f deployments/Dockerfile.agent.alpine .

## docker-compose-up: start collector via docker compose
docker-compose-up:
	docker compose -f deployments/docker-compose.yml up -d

## docker-compose-down: stop collector
docker-compose-down:
	docker compose -f deployments/docker-compose.yml down

## install-agent: build and natively install the agent on this host
## Creates dirs, writes config (if absent), installs logrotate, registers service.
## Options (override on command line):
##   INIT=auto|systemd|openrc|none   which init system to use  (default: auto)
##   COLLECTOR_URL=https://...        written into the agent config
##   CONFIG_DIR, DATA_DIR, LOG_DIR    installation paths
install-agent: build-agent _setup-agent-dirs _install-agent-config
	@echo "  ... installing agent binary"
	install -m 0755 $(BINARY_AGENT) $(BIN_DIR)/guiltyspark-agent
	@if [ -d $(LOGROTATE_DIR) ]; then \
		install -m 0644 deployments/logrotate.d/guiltyspark-agent $(LOGROTATE_DIR)/guiltyspark-agent; \
		echo "  [ok] logrotate config -> $(LOGROTATE_DIR)/guiltyspark-agent"; \
	fi
	@$(MAKE) --no-print-directory _start-agent-service
	@echo ""
	@echo "GuiltySpark Agent installed."
	@echo "  binary : $(BIN_DIR)/guiltyspark-agent"
	@echo "  config : $(CONFIG_DIR)/agent.yaml"
	@echo "  state  : $(DATA_DIR)/agent-state.json"
	@echo "  logs   : $(LOG_DIR)/"

_setup-agent-dirs:
	@echo "  ... creating directories"
	install -d -m 0755 $(BIN_DIR)
	install -d -m 0750 $(CONFIG_DIR) $(DATA_DIR) $(LOG_DIR)

_install-agent-config:
	@if [ ! -f $(CONFIG_DIR)/agent.yaml ]; then \
		echo "  ... writing $(CONFIG_DIR)/agent.yaml"; \
		install -m 0640 configs/agent.yaml $(CONFIG_DIR)/agent.yaml; \
		sed -i 's|url: "https://collector.example.com:8443"|url: "$(COLLECTOR_URL)"|' \
			$(CONFIG_DIR)/agent.yaml; \
		echo "  [ok] $(CONFIG_DIR)/agent.yaml"; \
	else \
		echo "  [--] $(CONFIG_DIR)/agent.yaml already exists, skipping"; \
	fi

_start-agent-service:
	@case "$(_RESOLVED_INIT)" in \
	  systemd) \
	    echo "  ... registering with systemd"; \
	    install -m 0644 deployments/guiltyspark-agent.service $(SYSTEMD_DIR)/; \
	    systemctl daemon-reload; \
	    systemctl enable --now guiltyspark-agent; \
	    echo "  [ok] guiltyspark-agent enabled and started (systemd)"; \
	    ;; \
	  openrc) \
	    echo "  ... registering with OpenRC"; \
	    install -m 0755 deployments/guiltyspark-agent.openrc $(INITD_DIR)/guiltyspark-agent; \
	    rc-update add guiltyspark-agent default; \
	    rc-service guiltyspark-agent start; \
	    echo "  [ok] guiltyspark-agent enabled and started (OpenRC)"; \
	    ;; \
	  *) \
	    echo "  [--] No init system registered (INIT=none or undetected)."; \
	    echo "       Start manually: $(BIN_DIR)/guiltyspark-agent -config $(CONFIG_DIR)/agent.yaml"; \
	    ;; \
	esac

## uninstall-agent: stop, disable and remove the agent binary and service unit
## Config and data in CONFIG_DIR / DATA_DIR are preserved.
uninstall-agent:
	@echo "Stopping and disabling guiltyspark-agent..."
	@-systemctl stop guiltyspark-agent 2>/dev/null || true
	@-systemctl disable guiltyspark-agent 2>/dev/null || true
	@-rm -f $(SYSTEMD_DIR)/guiltyspark-agent.service
	@-systemctl daemon-reload 2>/dev/null || true
	@-rc-service guiltyspark-agent stop 2>/dev/null || true
	@-rc-update del guiltyspark-agent default 2>/dev/null || true
	@-rm -f $(INITD_DIR)/guiltyspark-agent
	rm -f $(BIN_DIR)/guiltyspark-agent
	@-rm -f $(LOGROTATE_DIR)/guiltyspark-agent
	@echo "Agent uninstalled. Config/data preserved:"
	@echo "  $(CONFIG_DIR)/agent.yaml"
	@echo "  $(DATA_DIR)/"
	@echo "Remove manually if no longer needed."

## install-collector: build and natively install the collector on this host
## Creates guiltyspark system user, dirs, writes config, installs logrotate.
## Options: INIT=auto|systemd|openrc|none   CONFIG_DIR  DATA_DIR  LOG_DIR
install-collector: build-collector _setup-collector-dirs _install-collector-config
	@echo "  ... installing collector binary"
	install -m 0755 $(BINARY_COLLECTOR) $(BIN_DIR)/guiltyspark-collector
	@if [ -d $(LOGROTATE_DIR) ]; then \
		install -m 0644 deployments/logrotate.d/guiltyspark-collector $(LOGROTATE_DIR)/guiltyspark-collector; \
		echo "  [ok] logrotate config -> $(LOGROTATE_DIR)/guiltyspark-collector"; \
	fi
	@$(MAKE) --no-print-directory _start-collector-service
	@echo ""
	@echo "GuiltySpark Collector installed."
	@echo "  binary : $(BIN_DIR)/guiltyspark-collector"
	@echo "  config : $(CONFIG_DIR)/collector.yaml  <-- set server.admin_api_key"
	@echo "  db     : $(DATA_DIR)/collector.db"
	@echo "  health : curl http://localhost:8080/health"

_setup-collector-dirs:
	@echo "  ... creating user and directories"
	@id guiltyspark >/dev/null 2>&1 \
	  || useradd -r -m -d $(DATA_DIR) -s /sbin/nologin guiltyspark 2>/dev/null \
	  || adduser -S -h $(DATA_DIR) -s /sbin/nologin guiltyspark 2>/dev/null \
	  || true
	install -d -m 0755 $(BIN_DIR)
	install -d -m 0750 $(CONFIG_DIR) $(LOG_DIR)
	@install -d -m 0750 $(DATA_DIR) && \
	  chown guiltyspark:guiltyspark $(DATA_DIR) 2>/dev/null || \
	  chown guiltyspark $(DATA_DIR) 2>/dev/null || true
	@chown guiltyspark:guiltyspark $(LOG_DIR) 2>/dev/null || \
	  chown guiltyspark $(LOG_DIR) 2>/dev/null || true

_install-collector-config:
	@if [ ! -f $(CONFIG_DIR)/collector.yaml ]; then \
		echo "  ... writing $(CONFIG_DIR)/collector.yaml"; \
		install -m 0640 configs/collector.yaml $(CONFIG_DIR)/collector.yaml; \
		chown root:guiltyspark $(CONFIG_DIR)/collector.yaml 2>/dev/null || true; \
		echo "  [ok] $(CONFIG_DIR)/collector.yaml"; \
		echo "  [!!] Set server.admin_api_key before starting the collector"; \
	else \
		echo "  [--] $(CONFIG_DIR)/collector.yaml already exists, skipping"; \
	fi
	@if [ ! -f $(CONFIG_DIR)/default_rules.yaml ]; then \
		install -m 0644 configs/default_rules.yaml $(CONFIG_DIR)/default_rules.yaml; \
		echo "  [ok] $(CONFIG_DIR)/default_rules.yaml"; \
	fi

_start-collector-service:
	@case "$(_RESOLVED_INIT)" in \
	  systemd) \
	    echo "  ... registering with systemd"; \
	    install -m 0644 deployments/guiltyspark-collector.service $(SYSTEMD_DIR)/; \
	    systemctl daemon-reload; \
	    systemctl enable --now guiltyspark-collector; \
	    echo "  [ok] guiltyspark-collector enabled and started (systemd)"; \
	    ;; \
	  openrc) \
	    echo "  ... registering with OpenRC"; \
	    install -m 0755 deployments/guiltyspark-collector.openrc $(INITD_DIR)/guiltyspark-collector; \
	    rc-update add guiltyspark-collector default; \
	    rc-service guiltyspark-collector start; \
	    echo "  [ok] guiltyspark-collector enabled and started (OpenRC)"; \
	    ;; \
	  *) \
	    echo "  [--] No init system registered (INIT=none or undetected)."; \
	    echo "       Start manually: $(BIN_DIR)/guiltyspark-collector -config $(CONFIG_DIR)/collector.yaml -rules $(CONFIG_DIR)/default_rules.yaml"; \
	    ;; \
	esac

## uninstall-collector: stop, disable and remove the collector binary and service unit
uninstall-collector:
	@echo "Stopping and disabling guiltyspark-collector..."
	@-systemctl stop guiltyspark-collector 2>/dev/null || true
	@-systemctl disable guiltyspark-collector 2>/dev/null || true
	@-rm -f $(SYSTEMD_DIR)/guiltyspark-collector.service
	@-systemctl daemon-reload 2>/dev/null || true
	@-rc-service guiltyspark-collector stop 2>/dev/null || true
	@-rc-update del guiltyspark-collector default 2>/dev/null || true
	@-rm -f $(INITD_DIR)/guiltyspark-collector
	rm -f $(BIN_DIR)/guiltyspark-collector
	@-rm -f $(LOGROTATE_DIR)/guiltyspark-collector
	@echo "Collector uninstalled. Config/data preserved:"
	@echo "  $(CONFIG_DIR)/collector.yaml"
	@echo "  $(DATA_DIR)/"
	@echo "Remove manually if no longer needed."

## install-systemd-agent: alias for 'make install-agent INIT=systemd'
install-systemd-agent:
	$(MAKE) install-agent INIT=systemd

## install-systemd-collector: alias for 'make install-collector INIT=systemd'
install-systemd-collector:
	$(MAKE) install-collector INIT=systemd

## install-openrc-agent: alias for 'make install-agent INIT=openrc'
install-openrc-agent:
	$(MAKE) install-agent INIT=openrc

## install-openrc-collector: alias for 'make install-collector INIT=openrc'
install-openrc-collector:
	$(MAKE) install-collector INIT=openrc

## install-deps: install build-time dependencies (Go toolchain must already be present)
## Detects the host package manager and installs: git, make, openssl
install-deps:
	@if command -v apt-get >/dev/null 2>&1; then \
		apt-get update -qq && apt-get install -y git make openssl; \
	elif command -v pacman >/dev/null 2>&1; then \
		pacman -Sy --noconfirm git make openssl; \
	elif command -v apk >/dev/null 2>&1; then \
		apk add --no-cache git make openssl; \
	elif command -v dnf >/dev/null 2>&1; then \
		dnf install -y git make openssl; \
	elif command -v yum >/dev/null 2>&1; then \
		yum install -y git make openssl; \
	else \
		echo "No supported package manager found. Install git, make, openssl manually."; exit 1; \
	fi

## release: build release binaries for linux/amd64 and linux/arm64
## CGO_ENABLED=0 + -trimpath produces fully static binaries that run on
## both glibc (Debian/Ubuntu/RHEL/Arch) and musl (Alpine) without changes.
## The output names match what scripts/install.sh downloads from GitHub Releases:
##   guiltyspark-{collector,agent}-linux-{amd64,arm64}  (bare binaries, no extension)
release: deps
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath $(LDFLAGS) -o dist/guiltyspark-collector-linux-amd64 ./cmd/collector
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath $(LDFLAGS) -o dist/guiltyspark-agent-linux-amd64     ./cmd/agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath $(LDFLAGS) -o dist/guiltyspark-collector-linux-arm64 ./cmd/collector
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath $(LDFLAGS) -o dist/guiltyspark-agent-linux-arm64     ./cmd/agent
	@echo "Release binaries in dist/"
	@echo ""
	@echo "Upload these as GitHub Release assets for tag $(VERSION):"
	@echo "  gh release create $(VERSION) dist/* --title $(VERSION) --notes ''"
	@echo "or via the GitHub web UI: https://github.com/VRCDN/GuiltySpark/releases/new"

## help: show this help
help:
	@echo "Available targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
