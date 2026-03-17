// Package api is the HTTP server that agents and admins talk to.
package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/VRCDN/guiltyspark/internal/collector/alerts"
	"github.com/VRCDN/guiltyspark/internal/collector/heartbeat"
	"github.com/VRCDN/guiltyspark/internal/collector/inventory"
	"github.com/VRCDN/guiltyspark/internal/collector/rules"
	"github.com/VRCDN/guiltyspark/internal/collector/storage"
	"github.com/VRCDN/guiltyspark/internal/common/models"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Config is the server's listen address and TLS settings.
type Config struct {
	Host            string
	Port            int
	TLSEnabled      bool
	TLSCertFile     string
	TLSKeyFile      string
	AdminAPIKey     string
	RegistrationKey string
}

// Server is the collector's HTTP API — handles both agent comms and the admin endpoints.
type Server struct {
	cfg          Config
	store        storage.Storage
	rulesMgr     *rules.Manager
	alertsMgr    *alerts.Manager
	heartbeatMon *heartbeat.Monitor
	inventoryStr *inventory.Store
	logger       *slog.Logger
	router       *mux.Router
	httpServer   *http.Server

	// per-IP request counts for rate limiting
	rateMu     sync.Mutex
	rateCounts map[string]*rateEntry
}

type rateEntry struct {
	count   int
	resetAt time.Time
}

// New wires up the server and builds the router.
func New(
	cfg Config,
	store storage.Storage,
	rulesMgr *rules.Manager,
	alertsMgr *alerts.Manager,
	heartbeatMon *heartbeat.Monitor,
	inventoryStr *inventory.Store,
	logger *slog.Logger,
) *Server {
	s := &Server{
		cfg:          cfg,
		store:        store,
		rulesMgr:     rulesMgr,
		alertsMgr:    alertsMgr,
		heartbeatMon: heartbeatMon,
		inventoryStr: inventoryStr,
		logger:       logger,
		rateCounts:   make(map[string]*rateEntry),
	}
	s.router = s.buildRouter()
	return s
}

// Start listens and serves. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	var ln net.Listener
	var err error

	if s.cfg.TLSEnabled {
		tlsCfg := &tls.Config{
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("load TLS cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
		ln, err = tls.Listen("tcp", addr, tlsCfg)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	scheme := "http"
	if s.cfg.TLSEnabled {
		scheme = "https"
	}
	s.logger.Info("collector API listening", "addr", fmt.Sprintf("%s://%s", scheme, addr))

	// wait for the shutdown signal and give in-flight requests 15s to finish
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutCtx)
	}()

	if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Router

func (s *Server) buildRouter() *mux.Router {
	r := mux.NewRouter()
	r.Use(s.middlewareLogging)
	r.Use(s.middlewareRecover)

	// Health check — no auth
	r.HandleFunc("/api/v1/health", s.handleHealth).Methods(http.MethodGet)

	// agent registration — unauthenticated, it's how they get a key in the first place
	r.HandleFunc("/api/v1/agents/register", s.handleAgentRegister).Methods(http.MethodPost)

	// Agent-authenticated routes
	agent := r.PathPrefix("/api/v1/agents/{id}").Subrouter()
	agent.Use(s.middlewareAgentAuth)
	agent.HandleFunc("/heartbeat", s.handleHeartbeat).Methods(http.MethodPost)
	agent.HandleFunc("/rules", s.handleGetRules).Methods(http.MethodGet)
	agent.HandleFunc("/events", s.handleLogEvents).Methods(http.MethodPost)
	agent.HandleFunc("/inventory", s.handleInventory).Methods(http.MethodPost)
	agent.HandleFunc("/audit-events", s.handleAuditEvents).Methods(http.MethodPost)

	// admin-authenticated routes
	admin := r.NewRoute().Subrouter()
	admin.Use(s.middlewareAdminAuth)
	admin.Use(s.middlewareRateLimit)

	// agent CRUD
	admin.HandleFunc("/api/v1/agents", s.handleListAgents).Methods(http.MethodGet)
	admin.HandleFunc("/api/v1/agents/{id}", s.handleGetAgent).Methods(http.MethodGet)
	admin.HandleFunc("/api/v1/agents/{id}", s.handleDeleteAgent).Methods(http.MethodDelete)

	// Rules
	admin.HandleFunc("/api/v1/rules", s.handleListRules).Methods(http.MethodGet)
	admin.HandleFunc("/api/v1/rules", s.handleCreateRule).Methods(http.MethodPost)
	admin.HandleFunc("/api/v1/rules/{id}", s.handleGetRule).Methods(http.MethodGet)
	admin.HandleFunc("/api/v1/rules/{id}", s.handleUpdateRule).Methods(http.MethodPut)
	admin.HandleFunc("/api/v1/rules/{id}", s.handleDeleteRule).Methods(http.MethodDelete)

	// Alerts
	admin.HandleFunc("/api/v1/alerts", s.handleListAlerts).Methods(http.MethodGet)
	admin.HandleFunc("/api/v1/alerts/{id}", s.handleGetAlert).Methods(http.MethodGet)
	admin.HandleFunc("/api/v1/alerts/{id}/acknowledge", s.handleAcknowledgeAlert).Methods(http.MethodPut)

	// Inventory
	admin.HandleFunc("/api/v1/inventory", s.handleListInventory).Methods(http.MethodGet)
	admin.HandleFunc("/api/v1/inventory/{agent_id}", s.handleGetInventory).Methods(http.MethodGet)

	// Audit events
	admin.HandleFunc("/api/v1/audit-events", s.handleListAuditEvents).Methods(http.MethodGet)

	// Log events
	admin.HandleFunc("/api/v1/log-events", s.handleListLogEvents).Methods(http.MethodGet)

	return r
}

// Middleware

func (s *Server) middlewareLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		s.logger.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

func (s *Server) middlewareRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic in handler", "panic", rec, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) middlewareAdminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if key != s.cfg.AdminAPIKey || s.cfg.AdminAPIKey == "" {
			writeError(w, http.StatusUnauthorized, "invalid API key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) middlewareAgentAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			writeError(w, http.StatusUnauthorized, "missing API key")
			return
		}
		agent, err := s.store.GetAgentByAPIKey(r.Context(), apiKey)
		if err != nil || agent == nil {
			writeError(w, http.StatusUnauthorized, "invalid API key")
			return
		}
		// make sure the API key belongs to the agent ID in the URL path
		pathID := mux.Vars(r)["id"]
		if agent.ID != pathID {
			writeError(w, http.StatusForbidden, "API key does not match agent ID")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) middlewareRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		s.rateMu.Lock()
		entry, ok := s.rateCounts[ip]
		now := time.Now()
		if !ok || now.After(entry.resetAt) {
			entry = &rateEntry{resetAt: now.Add(time.Minute)}
			s.rateCounts[ip] = entry
		}
		entry.count++
		count := entry.count
		s.rateMu.Unlock()

		if count > 300 { // 300 req/min per IP
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Health

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"version":   models.Version,
		"timestamp": time.Now().UTC(),
	})
}

// Agent registration

func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "hostname is required")
		return
	}

	// reject if a registration key is configured and the request doesn't match
	if s.cfg.RegistrationKey != "" && req.RegistrationKey != s.cfg.RegistrationKey {
		s.logger.Warn("agent registration rejected — bad registration key", "hostname", req.Hostname, "remote", r.RemoteAddr)
		// deliberately vague — don't tell them what was wrong
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	apiKey := uuid.New().String() + uuid.New().String()
	apiKey = strings.ReplaceAll(apiKey, "-", "")

	agent := &models.Agent{
		ID:           uuid.New().String(),
		Hostname:     req.Hostname,
		IPAddresses:  req.IPAddresses,
		Region:       req.Region,
		Tags:         req.Tags,
		Version:      req.Version,
		OS:           req.OS,
		APIKey:       apiKey,
		LastSeen:     time.Now().UTC(),
		Status:       models.AgentStatusOnline,
		RegisteredAt: time.Now().UTC(),
	}

	if err := s.store.CreateAgent(r.Context(), agent); err != nil {
		s.logger.Error("register agent", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to register agent")
		return
	}

	s.logger.Info("agent registered", "agent_id", agent.ID, "hostname", agent.Hostname)
	writeJSON(w, http.StatusCreated, models.RegisterResponse{
		AgentID: agent.ID,
		APIKey:  apiKey,
	})
}

// Heartbeat

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	agentID := mux.Vars(r)["id"]

	var req models.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.heartbeatMon.RecordHeartbeat(r.Context(), agentID); err != nil {
		s.logger.Error("record heartbeat", "error", err)
		writeError(w, http.StatusInternalServerError, "heartbeat failed")
		return
	}

	currentVersion, err := s.rulesMgr.GetRulesVersion(r.Context())
	if err != nil {
		currentVersion = ""
	}

	writeJSON(w, http.StatusOK, models.HeartbeatResponse{
		RulesUpdated: currentVersion != req.RulesVersion,
		RulesVersion: currentVersion,
	})
}

// Rules (agent)

func (s *Server) handleGetRules(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rulesMgr.GetRulesResponse(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch rules")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Log Events (agent)

func (s *Server) handleLogEvents(w http.ResponseWriter, r *http.Request) {
	agentID := mux.Vars(r)["id"]

	var req models.LogEventsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	for i := range req.Events {
		ev := &req.Events[i]
		ev.AgentID = agentID
		if ev.ID == "" {
			ev.ID = uuid.New().String()
		}
		if err := s.store.SaveLogEvent(r.Context(), ev); err != nil {
			s.logger.Error("save log event", "error", err)
			continue
		}
		if _, err := s.alertsMgr.CreateFromLogEvent(r.Context(), ev); err != nil {
			s.logger.Error("create alert from log event", "error", err)
		}
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{"received": len(req.Events)})
}

// Inventory (agent)

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	agentID := mux.Vars(r)["id"]

	var inv models.SystemInventory
	if err := json.NewDecoder(r.Body).Decode(&inv); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	inv.AgentID = agentID

	if err := s.inventoryStr.Save(r.Context(), &inv); err != nil {
		s.logger.Error("save inventory", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to save inventory")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"saved": true})
}

// Audit Events (agent)

func (s *Server) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	agentID := mux.Vars(r)["id"]

	var req models.AuditEventsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	for i := range req.Events {
		ev := &req.Events[i]
		ev.AgentID = agentID
		if ev.ID == "" {
			ev.ID = uuid.New().String()
		}
		if err := s.store.SaveAuditEvent(r.Context(), ev); err != nil {
			s.logger.Error("save audit event", "error", err)
		}
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{"received": len(req.Events)})
}

// Admin: Agents

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list agents")
		return
	}
	writeJSON(w, http.StatusOK, agents)
}

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	agent, err := s.store.GetAgent(r.Context(), id)
	if err != nil || agent == nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	agent.APIKey = "" // don't send API keys in list responses
	writeJSON(w, http.StatusOK, agent)
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := s.store.DeleteAgent(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete agent")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// Admin: Rules

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.rulesMgr.ListRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list rules")
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var req models.Rule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	rule, err := s.rulesMgr.CreateRule(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleGetRule(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	rule, err := s.rulesMgr.GetRule(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req models.Rule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	rule, err := s.rulesMgr.UpdateRule(r.Context(), id, &req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := s.rulesMgr.DeleteRule(r.Context(), id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// Admin: Alerts

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := models.AlertFilter{
		AgentID:   q.Get("agent_id"),
		AlertType: models.AlertType(q.Get("type")),
		Severity:  models.Severity(q.Get("severity")),
		Limit:     100,
	}
	if q.Get("unacknowledged") == "true" {
		f := false
		filter.Acknowledged = &f
	}

	alertList, err := s.alertsMgr.ListAlerts(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list alerts")
		return
	}
	writeJSON(w, http.StatusOK, alertList)
}

func (s *Server) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	alert, err := s.alertsMgr.GetAlert(r.Context(), id)
	if err != nil || alert == nil {
		writeError(w, http.StatusNotFound, "alert not found")
		return
	}
	writeJSON(w, http.StatusOK, alert)
}

func (s *Server) handleAcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var body struct {
		By string `json:"by"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.By == "" {
		body.By = "admin"
	}
	if err := s.alertsMgr.AcknowledgeAlert(r.Context(), id, body.By); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to acknowledge alert")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"acknowledged": true})
}

// Admin: Inventory

func (s *Server) handleListInventory(w http.ResponseWriter, r *http.Request) {
	invs, err := s.inventoryStr.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list inventory")
		return
	}
	writeJSON(w, http.StatusOK, invs)
}

func (s *Server) handleGetInventory(w http.ResponseWriter, r *http.Request) {
	agentID := mux.Vars(r)["agent_id"]
	inv, err := s.inventoryStr.Get(r.Context(), agentID)
	if err != nil || inv == nil {
		writeError(w, http.StatusNotFound, "inventory not found")
		return
	}
	writeJSON(w, http.StatusOK, inv)
}

// Admin: Audit Events

func (s *Server) handleListAuditEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := models.AuditEventFilter{
		AgentID:   q.Get("agent_id"),
		EventType: models.AuditEventType(q.Get("type")),
		Username:  q.Get("username"),
		Limit:     200,
	}
	if since := q.Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			filter.Since = t
		}
	}
	events, err := s.store.ListAuditEvents(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list audit events")
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// Admin: Log Events

func (s *Server) handleListLogEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := models.AlertFilter{
		AgentID: q.Get("agent_id"),
		Limit:   200,
	}
	events, err := s.store.ListLogEvents(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list log events")
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// Helpers

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, models.APIResponse{Success: false, Error: msg})
}
