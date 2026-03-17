// Package client is the HTTP client the agent uses to talk to the collector.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"time"

	"github.com/VRCDN/guiltyspark/internal/common/models"
)

// Config holds the connection settings for the collector.
type Config struct {
	CollectorURL string
	APIKey       string
	AgentID      string
	TLSEnabled   bool
	CACertFile   string
	SkipVerify   bool
	Timeout      time.Duration
}

// Client wraps http.Client with typed methods for every collector endpoint.
type Client struct {
	cfg  Config
	http *http.Client
}

// New builds the HTTP client. If a CA cert is provided it gets pinned; otherwise we trust the system pool.
func New(cfg Config) (*Client, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.SkipVerify, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
	}

	if cfg.CACertFile != "" {
		pem, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("invalid CA cert PEM")
		}
		tlsCfg.RootCAs = pool
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
		MaxIdleConns:    10,
		IdleConnTimeout: 90 * time.Second,
	}

	return &Client{
		cfg:  cfg,
		http: &http.Client{Transport: transport, Timeout: cfg.Timeout},
	}, nil
}

// Register is the first call a new agent makes. Returns the agent ID and API key.
func (c *Client) Register(ctx context.Context, req models.RegisterRequest) (*models.RegisterResponse, error) {
	var resp models.RegisterResponse
	if err := c.post(ctx, "/api/v1/agents/register", req, &resp, false); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Heartbeat pings the collector and finds out if our rules are out of date.
func (c *Client) Heartbeat(ctx context.Context, req models.HeartbeatRequest) (*models.HeartbeatResponse, error) {
	var resp models.HeartbeatResponse
	url := fmt.Sprintf("/api/v1/agents/%s/heartbeat", c.cfg.AgentID)
	if err := c.post(ctx, url, req, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetRules fetches the current rule set.
func (c *Client) GetRules(ctx context.Context) (*models.RulesResponse, error) {
	var resp models.RulesResponse
	url := fmt.Sprintf("/api/v1/agents/%s/rules", c.cfg.AgentID)
	if err := c.get(ctx, url, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SendLogEvents ships a batch of rule matches to the collector.
func (c *Client) SendLogEvents(ctx context.Context, events []models.LogEvent) error {
	url := fmt.Sprintf("/api/v1/agents/%s/events", c.cfg.AgentID)
	return c.post(ctx, url, models.LogEventsRequest{Events: events}, nil, true)
}

// SendInventory uploads a full system inventory snapshot.
func (c *Client) SendInventory(ctx context.Context, inv *models.SystemInventory) error {
	url := fmt.Sprintf("/api/v1/agents/%s/inventory", c.cfg.AgentID)
	return c.post(ctx, url, inv, nil, true)
}

// SendAuditEvents ships a batch of audit events.
func (c *Client) SendAuditEvents(ctx context.Context, events []models.AuditEvent) error {
	url := fmt.Sprintf("/api/v1/agents/%s/audit-events", c.cfg.AgentID)
	return c.post(ctx, url, models.AuditEventsRequest{Events: events}, nil, true)
}

func (c *Client) post(ctx context.Context, path string, body, out interface{}, auth bool) error {
	return c.doWithRetry(ctx, func() error {
		return c.doRequest(ctx, http.MethodPost, path, body, out, auth)
	}, 3)
}

func (c *Client) get(ctx context.Context, path string, out interface{}) error {
	return c.doWithRetry(ctx, func() error {
		return c.doRequest(ctx, http.MethodGet, path, nil, out, true)
	}, 3)
}

func (c *Client) doWithRetry(ctx context.Context, fn func() error, maxAttempts int) error {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(); err != nil {
			lastErr = err
			// exponential backoff: 1s → 2s → 4s
			wait := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}
		return nil
	}
	return lastErr
}

func (c *Client) doRequest(ctx context.Context, method, path string, body, out interface{}, auth bool) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.cfg.CollectorURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GuiltySpark-Agent/"+models.Version)
	if auth && c.cfg.APIKey != "" {
		req.Header.Set("X-API-Key", c.cfg.APIKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("http %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("http %s %s: status %d: %s", method, path, resp.StatusCode, string(raw))
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
