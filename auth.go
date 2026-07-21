package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Machine-to-machine token manager for the category-(b) synthetic
// ingest scenarios. The harness behaves like the cluster's
// komuta-security-agent: it does an OAuth2 client_credentials flow
// against the Komuta auth server, caches the bearer token, and
// refreshes it ~60s before expiry.
//
// Config (all via env, wired by the operator at deploy time):
//
//	KOMUTA_AUTH_URL    e.g. https://auth.devopszon.com
//	KOMUTA_API_BASE    e.g. https://komuta-api-xxxx.edge-4.komuta.app
//	KOMUTA_CLIENT_ID   OAuth client (for runtime ingest this MUST be the
//	                   cluster's security-agent client so the backend's
//	                   cluster resolver maps client_id -> cluster)
//	KOMUTA_CLIENT_SECRET
//	KOMUTA_CLUSTER_ID  the cluster UUID — sent as X-Cluster-Id; must
//	                   match the cluster the client_id resolves to
//	KOMUTA_SCOPE       optional, default "DevOpsZon"
//
// If KOMUTA_CLIENT_ID/SECRET are unset the category-(b) scenarios are
// reported as "not configured" instead of failing — category-(a)
// cluster-native triggers still work without any of this.

type ingestConfig struct {
	AuthURL      string
	APIBase      string
	ClientID     string
	ClientSecret string
	ClusterID    string
	Scope        string
}

type tokenManager struct {
	cfg ingestConfig

	mu        sync.Mutex
	token     string
	expiresAt time.Time
	http      *http.Client
}

var ingestTokens *tokenManager

func loadIngestConfig() ingestConfig {
	scope := os.Getenv("KOMUTA_SCOPE")
	if scope == "" {
		scope = "DevOpsZon"
	}
	return ingestConfig{
		AuthURL:      strings.TrimRight(os.Getenv("KOMUTA_AUTH_URL"), "/"),
		APIBase:      strings.TrimRight(os.Getenv("KOMUTA_API_BASE"), "/"),
		ClientID:     os.Getenv("KOMUTA_CLIENT_ID"),
		ClientSecret: os.Getenv("KOMUTA_CLIENT_SECRET"),
		ClusterID:    os.Getenv("KOMUTA_CLUSTER_ID"),
		Scope:        scope,
	}
}

func initTokenManager() {
	cfg := loadIngestConfig()
	ingestTokens = &tokenManager{
		cfg:  cfg,
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

// configured reports whether the operator wired enough env for the
// category-(b) direct-ingest scenarios to run at all.
func (t *tokenManager) configured() bool {
	c := t.cfg
	return c.AuthURL != "" && c.APIBase != "" && c.ClientID != "" &&
		c.ClientSecret != "" && c.ClusterID != ""
}

// missingConfig returns the human-readable list of unset env keys so
// the UI can tell the operator exactly what to wire.
func (t *tokenManager) missingConfig() []string {
	c := t.cfg
	var miss []string
	if c.AuthURL == "" {
		miss = append(miss, "KOMUTA_AUTH_URL")
	}
	if c.APIBase == "" {
		miss = append(miss, "KOMUTA_API_BASE")
	}
	if c.ClientID == "" {
		miss = append(miss, "KOMUTA_CLIENT_ID")
	}
	if c.ClientSecret == "" {
		miss = append(miss, "KOMUTA_CLIENT_SECRET")
	}
	if c.ClusterID == "" {
		miss = append(miss, "KOMUTA_CLUSTER_ID")
	}
	return miss
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// bearer returns a valid access token, refreshing via
// client_credentials when the cached one is missing or within 60s of
// expiry. Concurrent callers share one refresh under the mutex.
func (t *tokenManager) bearer(ctx context.Context) (string, error) {
	if !t.configured() {
		return "", fmt.Errorf("ingest not configured; missing env: %s",
			strings.Join(t.missingConfig(), ", "))
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.token != "" && time.Until(t.expiresAt) > 60*time.Second {
		return t.token, nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", t.cfg.ClientID)
	form.Set("client_secret", t.cfg.ClientSecret)
	form.Set("scope", t.cfg.Scope)

	tokenURL := t.cfg.AuthURL + "/connect/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := t.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("token decode (HTTP %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		msg := tr.Error
		if tr.ErrorDesc != "" {
			msg += ": " + tr.ErrorDesc
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return "", fmt.Errorf("token endpoint rejected: %s", msg)
	}

	t.token = tr.AccessToken
	ttl := tr.ExpiresIn
	if ttl <= 0 {
		ttl = 300
	}
	t.expiresAt = time.Now().Add(time.Duration(ttl) * time.Second)
	return t.token, nil
}
