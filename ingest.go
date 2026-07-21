package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Category-(b) direct synthetic ingest. Each builder crafts a
// backend-valid payload (shapes mirror the real
// Application.Contracts DTOs) and POSTs it with the M2M bearer +
// the X-Cluster-Id / X-Batch-Id headers the ingest controllers
// require. Returns a compact result the scenario layer surfaces to
// the operator.

type ingestResult struct {
	Endpoint   string `json:"endpoint"`
	HTTPStatus int    `json:"httpStatus"`
	RequestID  string `json:"requestId,omitempty"`
	Body       string `json:"body"`
	Err        string `json:"error,omitempty"`
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// postJSON sends a single JSON document with the M2M bearer.
func (t *tokenManager) postJSON(ctx context.Context, path string, payload any) ingestResult {
	res := ingestResult{Endpoint: path}
	tok, err := t.bearer(ctx)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		t.cfg.APIBase+path, bytes.NewReader(buf))
	if err != nil {
		res.Err = err.Error()
		return res
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	return t.do(req, &res)
}

// postNDJSON sends a runtime/flow batch: one JSON object per line,
// plus the cluster + batch idempotency headers.
func (t *tokenManager) postNDJSON(ctx context.Context, path string, records []any) ingestResult {
	res := ingestResult{Endpoint: path}
	tok, err := t.bearer(ctx)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			res.Err = err.Error()
			return res
		}
	}
	batchID := newUUID()
	res.RequestID = batchID
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		t.cfg.APIBase+path, strings.NewReader(sb.String()))
	if err != nil {
		res.Err = err.Error()
		return res
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("X-Cluster-Id", t.cfg.ClusterID)
	req.Header.Set("X-Batch-Id", batchID)
	return t.do(req, &res)
}

func (t *tokenManager) do(req *http.Request, res *ingestResult) ingestResult {
	resp, err := t.http.Do(req)
	if err != nil {
		res.Err = err.Error()
		return *res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	res.HTTPStatus = resp.StatusCode
	res.Body = strings.TrimSpace(string(body))
	if resp.StatusCode >= 400 {
		res.Err = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return *res
}

// ── Runtime ingest (Tetragon / KubeArmor / Hubble source) ───────────

// runtimeRecord mirrors SecurityRuntimeIngestRecordDto. Field names
// are lowerCamelCase to match the backend's JSON casing.
type runtimeRecord struct {
	EventTime     string `json:"eventTime"`
	Source        string `json:"source"`
	EventType     string `json:"eventType"`
	Severity      int    `json:"severity"`
	ServiceID     string `json:"serviceId,omitempty"`
	NodeName      string `json:"nodeName"`
	PodName       string `json:"podName"`
	ContainerName string `json:"containerName"`
	BinaryPath    string `json:"binaryPath"`
	Args          string `json:"args"`
	EvidenceJSON  string `json:"evidenceJson"`
}

func (t *tokenManager) ingestRuntime(ctx context.Context, source string, recs []runtimeRecord) ingestResult {
	anyRecs := make([]any, len(recs))
	for i := range recs {
		anyRecs[i] = recs[i]
	}
	return t.postNDJSON(ctx, "/api/app/security-center/runtime/ingest", anyRecs)
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// ── KubeArmor baseline observations (-> findings via projector) ─────

type observationEvent struct {
	ServiceID string `json:"serviceId"`
	Operation string `json:"operation"` // Write|Exec|NetworkConnect|CapabilityUse|Mount
	Path      string `json:"path"`
	Action    string `json:"action"` // Audit|Block
	Severity  int    `json:"severity"`
	RuleName  string `json:"ruleName,omitempty"`
	PodName   string `json:"podName,omitempty"`
	TenantID  string `json:"tenantId,omitempty"`
}

func (t *tokenManager) ingestObservations(ctx context.Context, evs []observationEvent) ingestResult {
	return t.postJSON(ctx, "/api/devopszon/security-observations/ingest",
		map[string]any{"events": evs})
}

// ── Network flow ingest (Hubble L4/L7) ─────────────────────────────

func (t *tokenManager) ingestFlows(ctx context.Context, records []any) ingestResult {
	return t.postNDJSON(ctx, "/api/app/network-observability/flows/ingest", records)
}

// ── Supply chain (Tekton task ingest -> WORM 40-43) ────────────────

func (t *tokenManager) ingestSbom(ctx context.Context, pipelineRun, imageRef, sbomURI string) ingestResult {
	return t.postJSON(ctx, "/api/app/security-center/build-artifacts/ingest/sbom",
		map[string]any{
			"pipelineRunName": pipelineRun,
			"imageRef":        imageRef,
			"sbomS3Uri":       sbomURI,
			"emittedAt":       now(),
		})
}

func (t *tokenManager) ingestScan(ctx context.Context, pipelineRun, imageRef string, crit, high, med, low int) ingestResult {
	return t.postJSON(ctx, "/api/app/security-center/build-artifacts/ingest/scan",
		map[string]any{
			"pipelineRunName": pipelineRun,
			"imageRef":        imageRef,
			"reportInline":    `{"schema":"trivy","summary":"komuta-test-app synthetic scan"}`,
			"criticalCount":   crit,
			"highCount":       high,
			"mediumCount":     med,
			"lowCount":        low,
			"scannedAt":       now(),
		})
}

func (t *tokenManager) ingestSignature(ctx context.Context, pipelineRun, imageRef string) ingestResult {
	return t.postJSON(ctx, "/api/app/security-center/build-artifacts/ingest/signature",
		map[string]any{
			"pipelineRunName": pipelineRun,
			"imageRef":        imageRef,
			"rekorEntryUuid":  hex.EncodeToString([]byte(newUUID()))[:48],
			"signatureUri":    imageRef + ".sig",
			"signerIdentity":  "Microzon-Tech/komuta-test-app",
			"signedAt":        now(),
		})
}

func (t *tokenManager) ingestBuildFailure(ctx context.Context, pipelineRun, imageRef, reason string) ingestResult {
	return t.postJSON(ctx, "/api/app/security-center/build-artifacts/ingest/failure",
		map[string]any{
			"pipelineRunName": pipelineRun,
			"imageRef":        imageRef,
			"reason":          reason,
		})
}

// ── Synthetic attack run trigger ───────────────────────────────────

func (t *tokenManager) triggerSyntheticAttack(ctx context.Context, scenarioID, targetServiceID string) ingestResult {
	body := map[string]any{"scenarioId": scenarioID}
	if targetServiceID != "" {
		body["targetServiceId"] = targetServiceID
	} else if t.cfg.ClusterID != "" {
		body["targetClusterId"] = t.cfg.ClusterID
	}
	return t.postJSON(ctx, "/api/app/security-center/synthetic-attacks/runs/trigger", body)
}
