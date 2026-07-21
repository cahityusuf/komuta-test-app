package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DDoS flood generator — drives a sustained fresh-connection HTTP flood
// so Komuta's DdosFlowToIncidentProjector has a real signal to raise on.
//
// The detector keys on (source_ip, destination_identity, port, protocol)
// over a rolling 10-min window sourced from komuta.l4_traffic_5m (request
// side, pre-sampling) and trips when flow_count > 10000. Every NEW TCP
// connection is one flow, so keep-alive is OFF and every request forces a
// fresh handshake.
//
// Target resolution is deploy-agnostic — this image is redeployed under
// different tenants/service names, so nothing is hardcoded. See
// resolveDdosFloodTarget for the order. A "self-service" target (this
// app's own -stable ClusterIP service) yields an incident stamped with
// this service's resolved service_id → attributed to the tenant. A
// "world" target (external host, CNP toEntities:world) always works but
// yields a cluster-scoped, unattributed incident.
//
// Sizing: >10000 flows in a 10-min window needs ≥17 conn/s. The default
// of ~50 conn/s for ~12 min (≈36000 flows) clears the threshold with a
// comfortable margin. The flood runs on its own context — NOT the request
// context — so the scenario handler returns immediately while the flood
// continues in the background until its duration elapses or it is stopped.

const (
	ddosDefaultConnPerSec   = 50
	ddosDefaultDuration     = 12 * 60 // 720s — comfortably above the 10-min detector window
	ddosMaxConnPerSec       = 200     // safety: this is real sustained load
	ddosMaxDuration         = 30 * 60 // hard cap so a flood can never run unbounded
	ddosDefaultPath         = "/healthz"
	ddosDefaultPort         = "8080"
	ddosWorldFallbackTarget = "1.1.1.1:80" // last-resort world target when nothing else resolves
	ddosSANamespaceFile     = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

type ddosFloodState struct {
	mu        sync.Mutex
	cancel    context.CancelFunc
	startedAt time.Time
	cfg       ddosFloodCfg
}

type ddosFloodCfg struct {
	Target      string `json:"target"` // host:port
	Path        string `json:"path"`
	ConnPerSec  int    `json:"connPerSec"`
	DurationSec int    `json:"durationSec"`
	Mode        string `json:"mode"`        // "self-service" | "world"
	Attribution string `json:"attribution"` // "tenant-service" | "cluster-scoped"
	Note        string `json:"note"`
}

var ddosState = &ddosFloodState{}

// ddosTargetResolution is the outcome of picking a flood target, carrying
// enough context for the operator to know whether the resulting incident
// will be attributed to the tenant service or land cluster-scoped.
type ddosTargetResolution struct {
	Target      string
	Mode        string
	Attribution string
	Note        string
}

// podNamespace reads the pod namespace from the downward-API env first,
// then the mounted service-account namespace file.
func podNamespace() string {
	if ns := strings.TrimSpace(os.Getenv("POD_NAMESPACE")); ns != "" {
		return ns
	}
	data, err := os.ReadFile(ddosSANamespaceFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// selfServiceName derives this deployed service's name from the first env
// that the operator or Komuta sets. Empty if none is present, in which
// case the self-service DNS can't be built and the flood falls back to
// world mode. Not hardcoded because the image is redeployed under
// different service names.
func selfServiceName() string {
	for _, k := range []string{
		"DDOS_SELF_SERVICE",
		"KOMUTA_SERVICE_NAME",
		"KOMUTA_SERVICE_SLUG",
		"SERVICE_NAME",
		"APP_NAME",
	} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// resolveDdosFloodTarget picks the target for the default (self) scenario:
//  1. DDOS_TARGET (host:port) — operator override, treated as self-service
//     (set it to your own -stable ClusterIP DNS for an attributed incident).
//  2. <svc>-stable.<ns>.svc.cluster.local:8080 — derived from a service-name
//     env + the pod namespace; attributed to this tenant service.
//  3. World fallback — DDOS_WORLD_TARGET else 1.1.1.1:80. Always works but
//     the incident is cluster-scoped / unattributed.
func resolveDdosFloodTarget() ddosTargetResolution {
	if t := strings.TrimSpace(os.Getenv("DDOS_TARGET")); t != "" {
		return ddosTargetResolution{
			Target: t, Mode: "self-service", Attribution: "tenant-service",
			Note: "target from DDOS_TARGET override",
		}
	}
	svc := selfServiceName()
	ns := podNamespace()
	if svc != "" && ns != "" {
		return ddosTargetResolution{
			Target:      svc + "-stable." + ns + ".svc.cluster.local:" + ddosDefaultPort,
			Mode:        "self-service",
			Attribution: "tenant-service",
			Note:        "derived self-service DNS from service=" + svc + " ns=" + ns,
		}
	}
	target := strings.TrimSpace(os.Getenv("DDOS_WORLD_TARGET"))
	if target == "" {
		target = ddosWorldFallbackTarget
	}
	return ddosTargetResolution{
		Target: target, Mode: "world", Attribution: "cluster-scoped",
		Note: "self-service target unresolved (set DDOS_TARGET, or DDOS_SELF_SERVICE + POD_NAMESPACE, for a tenant-attributed incident); flooding external host",
	}
}

// resolveDdosWorldTarget picks the target for the explicit world scenario:
// DDOS_WORLD_TARGET, else DDOS_TARGET, else 1.1.1.1:80. Always resolves.
func resolveDdosWorldTarget() ddosTargetResolution {
	target := strings.TrimSpace(os.Getenv("DDOS_WORLD_TARGET"))
	if target == "" {
		target = strings.TrimSpace(os.Getenv("DDOS_TARGET"))
	}
	if target == "" {
		target = ddosWorldFallbackTarget
	}
	return ddosTargetResolution{
		Target: target, Mode: "world", Attribution: "cluster-scoped",
		Note: "forced world-mode flood to external host",
	}
}

func ddosConnPerSec() int {
	if v := strings.TrimSpace(os.Getenv("DDOS_CONN_PER_SEC")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return ddosDefaultConnPerSec
}

func ddosDurationSec() int {
	if v := strings.TrimSpace(os.Getenv("DDOS_DURATION_SEC")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return ddosDefaultDuration
}

func ddosPath() string {
	if p := strings.TrimSpace(os.Getenv("DDOS_PATH")); p != "" {
		return p
	}
	return ddosDefaultPath
}

// startFloodFrom builds the flood cfg from a resolved target + the env
// knobs and launches it. Shared by both the self and world scenarios.
func startFloodFrom(res ddosTargetResolution) map[string]any {
	return startDdosFlood(ddosFloodCfg{
		Target:      res.Target,
		Path:        ddosPath(),
		ConnPerSec:  ddosConnPerSec(),
		DurationSec: ddosDurationSec(),
		Mode:        res.Mode,
		Attribution: res.Attribution,
		Note:        res.Note,
	})
}

// startDdosFlood launches the background flood. Calling it again replaces
// the running flood so self/world can't stack. Returns the summary the
// scenario handler echoes back.
func startDdosFlood(cfg ddosFloodCfg) map[string]any {
	ddosState.mu.Lock()
	defer ddosState.mu.Unlock()

	if ddosState.cancel != nil {
		ddosState.cancel()
	}

	if cfg.ConnPerSec <= 0 {
		cfg.ConnPerSec = ddosDefaultConnPerSec
	}
	if cfg.ConnPerSec > ddosMaxConnPerSec {
		cfg.ConnPerSec = ddosMaxConnPerSec
	}
	if cfg.DurationSec <= 0 {
		cfg.DurationSec = ddosDefaultDuration
	}
	if cfg.DurationSec > ddosMaxDuration {
		cfg.DurationSec = ddosMaxDuration
	}
	if cfg.Path == "" {
		cfg.Path = ddosDefaultPath
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.DurationSec)*time.Second)
	ddosState.cancel = cancel
	ddosState.startedAt = time.Now()
	ddosState.cfg = cfg

	log.Printf("[komuta-test-app] ddos flood start: target=%s mode=%s attribution=%s connPerSec=%d durationSec=%d — %s",
		cfg.Target, cfg.Mode, cfg.Attribution, cfg.ConnPerSec, cfg.DurationSec, cfg.Note)

	go runDdosFlood(ctx, cfg)

	return map[string]any{
		"floodStarted": true,
		"target":       cfg.Target,
		"path":         cfg.Path,
		"mode":         cfg.Mode,
		"attribution":  cfg.Attribution,
		"note":         cfg.Note,
		"connPerSec":   cfg.ConnPerSec,
		"durationSec":  cfg.DurationSec,
		"estFlows":     cfg.ConnPerSec * cfg.DurationSec,
	}
}

// stopDdosFlood cancels the running flood if any. Called from the stop
// scenario, the /control/ddos/stop endpoint, and main.go on SIGTERM.
func stopDdosFlood() {
	ddosState.mu.Lock()
	defer ddosState.mu.Unlock()
	if ddosState.cancel != nil {
		ddosState.cancel()
		ddosState.cancel = nil
	}
}

func snapshotDdosFlood() map[string]any {
	ddosState.mu.Lock()
	defer ddosState.mu.Unlock()
	if ddosState.cancel == nil {
		return map[string]any{"running": false}
	}
	return map[string]any{
		"running":     true,
		"startedAt":   ddosState.startedAt.UTC().Format(time.RFC3339),
		"target":      ddosState.cfg.Target,
		"path":        ddosState.cfg.Path,
		"mode":        ddosState.cfg.Mode,
		"attribution": ddosState.cfg.Attribution,
		"connPerSec":  ddosState.cfg.ConnPerSec,
		"durationSec": ddosState.cfg.DurationSec,
	}
}

func runDdosFlood(ctx context.Context, cfg ddosFloodCfg) {
	interval := time.Second / time.Duration(cfg.ConnPerSec)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()

	// DisableKeepAlives + req.Close force a brand-new TCP handshake per
	// request — each one is a distinct flow the detector counts.
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}

	url := "http://" + cfg.Target + cfg.Path

	jobs := make(chan struct{}, 256)
	workerCount := minInt(cfg.ConnPerSec, 40)
	if workerCount < 8 {
		workerCount = 8
	}

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				fireFresh(client, url)
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case <-tick.C:
			select {
			case jobs <- struct{}{}:
			default:
				// Workers saturated — drop the tick instead of piling up.
			}
		}
	}
}

func fireFresh(client *http.Client, url string) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

func registerDdosRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /control/ddos/stop", func(w http.ResponseWriter, _ *http.Request) {
		stopDdosFlood()
		writeJSON(w, http.StatusOK, snapshotDdosFlood())
	})
	mux.HandleFunc("GET /control/ddos/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, snapshotDdosFlood())
	})
}
