// komuta-test-app
//
// Single-binary harness for exercising Komuta's Insights and Security
// surfaces against realistic-looking traffic and on-demand fault /
// violation triggers. Drop it on a cluster, point Komuta at it, and use
// the embedded UI at "/" to inject latency, fire 500s, generate
// synthetic load, or trip KubeArmor policies.
package main

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

//go:embed ui/index.html
var uiFS embed.FS

// AppVersion is the operator-visible version of this build. Komuta's
// Insights → Etki tab uses the deployed image tag to label release rows;
// we mirror it into /readyz and the UI footer so test cycles can confirm
// "yes, the regression I'm seeing IS the v1.1-bug image, not stale data".
//
// The string is also pattern-matched to enable preset behaviours so a
// single image can be deployed under different tags to demo deploy
// impact without rebuilding:
//
//	*-bug    → /api/checkout returns 500 on ~30% of POSTs by default
//	*-slow   → every business endpoint adds +200ms baseline latency
//	(else)   → clean baseline; faults must be injected from the UI
var AppVersion = "v0.0.0-dev"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--runtime-acceptance-probe" {
		writeRuntimeProbe(os.Stdout)
		return
	}
	if v := os.Getenv("APP_VERSION"); v != "" {
		AppVersion = v
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Tag-driven preset injection — applied at startup so a fresh deploy
	// starts in the right mode before any traffic shows up. Manual UI
	// injections still work; presets just give the operator a known-bad
	// (or known-slow) baseline without manual setup.
	applyVersionPresets(AppVersion)

	shutdownTelemetry, err := initTelemetry(context.Background())
	if err != nil {
		log.Printf("[komuta-test-app] OpenTelemetry disabled: %v", err)
		shutdownTelemetry = func(context.Context) error { return nil }
	}

	// Embedded localization bundles (tr = default, en = fallback) must
	// load before any handler can serve the localized catalogue. Fatal
	// on a malformed bundle — a half-localized console is worse than a
	// loud startup failure.
	loadI18n()

	// M2M token manager + scenario catalog must exist before routes
	// are registered so the catalog handler can report ingest wiring
	// status on the very first request.
	initTokenManager()
	buildScenarios()

	mux := http.NewServeMux()

	registerHealthRoutes(mux)
	registerAPIRoutes(mux)
	registerControlRoutes(mux)
	registerScenarioRoutes(mux)
	registerBandwidthRoutes(mux)
	registerUIRoutes(mux)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           tracedHTTPHandler(mux, withRequestLog(mux)),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Graceful shutdown so Komuta's pre-stop hook (if wired) sees us
	// drain in-flight requests instead of cutting the deploy mid-spike.
	go func() {
		log.Printf("[komuta-test-app] %s listening on :%s", AppVersion, port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[komuta-test-app] listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("[komuta-test-app] shutdown signal received")

	stopTrafficGenerator()
	stopDdosFlood()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	if err := shutdownTelemetry(ctx); err != nil {
		log.Printf("[komuta-test-app] OpenTelemetry shutdown: %v", err)
	}
}

// withRequestLog stamps every request with method, path, status and
// elapsed time so kubectl logs is useful when ClickHouse pipeline isn't
// reachable. Skips the noisy /healthz and /readyz lines.
func withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			return
		}
		log.Printf("%s %s %d %dms", r.Method, r.URL.Path, rw.status, time.Since(start).Milliseconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func registerUIRoutes(mux *http.ServeMux) {
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		log.Fatalf("[komuta-test-app] embed: %v", err)
	}
	mux.Handle("GET /", http.FileServer(http.FS(sub)))
}

func applyVersionPresets(tag string) {
	t := strings.ToLower(tag)
	switch {
	case strings.HasSuffix(t, "-bug"):
		// Mirror the typical "we shipped a bad release" demo: a single
		// loud endpoint regressing while the rest of the surface stays
		// healthy. Insights' top-contributing-endpoints chip strip
		// should pick this up on the first deploy-impact refresh.
		setErrorInjection("POST /api/checkout", 0.30, http.StatusInternalServerError, 0)
		log.Printf("[komuta-test-app] preset: %s → POST /api/checkout error 30%%", tag)
	case strings.HasSuffix(t, "-slow"):
		setLatencyInjection("*", 200*time.Millisecond, 0)
		log.Printf("[komuta-test-app] preset: %s → +200ms baseline on every endpoint", tag)
	}
}
