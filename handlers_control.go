package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Control plane — fault injection, traffic generator, current-state
// snapshot. Mounted at /control/*. Security violation triggers register
// themselves via registerSecurityRoutes (called from here) so the
// security surface stays self-contained even if it grows.

func registerControlRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /control/inject-latency", controlInjectLatency)
	mux.HandleFunc("POST /control/inject-errors", controlInjectErrors)
	mux.HandleFunc("POST /control/clear-faults", controlClearFaults)
	mux.HandleFunc("POST /control/start-traffic", controlStartTraffic)
	mux.HandleFunc("POST /control/stop-traffic", controlStopTraffic)
	mux.HandleFunc("GET /control/state", controlState)

	registerSecurityRoutes(mux)
	registerDdosRoutes(mux)
}

type injectLatencyInput struct {
	// Pattern is the mux key — either "METHOD /path" or "*" for all
	// business endpoints. "*" stacks with per-endpoint rules.
	Pattern     string `json:"pattern"`
	Ms          int    `json:"ms"`
	DurationSec int    `json:"durationSec"` // 0 = until cleared
}

func controlInjectLatency(w http.ResponseWriter, r *http.Request) {
	var in injectLatencyInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if in.Pattern == "" || in.Ms <= 0 {
		writeJSONError(w, http.StatusBadRequest, "pattern + ms required")
		return
	}
	setLatencyInjection(in.Pattern, time.Duration(in.Ms)*time.Millisecond, time.Duration(in.DurationSec)*time.Second)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "applied": in})
}

type injectErrorsInput struct {
	Pattern     string  `json:"pattern"`
	Rate        float64 `json:"rate"`   // 0..1
	Status      int     `json:"status"` // 4xx/5xx
	DurationSec int     `json:"durationSec"`
}

func controlInjectErrors(w http.ResponseWriter, r *http.Request) {
	var in injectErrorsInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if in.Pattern == "" || in.Rate <= 0 || in.Status < 400 {
		writeJSONError(w, http.StatusBadRequest, "pattern + rate + 4xx/5xx status required")
		return
	}
	setErrorInjection(in.Pattern, in.Rate, in.Status, time.Duration(in.DurationSec)*time.Second)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "applied": in})
}

func controlClearFaults(w http.ResponseWriter, _ *http.Request) {
	clearFaults()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cleared": true})
}

func controlStartTraffic(w http.ResponseWriter, r *http.Request) {
	var in trafficCfg
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	startTrafficGenerator(in, port)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "running": true})
}

func controlStopTraffic(w http.ResponseWriter, _ *http.Request) {
	stopTrafficGenerator()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "running": false})
}

func controlState(w http.ResponseWriter, _ *http.Request) {
	endpoints := make([]string, 0, len(apiProfiles))
	for k := range apiProfiles {
		endpoints = append(endpoints, k)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":          AppVersion,
		"endpoints":        endpoints,
		"defaultMix":       defaultTrafficMix,
		"faults":           snapshotFaults(),
		"trafficGenerator": snapshotTraffic(),
	})
}

// duration parser kept here in case we ever take "5m" / "30s" strings
// from query params instead of integer seconds. Unused at the moment but
// trivial enough to keep close.
func parseDuration(raw string) time.Duration {
	if raw == "" {
		return 0
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return d
	}
	if n, err := strconv.Atoi(strings.TrimSuffix(raw, "s")); err == nil {
		return time.Duration(n) * time.Second
	}
	return 0
}
