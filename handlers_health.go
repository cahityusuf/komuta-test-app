package main

import (
	"net/http"
	"os"
	"runtime"
	"time"
)

var startTime = time.Now()

func registerHealthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		hostname, _ := os.Hostname()
		writeJSON(w, http.StatusOK, map[string]any{
			"status":     "ready",
			"version":    AppVersion,
			"hostname":   hostname,
			"uptimeSec":  int(time.Since(startTime).Seconds()),
			"goVersion":  runtime.Version(),
			"goRoutines": runtime.NumGoroutine(),
		})
	})
}
