package main

import (
	"io"
	"math"
	"net/http"
	"strconv"
	"time"
)

// Bandwidth endpoints exercise the platform's per-service bandwidth caps
// end-to-end:
//
//	GET  /api/bandwidth/download?mb=N — streams N MB out of the pod. The bytes
//	    leave the pod, so a client download measures pod EGRESS, which Cilium
//	    Bandwidth Manager caps at the plan's egress limit.
//	POST /api/bandwidth/upload        — reads and discards the request body and
//	    reports how fast it arrived. The bytes flow INTO the pod, so a client
//	    upload measures pod INGRESS, which komuta-ingress-shaper caps at the
//	    plan's ingress limit.
//
// Run both from a client on a DIFFERENT node (or external): same-node
// pod-to-pod traffic is redirected veth-to-veth in eBPF and bypasses the host
// tc qdisc, so it won't show the ingress cap.
func registerBandwidthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/bandwidth/download", bandwidthDownload)
	mux.HandleFunc("POST /api/bandwidth/upload", bandwidthUpload)
}

const (
	bwDefaultMB = 50
	bwMaxMB     = 1024
)

// GET /api/bandwidth/download?mb=N  (default 50, max 1024)
func bandwidthDownload(w http.ResponseWriter, r *http.Request) {
	mb := bwClampMB(r.URL.Query().Get("mb"))
	total := mb * 1024 * 1024

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(total))
	w.Header().Set("Cache-Control", "no-store")

	buf := make([]byte, 64*1024)
	for i := range buf {
		buf[i] = 'X'
	}
	remaining := total
	for remaining > 0 {
		n := len(buf)
		if n > remaining {
			n = remaining
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return // client went away mid-stream
		}
		remaining -= n
	}
}

// POST /api/bandwidth/upload — ingress sink: drain the body, report throughput.
func bandwidthUpload(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	n, err := io.Copy(io.Discard, r.Body)
	_ = r.Body.Close()
	seconds := time.Since(start).Seconds()

	mbps := 0.0
	if seconds > 0 {
		mbps = float64(n) * 8 / 1_000_000 / seconds
	}

	resp := map[string]any{
		"received_bytes": n,
		"seconds":        bwRound(seconds, 3),
		"mbps":           bwRound(mbps, 2),
	}
	if err != nil {
		// Partial read still reports what arrived (fail-soft for test tooling).
		resp["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func bwClampMB(raw string) int {
	mb, err := strconv.Atoi(raw)
	if err != nil || mb <= 0 {
		return bwDefaultMB
	}
	if mb > bwMaxMB {
		return bwMaxMB
	}
	return mb
}

func bwRound(f float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(f*p) / p
}
