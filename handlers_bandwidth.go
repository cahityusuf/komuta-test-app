package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Bandwidth endpoints exercise the platform's per-service bandwidth caps
// end-to-end. Komuta shapes only traffic between the Pod and the internet:
//
//	GET  /api/bandwidth/download?mb=N — streams N MB of incompressible data out
//	    of the Pod (Pod EGRESS). The server-side rate of the last download is
//	    served by GET /api/bandwidth/last-download.
//	POST /api/bandwidth/upload        — drains the request body (Pod INGRESS)
//	    and reports the rate the Pod received it at.
//	POST /api/bandwidth/selftest?direction=ingress|egress&seconds=N — the Pod
//	    itself pulls from (ingress) or pushes to (egress) a fast public endpoint
//	    and reports per-second throughput. This measures the plan cap without
//	    depending on the tester's own connection, which is usually slower than
//	    the cap and would otherwise be what a browser test measures.
func registerBandwidthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/bandwidth/download", bandwidthDownload)
	mux.HandleFunc("GET /api/bandwidth/last-download", bandwidthLastDownload)
	mux.HandleFunc("POST /api/bandwidth/upload", bandwidthUpload)
	mux.HandleFunc("POST /api/bandwidth/selftest", bandwidthSelfTest)
}

const (
	bwDefaultMB       = 50
	bwMaxMB           = 1024
	bwDefaultSeconds  = 20
	bwMaxSeconds      = 45
	bwWarmupSeconds   = 3
	bwPushLimitBytes  = 95 * 1000 * 1000
	bwRandomBlockSize = 1 << 20
)

var bwPullSources = []string{
	"https://fsn1-speed.hetzner.com/10GB.bin",
	"https://nbg1-speed.hetzner.com/10GB.bin",
	"https://proof.ovh.net/files/10Gb.dat",
}

const bwPushSink = "https://speed.cloudflare.com/__up"

var (
	bwRandomOnce  sync.Once
	bwRandomBlock []byte

	bwSelfTestBusy atomic.Bool

	bwLastMu       sync.Mutex
	bwLastDownload map[string]any
)

func bwRandom() []byte {
	bwRandomOnce.Do(func() {
		bwRandomBlock = make([]byte, bwRandomBlockSize)
		if _, err := rand.Read(bwRandomBlock); err != nil {
			for i := range bwRandomBlock {
				bwRandomBlock[i] = byte(i*131 + i>>8)
			}
		}
	})
	return bwRandomBlock
}

// GET /api/bandwidth/download?mb=N  (default 50, max 1024)
func bandwidthDownload(w http.ResponseWriter, r *http.Request) {
	mb := bwClampMB(r.URL.Query().Get("mb"))
	total := mb * 1024 * 1024

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(total))
	w.Header().Set("Cache-Control", "no-store, no-transform")
	w.Header().Set("Content-Encoding", "identity")

	block := bwRandom()
	start := time.Now()
	sent := 0
	completed := true
	for sent < total {
		n := len(block)
		if n > total-sent {
			n = total - sent
		}
		written, err := w.Write(block[:n])
		sent += written
		if err != nil {
			completed = false
			break
		}
	}
	seconds := time.Since(start).Seconds()
	bwLastMu.Lock()
	bwLastDownload = map[string]any{
		"sent_bytes":  sent,
		"seconds":     bwRound(seconds, 3),
		"mbps":        bwRound(bwMbps(int64(sent), seconds), 2),
		"completed":   completed,
		"remote_addr": r.RemoteAddr,
		"finished_at": time.Now().UTC().Format(time.RFC3339),
	}
	bwLastMu.Unlock()
}

// GET /api/bandwidth/last-download — the server-side rate of the most recent download.
func bandwidthLastDownload(w http.ResponseWriter, _ *http.Request) {
	bwLastMu.Lock()
	last := bwLastDownload
	bwLastMu.Unlock()
	if last == nil {
		writeJSONError(w, http.StatusNotFound, "no download has completed yet")
		return
	}
	writeJSON(w, http.StatusOK, last)
}

// POST /api/bandwidth/upload — ingress sink: drain the body, report throughput.
func bandwidthUpload(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	n, err := io.Copy(io.Discard, r.Body)
	_ = r.Body.Close()
	seconds := time.Since(start).Seconds()

	resp := map[string]any{
		"received_bytes": n,
		"seconds":        bwRound(seconds, 3),
		"mbps":           bwRound(bwMbps(n, seconds), 2),
		// The TCP peer seen by the Pod distinguishes direct Internet traffic
		// from an in-cluster Gateway hop. Forwarding headers are ignored
		// because clients can forge them.
		"remote_addr": r.RemoteAddr,
	}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/bandwidth/selftest?direction=ingress|egress&seconds=N
func bandwidthSelfTest(w http.ResponseWriter, r *http.Request) {
	direction := r.URL.Query().Get("direction")
	if direction != "ingress" && direction != "egress" {
		writeJSONError(w, http.StatusBadRequest, "direction must be ingress or egress")
		return
	}
	seconds := bwDefaultSeconds
	if s, err := strconv.Atoi(r.URL.Query().Get("seconds")); err == nil && s >= 5 {
		seconds = min(s, bwMaxSeconds)
	}
	if !bwSelfTestBusy.CompareAndSwap(false, true) {
		writeJSONError(w, http.StatusConflict, "a bandwidth self-test is already running")
		return
	}
	defer bwSelfTestBusy.Store(false)

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(seconds)*time.Second)
	defer cancel()

	var result bwSelfTestResult
	if direction == "ingress" {
		result = bwPull(ctx, seconds)
	} else {
		result = bwPush(ctx, seconds)
	}
	result.Direction = direction
	writeJSON(w, http.StatusOK, result)
}

type bwSelfTestResult struct {
	Direction     string    `json:"direction"`
	Target        string    `json:"target"`
	Seconds       float64   `json:"seconds"`
	TotalBytes    int64     `json:"total_bytes"`
	AverageMbps   float64   `json:"average_mbps"`
	SteadyMbps    float64   `json:"steady_mbps"`
	PerSecondMbps []float64 `json:"per_second_mbps"`
	Error         string    `json:"error,omitempty"`
}

type bwCountingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c bwCountingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

type bwRandomBody struct {
	ctx   context.Context
	limit int64
	sent  *atomic.Int64
}

func (b bwRandomBody) Read(p []byte) (int, error) {
	if b.ctx.Err() != nil {
		return 0, io.EOF
	}
	remaining := b.limit - b.sent.Load()
	if remaining <= 0 {
		return 0, io.EOF
	}
	block := bwRandom()
	n := copy(p, block[int(b.sent.Load()%int64(len(block))):])
	if int64(n) > remaining {
		n = int(remaining)
	}
	b.sent.Add(int64(n))
	return n, nil
}

func bwSample(ctx context.Context, counter *atomic.Int64, done <-chan struct{}) []float64 {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var samples []float64
	last := int64(0)
	for {
		select {
		case <-ticker.C:
			now := counter.Load()
			samples = append(samples, bwRound(float64(now-last)*8/1_000_000, 2))
			last = now
		case <-done:
			return samples
		case <-ctx.Done():
			return samples
		}
	}
}

func bwPull(ctx context.Context, seconds int) bwSelfTestResult {
	client := &http.Client{}
	var lastErr error
	for _, source := range bwPullSources {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept-Encoding", "identity")
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("%s returned %d", source, resp.StatusCode)
			continue
		}
		var counter atomic.Int64
		done := make(chan struct{})
		samplesCh := make(chan []float64, 1)
		go func() { samplesCh <- bwSample(ctx, &counter, done) }()
		_, copyErr := io.Copy(io.Discard, bwCountingReader{r: resp.Body, n: &counter})
		_ = resp.Body.Close()
		close(done)
		result := bwSummarise(source, counter.Load(), time.Since(start).Seconds(), <-samplesCh)
		if copyErr != nil && !errors.Is(copyErr, context.DeadlineExceeded) && ctx.Err() == nil {
			result.Error = copyErr.Error()
		}
		return result
	}
	return bwSelfTestResult{Error: fmt.Sprintf("no pull source reachable: %v", lastErr)}
}

func bwPush(ctx context.Context, seconds int) bwSelfTestResult {
	var counter atomic.Int64
	body := bwRandomBody{ctx: ctx, limit: bwPushLimitBytes, sent: &counter}
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), http.MethodPost, bwPushSink, body)
	if err != nil {
		return bwSelfTestResult{Target: bwPushSink, Error: err.Error()}
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	done := make(chan struct{})
	samplesCh := make(chan []float64, 1)
	go func() { samplesCh <- bwSample(ctx, &counter, done) }()
	start := time.Now()
	resp, err := (&http.Client{Timeout: time.Duration(seconds+30) * time.Second}).Do(req)
	elapsed := time.Since(start).Seconds()
	close(done)
	result := bwSummarise(bwPushSink, counter.Load(), elapsed, <-samplesCh)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		result.Error = fmt.Sprintf("sink returned %d", resp.StatusCode)
	}
	return result
}

func bwSummarise(target string, total int64, seconds float64, samples []float64) bwSelfTestResult {
	result := bwSelfTestResult{
		Target:        target,
		Seconds:       bwRound(seconds, 2),
		TotalBytes:    total,
		AverageMbps:   bwRound(bwMbps(total, seconds), 2),
		PerSecondMbps: samples,
	}
	steady := samples
	if len(steady) > bwWarmupSeconds+2 {
		steady = steady[bwWarmupSeconds : len(steady)-1]
	}
	if len(steady) > 0 {
		sorted := append([]float64(nil), steady...)
		sort.Float64s(sorted)
		result.SteadyMbps = sorted[len(sorted)/2]
	}
	return result
}

func bwMbps(bytes int64, seconds float64) float64 {
	if seconds <= 0 {
		return 0
	}
	return float64(bytes) * 8 / 1_000_000 / seconds
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
