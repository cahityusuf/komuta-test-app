package main

import (
	"context"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// trafficWorker drives synthetic load against this same process by
// hitting localhost:$PORT — keeps the generator self-contained so the
// only thing the operator deploys is this one container.
type trafficGenState struct {
	mu        sync.Mutex
	cancel    context.CancelFunc
	startedAt time.Time
	cfg       trafficCfg
}

type trafficCfg struct {
	RPS         int      `json:"rps"`
	DurationSec int      `json:"durationSec"` // 0 = until stopped
	Endpoints   []string `json:"endpoints"`   // empty = all business endpoints
}

var (
	trafficState = &trafficGenState{}
	globalRand   = rand.New(rand.NewSource(time.Now().UnixNano()))

	// Endpoints used when the operator doesn't pick a subset. Weighted
	// duplicates (more entries = more traffic share) so the generated
	// distribution looks like a real e-commerce service: lots of
	// item reads, fewer checkouts, occasional admin pokes.
	defaultTrafficMix = []string{
		"GET /api/items",
		"GET /api/items",
		"GET /api/items",
		"GET /api/items/42",
		"GET /api/items/99",
		"POST /api/items",
		"PUT /api/items/42",
		"GET /api/checkout",
		"POST /api/checkout",
		"GET /api/search?q=shoes",
		"GET /api/search?q=organic",
		"GET /api/users/me",
		"GET /api/admin/users",
	}
)

// startTrafficGenerator spins up a worker that fires `cfg.RPS` requests
// per second against the listed endpoints. Calling it again replaces
// the running generator so the operator can dial RPS up/down without a
// stop-then-start dance.
func startTrafficGenerator(cfg trafficCfg, port string) {
	trafficState.mu.Lock()
	defer trafficState.mu.Unlock()

	if trafficState.cancel != nil {
		trafficState.cancel()
	}

	if cfg.RPS <= 0 {
		cfg.RPS = 10
	}
	if cfg.RPS > 500 {
		cfg.RPS = 500 // safety: we ARE hitting ourselves
	}
	mix := cfg.Endpoints
	if len(mix) == 0 {
		mix = defaultTrafficMix
	}

	ctx, cancel := context.WithCancel(context.Background())
	if cfg.DurationSec > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.DurationSec)*time.Second)
	}
	trafficState.cancel = cancel
	trafficState.startedAt = time.Now()
	trafficState.cfg = cfg

	go runTrafficWorkers(ctx, cfg.RPS, mix, port)
}

// stopTrafficGenerator cancels the running worker if any. Called both
// from the UI's stop button and from main.go on SIGTERM so the goroutine
// doesn't outlive the process (defensive — http.Server.Shutdown would
// kill in-flight requests anyway, but explicit is friendlier).
func stopTrafficGenerator() {
	trafficState.mu.Lock()
	defer trafficState.mu.Unlock()
	if trafficState.cancel != nil {
		trafficState.cancel()
		trafficState.cancel = nil
	}
}

// snapshotTraffic returns the generator state for the UI status panel.
func snapshotTraffic() map[string]any {
	trafficState.mu.Lock()
	defer trafficState.mu.Unlock()
	if trafficState.cancel == nil {
		return map[string]any{"running": false}
	}
	return map[string]any{
		"running":     true,
		"startedAt":   trafficState.startedAt.UTC().Format(time.RFC3339),
		"rps":         trafficState.cfg.RPS,
		"durationSec": trafficState.cfg.DurationSec,
		"endpoints":   trafficState.cfg.Endpoints,
	}
}

func runTrafficWorkers(ctx context.Context, rps int, mix []string, port string) {
	// One ticker, N workers — the ticker decides cadence, workers
	// fan out the actual HTTP calls so a slow endpoint can't stall
	// the whole train.
	interval := time.Second / time.Duration(rps)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()

	client := &http.Client{Timeout: 10 * time.Second}
	jobs := make(chan string, 256)

	workerCount := minInt(rps, 32)
	if workerCount < 4 {
		workerCount = 4
	}
	for i := 0; i < workerCount; i++ {
		go func() {
			for endpoint := range jobs {
				fireOne(client, port, endpoint)
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			close(jobs)
			return
		case <-tick.C:
			endpoint := mix[globalRand.Intn(len(mix))]
			select {
			case jobs <- endpoint:
			default:
				// Channel full — drop instead of building backlog.
				// Prevents a slow downstream from spiraling into OOM.
			}
		}
	}
}

func fireOne(client *http.Client, port, endpoint string) {
	method, path, found := strings.Cut(endpoint, " ")
	if !found {
		method = "GET"
		path = endpoint
	}
	req, err := http.NewRequest(method, "http://127.0.0.1:"+port+path, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	// Drain & close so the underlying TCP connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
