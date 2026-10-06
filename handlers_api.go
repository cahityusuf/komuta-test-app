package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Each endpoint pairs a baseline latency profile with an error chance so
// that, with no faults injected, the service produces a believable mix
// of fast/slow + 2xx/4xx/5xx traffic. Numbers are in milliseconds.
type endpointProfile struct {
	baseMs    int
	jitterMs  int
	errChance float64 // 0.0 .. 1.0
	errStatus int
}

var apiProfiles = map[string]endpointProfile{
	"GET /api/items":         {baseMs: 8, jitterMs: 12, errChance: 0.00},
	"GET /api/items/{id}":    {baseMs: 10, jitterMs: 15, errChance: 0.05, errStatus: http.StatusNotFound},
	"POST /api/items":        {baseMs: 25, jitterMs: 30, errChance: 0.03, errStatus: http.StatusUnprocessableEntity},
	"PUT /api/items/{id}":    {baseMs: 22, jitterMs: 25, errChance: 0.02, errStatus: http.StatusNotFound},
	"DELETE /api/items/{id}": {baseMs: 12, jitterMs: 15, errChance: 0.01, errStatus: http.StatusNotFound},
	"GET /api/checkout":      {baseMs: 120, jitterMs: 200, errChance: 0.00},
	"POST /api/checkout":     {baseMs: 220, jitterMs: 600, errChance: 0.01, errStatus: http.StatusBadGateway},
	"GET /api/search":        {baseMs: 30, jitterMs: 80, errChance: 0.00},
	"GET /api/users/me":      {baseMs: 6, jitterMs: 8, errChance: 0.00},
	"GET /api/admin/users":   {baseMs: 18, jitterMs: 22, errChance: 0.00},
}

func registerAPIRoutes(mux *http.ServeMux) {
	// Each handler pulls its profile by the same string the mux pattern
	// uses, so adding an endpoint stays a one-line change in apiProfiles
	// + one mux line here.
	mux.HandleFunc("GET /api/items", apiHandler("GET /api/items", listItems))
	mux.HandleFunc("GET /api/items/{id}", apiHandler("GET /api/items/{id}", getItem))
	mux.HandleFunc("POST /api/items", apiHandler("POST /api/items", createItem))
	mux.HandleFunc("PUT /api/items/{id}", apiHandler("PUT /api/items/{id}", updateItem))
	mux.HandleFunc("DELETE /api/items/{id}", apiHandler("DELETE /api/items/{id}", deleteItem))
	mux.HandleFunc("GET /api/checkout", apiHandler("GET /api/checkout", checkoutSummary))
	mux.HandleFunc("POST /api/checkout", apiHandler("POST /api/checkout", checkoutSubmit))
	mux.HandleFunc("GET /api/search", apiHandler("GET /api/search", search))
	mux.HandleFunc("GET /api/users/me", apiHandler("GET /api/users/me", whoami))
	mux.HandleFunc("GET /api/admin/users", apiHandler("GET /api/admin/users", listUsers))
	mux.HandleFunc("GET /api/identity", identityHandler(newIdentityKeySet()))
}

// apiHandler wraps a business handler with:
//  1. injected latency (per-endpoint or wildcard "*")
//  2. injected errors (returns the configured status before the body runs)
//  3. baseline latency / jitter / random error from the endpoint profile
//
// Pattern is the mux key, used to look up both the profile and the
// injection rule, so a single string identifies an endpoint everywhere.
func apiHandler(pattern string, fn http.HandlerFunc) http.HandlerFunc {
	profile := apiProfiles[pattern]
	return func(w http.ResponseWriter, r *http.Request) {
		// Injected latency wins over baseline — both stack additively if
		// the operator wanted to amplify a slow endpoint further.
		if d := injectedLatency(pattern); d > 0 {
			time.Sleep(d)
		}
		baseline := time.Duration(profile.baseMs)*time.Millisecond +
			time.Duration(rand.Intn(maxInt(1, profile.jitterMs)))*time.Millisecond
		time.Sleep(baseline)

		if status := injectedError(pattern); status > 0 {
			writeJSONError(w, status, "fault-injected error")
			return
		}
		if profile.errChance > 0 && rand.Float64() < profile.errChance {
			writeJSONError(w, profile.errStatus, "baseline error")
			return
		}

		fn(w, r)
	}
}

// ── Business handlers ────────────────────────────────────────────────────

func listItems(w http.ResponseWriter, _ *http.Request) {
	items := make([]map[string]any, 0, 20)
	for i := 0; i < 20; i++ {
		items = append(items, map[string]any{
			"id":    fmt.Sprintf("item-%03d", i+1),
			"name":  fmt.Sprintf("Item %d", i+1),
			"price": 10 + i*3,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

func getItem(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, map[string]any{
		"id":    id,
		"name":  "Item " + id,
		"price": 10 + (len(id)*3)%100,
	})
}

func createItem(w http.ResponseWriter, _ *http.Request) {
	id := fmt.Sprintf("item-new-%d", time.Now().UnixNano()%1000)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "created": true})
}

func updateItem(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"id": r.PathValue("id"), "updated": true})
}

func deleteItem(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func checkoutSummary(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"cart":     3,
		"subtotal": 120.50,
		"shipping": 9.99,
		"tax":      21.69,
		"total":    152.18,
		"currency": "TRY",
	})
}

func checkoutSubmit(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"orderId": fmt.Sprintf("ord-%d", time.Now().UnixNano()),
		"placed":  time.Now().UTC().Format(time.RFC3339),
	})
}

// search burns variable CPU based on query length so longer queries
// produce naturally longer latency tails — handy for showing the
// quantile chart's p99 separating from p50.
func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		q = "default"
	}
	// 5..30ms extra per character (capped) — cheap fake "scoring" loop.
	extra := minInt(len(q), 30) * (5 + rand.Intn(5))
	time.Sleep(time.Duration(extra) * time.Millisecond)

	results := []map[string]any{}
	for i := 0; i < 5; i++ {
		results = append(results, map[string]any{
			"id":    fmt.Sprintf("hit-%d", i+1),
			"score": 0.95 - float64(i)*0.07,
			"title": strings.Title(q) + " result " + strconv.Itoa(i+1),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"q": q, "hits": results})
}

func whoami(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"id":    "u-001",
		"email": "demo@komuta.test",
		"roles": []string{"user"},
	})
}

func listUsers(w http.ResponseWriter, _ *http.Request) {
	users := []map[string]any{
		{"id": "u-001", "email": "demo@komuta.test", "roles": []string{"user"}},
		{"id": "u-002", "email": "ops@komuta.test", "roles": []string{"user", "admin"}},
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

// ── Helpers ──────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg, "status": status})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
