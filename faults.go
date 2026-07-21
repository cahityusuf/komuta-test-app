package main

import (
	"sync"
	"time"
)

// faultRule holds either a latency or an error injection scoped to a
// specific endpoint pattern (mux key — e.g. "POST /api/checkout") or
// the wildcard "*" which applies to every business endpoint. The two
// types are stored separately so the operator can stack them (slow AND
// failing) on the same target.
type faultRule struct {
	pattern string
	addLat  time.Duration // 0 if not a latency rule
	errCode int           // 0 if not an error rule
	errRate float64       // 0..1
	expires time.Time     // zero ⇒ never expires
}

var (
	faultMu      sync.RWMutex
	latencyRules = map[string]*faultRule{} // key = pattern
	errorRules   = map[string]*faultRule{} // key = pattern
)

// setLatencyInjection adds (or replaces) the latency rule for `pattern`.
// `pattern` is the mux key, or "*" to apply to every business endpoint.
// `duration` is how long the rule stays active; 0 means until manually
// cleared.
func setLatencyInjection(pattern string, addLat time.Duration, duration time.Duration) {
	rule := &faultRule{pattern: pattern, addLat: addLat}
	if duration > 0 {
		rule.expires = time.Now().Add(duration)
	}
	faultMu.Lock()
	latencyRules[pattern] = rule
	faultMu.Unlock()
}

// setErrorInjection adds (or replaces) the error rule for `pattern`.
// `rate` is 0..1 — the probability of returning the configured `status`
// instead of the real handler body. `duration` works the same as in
// setLatencyInjection.
func setErrorInjection(pattern string, rate float64, status int, duration time.Duration) {
	if rate <= 0 || status <= 0 {
		return
	}
	if rate > 1 {
		rate = 1
	}
	rule := &faultRule{pattern: pattern, errRate: rate, errCode: status}
	if duration > 0 {
		rule.expires = time.Now().Add(duration)
	}
	faultMu.Lock()
	errorRules[pattern] = rule
	faultMu.Unlock()
}

// clearFaults removes every active rule. Used by the UI's "Clear all"
// button and by tests that need a known-good baseline between runs.
func clearFaults() {
	faultMu.Lock()
	latencyRules = map[string]*faultRule{}
	errorRules = map[string]*faultRule{}
	faultMu.Unlock()
}

// injectedLatency returns the additional sleep to apply for `pattern`,
// taking the wildcard rule into account when present. Expired rules are
// pruned lazily here so the next request after expiry sees clean state.
func injectedLatency(pattern string) time.Duration {
	faultMu.RLock()
	r := latencyRules[pattern]
	wild := latencyRules["*"]
	faultMu.RUnlock()

	var total time.Duration
	if r != nil && !ruleExpired(r) {
		total += r.addLat
	} else if r != nil {
		pruneRule(latencyRules, pattern)
	}
	if wild != nil && !ruleExpired(wild) {
		total += wild.addLat
	} else if wild != nil {
		pruneRule(latencyRules, "*")
	}
	return total
}

// injectedError returns the status to fail with for `pattern`, or 0 if
// no error rule fires this call. Wildcard rule wins when both are set
// (operator's intent is "fail everything"); expired rules are pruned.
func injectedError(pattern string) int {
	faultMu.RLock()
	r := errorRules[pattern]
	wild := errorRules["*"]
	faultMu.RUnlock()

	if wild != nil {
		if !ruleExpired(wild) {
			if randFloat() < wild.errRate {
				return wild.errCode
			}
		} else {
			pruneRule(errorRules, "*")
		}
	}
	if r != nil {
		if !ruleExpired(r) {
			if randFloat() < r.errRate {
				return r.errCode
			}
		} else {
			pruneRule(errorRules, pattern)
		}
	}
	return 0
}

// snapshotFaults returns a JSON-friendly view of the active rules for
// the UI's "current state" panel.
func snapshotFaults() map[string]any {
	faultMu.RLock()
	defer faultMu.RUnlock()
	lats := make([]map[string]any, 0, len(latencyRules))
	for _, r := range latencyRules {
		if ruleExpired(r) {
			continue
		}
		lats = append(lats, ruleToMap(r))
	}
	errs := make([]map[string]any, 0, len(errorRules))
	for _, r := range errorRules {
		if ruleExpired(r) {
			continue
		}
		errs = append(errs, ruleToMap(r))
	}
	return map[string]any{"latency": lats, "errors": errs}
}

func ruleExpired(r *faultRule) bool {
	return !r.expires.IsZero() && time.Now().After(r.expires)
}

func pruneRule(m map[string]*faultRule, key string) {
	faultMu.Lock()
	delete(m, key)
	faultMu.Unlock()
}

func ruleToMap(r *faultRule) map[string]any {
	m := map[string]any{"pattern": r.pattern}
	if r.addLat > 0 {
		m["addMs"] = r.addLat.Milliseconds()
	}
	if r.errCode > 0 {
		m["status"] = r.errCode
		m["rate"] = r.errRate
	}
	if !r.expires.IsZero() {
		m["expiresAt"] = r.expires.UTC().Format(time.RFC3339)
	}
	return m
}

// randFloat is a tiny indirection so tests can swap it out if we ever
// want deterministic injection. Right now it's just rand.Float64.
func randFloat() float64 {
	return globalRand.Float64()
}
