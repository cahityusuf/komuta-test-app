package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Scenario control plane — the surface the side-by-side functional
// test loop drives:
//
//	GET  /control/scenarios            full catalog + last-run status
//	POST /control/scenarios/{id}/run   run one scenario, return result
//	GET  /control/scenarios/{id}       single scenario + last run
//	GET  /control/ingest-status        M2M wiring health
//
// Scenarios with NeedsM2M=true short-circuit with a clear "configure
// these env vars" message instead of a confusing 401 when the
// operator hasn't wired the client_credentials env.

func registerScenarioRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /control/scenarios", scenarioCatalog)
	mux.HandleFunc("GET /control/scenarios/{id}", scenarioOne)
	mux.HandleFunc("POST /control/scenarios/{id}/run", scenarioRunHandler)
	mux.HandleFunc("GET /control/ingest-status", ingestStatus)
	mux.HandleFunc("GET /control/i18n", controlI18n)
}

type scenarioView struct {
	scenario
	// I18n carries the localized name + plain-language purpose/impact/
	// threat overlay for the catalogue endpoint. Nil on the internal
	// run/one views — those keep the raw English test contract that the
	// side-by-side test loop walks unchanged.
	I18n    *scenarioI18n `json:"i18n,omitempty"`
	LastRun *scenarioRun  `json:"lastRun,omitempty"`
}

func viewFor(s scenario) scenarioView {
	return scenarioView{scenario: s, LastRun: getLastRun(s.ID)}
}

// localizedViewFor adds the localized overlay for the requested locale.
func localizedViewFor(s scenario, loc string) scenarioView {
	v := viewFor(s)
	txt := scenarioText(loc, s.ID)
	v.I18n = &txt
	return v
}

func scenarioCatalog(w http.ResponseWriter, r *http.Request) {
	loc := resolveLocale(r)
	views := make([]scenarioView, 0, len(scenarioList))
	for _, s := range scenarioList {
		views = append(views, localizedViewFor(s, loc))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scenarios":     views,
		"ingestReady":   ingestTokens.configured(),
		"missingEnv":    ingestTokens.missingConfig(),
		"serviceId":     serviceID(),
		"version":       AppVersion,
		"locale":        loc,
		"defaultLocale": DefaultLocale,
		"locales":       []string{"tr", "en"},
		// techniqueLabels lets the console render localized attack-technique
		// facet chips (technique → {tr,en}) without hard-coding them
		// client-side. Keyed by the technique enum value on each scenario.
		"techniqueLabels": techniqueLabels,
	})
}

// controlI18n serves the console UI string bundle for the request's
// locale (?lang= → Accept-Language → tr) with English per-key fallback
// merged in, plus locale metadata for the TR/EN switch.
func controlI18n(w http.ResponseWriter, r *http.Request) {
	loc := resolveLocale(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"locale":  loc,
		"default": DefaultLocale,
		"locales": []string{"tr", "en"},
		"ui":      uiStrings(loc),
	})
}

func scenarioOne(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, s := range scenarioList {
		if s.ID == id {
			writeJSON(w, http.StatusOK, viewFor(s))
			return
		}
	}
	writeJSONError(w, http.StatusNotFound, "unknown scenario: "+id)
}

func scenarioRunHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var target *scenario
	for i := range scenarioList {
		if scenarioList[i].ID == id {
			target = &scenarioList[i]
			break
		}
	}
	if target == nil {
		writeJSONError(w, http.StatusNotFound, "unknown scenario: "+id)
		return
	}

	// Drain any body so keep-alive stays clean (params are optional).
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<16))

	if target.NeedsM2M && !ingestTokens.configured() {
		res := map[string]any{
			"skipped":    true,
			"reason":     "M2M ingest not configured",
			"missingEnv": ingestTokens.missingConfig(),
		}
		recordRun(id, time.Now(), res, false)
		writeJSON(w, http.StatusOK, viewFor(*target))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	started := time.Now()
	result := safeRun(ctx, target)
	ok := runLooksOK(result)
	recordRun(id, started, result, ok)
	writeJSON(w, http.StatusOK, viewFor(*target))
}

// safeRun isolates a panicking scenario so one bad trigger can't take
// the harness down mid test loop.
func safeRun(ctx context.Context, s *scenario) (result any) {
	defer func() {
		if rec := recover(); rec != nil {
			result = map[string]any{"panic": fmt.Sprintf("%v", rec)}
		}
	}()
	return s.run(ctx)
}

// runLooksOK is a best-effort heuristic for the UI's green/red dot.
// Native triggers: any outcome (allowed OR denied) is a valid signal.
// Ingest scenarios: fail only on transport/HTTP error or explicit
// "error"/"skipped" keys.
func runLooksOK(result any) bool {
	switch v := result.(type) {
	case ingestResult:
		return v.Err == "" && v.HTTPStatus > 0 && v.HTTPStatus < 400
	case triggerOutcome:
		return true
	case map[string]any:
		if _, bad := v["error"]; bad {
			return false
		}
		if _, bad := v["panic"]; bad {
			return false
		}
		if skipped, ok := v["skipped"].(bool); ok && skipped {
			return false
		}
		return true
	default:
		return true
	}
}

func ingestStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": ingestTokens.configured(),
		"missingEnv": ingestTokens.missingConfig(),
		"apiBase":    ingestTokens.cfg.APIBase,
		"clusterId":  ingestTokens.cfg.ClusterID,
		"serviceId":  serviceID(),
	})
}

// fanOutPaths drives the path-clustering scenario: many distinct
// high-cardinality paths so the backend's clustering has something to
// collapse. Self-directed against localhost like the traffic gen.
func fanOutPaths(p string) map[string]any {
	client := tracedHTTPClient(5*time.Second, nil)
	base := "http://127.0.0.1:" + p
	sent := 0
	for i := 0; i < 30; i++ {
		for _, path := range []string{
			fmt.Sprintf("/api/search?q=%s-%d", newUUID()[:6], i),
			fmt.Sprintf("/api/items/item-%d", 1000+i),
		} {
			req, err := http.NewRequest(http.MethodGet, base+path, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			sent++
		}
	}
	return map[string]any{"pathsFired": sent, "distinctTemplates": 2}
}
