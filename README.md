# komuta-test-app

Single-binary harness for exercising **Komuta.io**'s Insights and Security
surfaces against realistic-looking traffic and on-demand fault / violation
triggers.

Drop it on a cluster, point Komuta at the service, then use the embedded
control panel at `/` to:

- generate synthetic L7 traffic (variable RPS, weighted endpoint mix)
- inject latency on a specific endpoint (or `*` for all)
- inject 4xx / 5xx errors at a controllable rate
- trip KubeArmor / AppArmor policies on demand (exec shell, read
  `/etc/shadow`, install a tool, tamper `/etc`, egress to the public
  internet)
- deploy under different image tags (`v1.0`, `v1.1-bug`, `v1.2-fix`) to
  watch the **Insights → Etki** tab classify deploys as
  `regressed` / `improved` / `stable` from the same image.

## Endpoints

### Business surface (the things real traffic hits)

| Method | Path | Baseline latency | Notes |
|---|---|---|---|
| GET | `/api/items` | ~20ms | Fast list, never fails |
| GET | `/api/items/{id}` | ~25ms | 5% chance of 404 |
| POST | `/api/items` | ~55ms | 3% chance of 422 |
| PUT | `/api/items/{id}` | ~47ms | 2% chance of 404 |
| DELETE | `/api/items/{id}` | ~27ms | 1% chance of 404 |
| GET | `/api/checkout` | ~320ms | High latency tail |
| POST | `/api/checkout` | ~820ms | Highest latency tail; 1% baseline 502 |
| GET | `/api/search?q=…` | variable | Latency scales with `q` length |
| GET | `/api/users/me` | ~14ms | Always 200 |
| GET | `/api/admin/users` | ~40ms | Low-volume admin path |

### Control plane (`/control/*`)

| Method | Path | Body |
|---|---|---|
| POST | `/control/inject-latency` | `{"pattern":"POST /api/checkout","ms":500,"durationSec":300}` |
| POST | `/control/inject-errors` | `{"pattern":"GET /api/items","rate":0.3,"status":500,"durationSec":120}` |
| POST | `/control/clear-faults` | — |
| POST | `/control/start-traffic` | `{"rps":50,"durationSec":600}` |
| POST | `/control/stop-traffic` | — |
| GET | `/control/state` | — current rules + traffic generator status |
| POST | `/control/ddos/stop` | stop a running DDoS flood (see below) |
| GET | `/control/ddos/status` | DDoS flood status |

### Security violation triggers (`/control/security/*`)

Each is a single, opt-in `POST` that attempts one isolated syscall
pattern. Always returns `200` with `{verdict: "allowed" | "denied"}`.
`denied` means a cluster policy IS enforced — both outcomes are valid
test signal.

- `exec-shell` — spawns `sh -c "id; uname -a"`
- `read-secret` — reads `/etc/shadow`
- `install-tool` — invokes the package manager (`apk` / `apt-get` / `dnf`)
- `file-tamper` — writes to `/etc/passwd.injected`
- `network-egress` — HTTP GET to `example.com`
- `honey-path` — `open()` the Security Center honey path (`HONEY_PATH` env)
- `dns-exfil` — resolves a `*.attacker-c2.example` look-alike host
- `capability-use` — `chown(/etc/hostname,0,0)` (CAP_CHOWN)
- `mount-attempt` — `mount -t tmpfs none /mnt`
- `attack-chain` — ordered exec → capability → secret → egress kill chain

### DDoS flood test (`/control/ddos/*`)

A sustained fresh-connection HTTP flood that produces enough **real Hubble
flow** to trip Komuta's DDoS detector (`DdosFlowToIncidentProjector`). The
detector keys on `(source_ip, destination_identity, port, protocol)` over a
rolling 10-min window (`komuta.l4_traffic_5m`, request-side, pre-sampling)
and raises when `flow_count > 10000`. Every **new TCP connection is one
flow**, so keep-alive is OFF (`DisableKeepAlives` + `Connection: close`) and
every request forces a fresh handshake.

**Sizing:** >10000 flows in 10 min needs ≥17 conn/s. The default of ~50
conn/s for ~12 min (**≈36000 flows**) clears the threshold with margin. The
flood runs in the background on its own context (the scenario handler
returns immediately) and stops automatically at its duration cap (12 min
default, 30 min hard cap) or when stopped.

Two scenarios drive it (run from the console or
`POST /control/scenarios/{id}/run`):

- `sec-ddos-flood-self` — **default.** Target auto-resolves:
  `DDOS_TARGET` → `<svc>-stable.<ns>.svc.cluster.local:8080` (derived from a
  service-name env + the pod namespace) → external world fallback. When it
  resolves to this tenant's own service the incident is stamped with this
  service's `service_id` (**attributed to the tenant**).
- `sec-ddos-flood-world` — floods an external host
  (`DDOS_WORLD_TARGET` → `DDOS_TARGET` → `1.1.1.1:80`) over the CNP
  world-egress path. Always works, but the incident is **cluster-scoped
  (unattributed)**.

The `run()` result reports exactly what was chosen:
`{"floodStarted":true,"target":…,"mode":"self-service|world","attribution":"tenant-service|cluster-scoped","connPerSec":…,"durationSec":…,"estFlows":…}`.

> **Attribution when redeploying under your own tenant:** this image is
> deploy-agnostic — nothing is hardcoded to `komuta-test-app`. For a
> **tenant-attributed** incident, set `DDOS_TARGET=<your-stable-clusterip-dns>:8080`
> (or `DDOS_SELF_SERVICE=<your-service-name>` + `POD_NAMESPACE`). If none
> resolves, the flood falls back to **world mode** and produces a
> cluster-scoped incident instead — the fallback is logged so the "no
> attribution" reason is visible.

| Method | Path | Notes |
|---|---|---|
| POST | `/control/ddos/stop` | cancel a running flood immediately |
| GET | `/control/ddos/status` | `{running,target,mode,attribution,connPerSec,durationSec}` |

Optional env overrides (all have safe defaults):

| Env | Default | Purpose |
|---|---|---|
| `DDOS_TARGET` | — | `host:port` self-service override (highest priority) |
| `DDOS_SELF_SERVICE` | — | service name used to build `<svc>-stable.<ns>.svc:8080` |
| `POD_NAMESPACE` | SA namespace file | pod namespace for the derived self DNS |
| `DDOS_WORLD_TARGET` | `1.1.1.1:80` | `host:port` for the world scenario / fallback |
| `DDOS_CONN_PER_SEC` | `50` | fresh connections per second (capped at 200) |
| `DDOS_DURATION_SEC` | `720` | flood duration (capped at 1800) |
| `DDOS_PATH` | `/healthz` | small path each request hits |

**Verification:** the detector logs `[SC-PROJECTOR-DDOS] … raised=1` within
~2–4 min; a row appears in `AppNetworkIncidents` with
`Category=DDoSSuspected` / `Status=Open`, and `ServiceId` = this service
when running in self-service mode. Then stop via `/control/ddos/stop` or the
`sec-ddos-stop` scenario.

### Scenario console (`/control/scenarios/*`) — the test contract

The embedded UI at `/` is now a scenario console. Every Security
Center / Insights capability has exactly one scenario: what the
harness does, what Komuta should do, and **where in Komuta.UI to
verify it**. Categories:

- `insights` (5) — L7 baseline, latency regression, 5xx burn, path
  clustering, deploy-impact
- `security-native` — the cluster-native triggers above, wrapped
  with expected-result + UI-location metadata, plus the DDoS flood
  scenarios (`sec-ddos-flood-self` / `sec-ddos-flood-world` /
  `sec-ddos-stop`) that trip the DDoS detector with real Hubble flow
- `security-ingest` (6, **M2M**) — synthetic runtime NDJSON
  (Tetragon/KubeArmor/Hubble), KubeArmor observations→finding,
  collector decay, synthetic-attack trigger
- `supply-chain` (4, **M2M**) — Tekton build-artifact ingest
  (SBOM / scan / signature / failure → WORM 40-43)

| Method | Path | Notes |
|---|---|---|
| GET | `/control/scenarios` | full catalog + last-run status + ingest wiring; localized (`?lang=tr\|en`) — adds `engine` + `i18n{name,purpose,impact,threat}` per scenario |
| GET | `/control/scenarios/{id}` | one scenario + its last run |
| POST | `/control/scenarios/{id}/run` | run it; returns last-run result |
| GET | `/control/ingest-status` | M2M wiring health |
| GET | `/control/i18n` | console UI string bundle for the locale |

### Engine split & localization

Every security scenario is tagged with the **runtime engine whose job
it is to catch it** (`engine`: `KubeArmor` = LSM policy enforcement /
*block*, `Tetragon` = eBPF runtime observability / *detect*, `Hubble` =
flow visibility, `Mixed` = multi-stage chain). The console badges each
card so the Tetragon-vs-KubeArmor split is obvious at a glance. The
mapping is a single auditable table in `scenarios.go` (`scenarioEngine`)
— catalogue literals are untouched.

The console is **bilingual — Turkish (default)** and English. Locale
resolves `?lang=tr|en` → `Accept-Language` → `tr` (single source of
truth: `DefaultLocale` in `i18n.go`). The header has a TR/EN switch
(persisted in `localStorage`). Each scenario card shows a plain-language
**Maksat / Etki / Neden tehdit?** (Purpose / Impact / Why-a-threat)
overlay aimed at a non-technical operator; the English
`Does / Expected / Verify-in-Komuta` technical test contract is kept
verbatim under a collapsible `details`. Localized copy lives in
`i18n/{tr,en}.json` (`scenario.<id>` + `ui.*`), never in code.

### M2M ingest config (category-b scenarios)

`security-ingest` + `supply-chain` scenarios POST synthetic payloads
to the real backend ingest endpoints, so the harness needs a
machine token (OAuth2 `client_credentials`, same as the cluster's
`komuta-security-agent`). Set via env — when unset these scenarios
**skip cleanly** with a "configure these env vars" message; the
cluster-native + Insights scenarios still work without any of it.

| Env | Purpose |
|---|---|
| `KOMUTA_AUTH_URL` | e.g. `https://auth.komuta.io` |
| `KOMUTA_API_BASE` | e.g. `https://komuta-api-xxxx.edge-4.komuta.app` |
| `KOMUTA_CLIENT_ID` | OAuth client — for runtime ingest MUST be the cluster's security-agent client (backend resolves cluster from `client_id`) |
| `KOMUTA_CLIENT_SECRET` | client secret |
| `KOMUTA_CLUSTER_ID` | cluster UUID — sent as `X-Cluster-Id` |
| `KOMUTA_SERVICE_ID` | this app's ProjectRepoService id — targets observations / synthetic-attacks |
| `KOMUTA_SCOPE` | optional, default `DevOpsZon` |
| `HONEY_PATH` | optional, overrides the honey-path trigger target |
| `SYNTHETIC_SCENARIO_ID` | optional, synthetic-attack scenario id |

### Health

- `GET /healthz` — liveness
- `GET /readyz` — readiness + version + uptime + goroutine count

## `APP_VERSION` presets

The startup banner reads `APP_VERSION` (env). Suffix-based behaviour:

| Tag suffix | Baseline behaviour |
|---|---|
| `*-bug` | `POST /api/checkout` returns `500` on ~30% of requests |
| `*-slow` | every business endpoint adds +200ms latency |
| anything else | clean baseline |

This lets a single image demo deploy-impact: deploy `v1.0` (clean),
then `v1.1-bug` (regression), then `v1.2-fix` (recovery) — Insights
should classify them as `stable` → `regressed` → `improved` in
sequence.

## Local run

```bash
go run .
# open http://localhost:8080
```

## Build the container

```bash
docker build -t komuta-test-app:dev .
docker run --rm -p 8080:8080 -e APP_VERSION=v1.0-clean komuta-test-app:dev
```

## Deploy to Komuta

1. Push the image to a registry the cluster can pull (or use Komuta's
   own pipeline by pointing at this repo).
2. From the Komuta service form: set port `8080`, attach to a cluster,
   add `APP_VERSION` as an env var.
3. Open the service → **Insights → Etki** to see the deploy show up
   in the timeline once the first pipeline run completes.

A reference standalone manifest is in [`deploy/komuta-service.yaml`](deploy/komuta-service.yaml).

### Runtime acceptance observation

Run `/app --runtime-acceptance-probe` inside the application container to emit one
JSON observation of its own process security fields and the LSM-specific AppArmor
profile. This mode starts no server, telemetry exporter, token manager or security
trigger. It reads only fixed procfs paths and exposes no environment or file contents
outside that allowlist. Missing profile data is reported explicitly; the output is
not an enforcement/DENY test or a product-readiness verdict.

## Layout

```
.
├── main.go              # bootstrap, mux, embed
├── handlers_health.go   # /healthz, /readyz
├── handlers_api.go      # business endpoints + per-endpoint profiles
├── handlers_control.go  # /control/* fault & traffic endpoints
├── faults.go            # injection state, thread-safe rule store
├── traffic.go           # synthetic traffic generator
├── security.go          # cluster-native syscall/network triggers
├── ddos.go              # sustained fresh-connection DDoS flood generator
├── auth.go              # OAuth2 client_credentials M2M token manager
├── ingest.go            # synthetic NDJSON/JSON ingest builders + POST
├── scenarios.go         # the scenario catalog (= the test contract)
│                        #   + engine map (Tetragon/KubeArmor split)
├── handlers_scenario.go # /control/scenarios (localized) + /control/i18n
├── i18n.go              # embedded tr/en bundles, tr = default locale
├── i18n/{tr,en}.json    # ui + per-scenario name/purpose/impact/threat
├── ui/index.html        # embedded scenario console (TR/EN switch)
├── deploy/              # sample k8s manifests
└── Dockerfile           # multi-stage Go → alpine runtime
```

The server also emits the same bounded observation once at startup with
`processRole=main-server`. CLI observations use `processRole=diagnostic-exec`;
these are separate processes and must not be treated as interchangeable security
evidence. Neither observation proves a DENY policy test passed.
