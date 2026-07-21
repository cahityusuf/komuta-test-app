package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// The scenario catalog IS the functional test contract. Every
// Security Center / Insights capability we ship has exactly one
// scenario here: what the harness does, what Komuta should do in
// response, and precisely where in Komuta.UI to verify it. The
// side-by-side test loop walks this list top to bottom.

type scenarioCategory string

const (
	catInsights  scenarioCategory = "insights"
	catSecNative scenarioCategory = "security-native" // (a) real syscalls -> cluster agent
	catSecIngest scenarioCategory = "security-ingest" // (b) direct synthetic ingest (M2M)
	catSupplyChn scenarioCategory = "supply-chain"    // (b) Tekton build-artifact ingest
)

type scenario struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Category scenarioCategory `json:"category"`
	// Engine is the runtime security engine whose job it is to catch
	// this scenario. Lets the console group/badge security scenarios by
	// "is this Tetragon's job or KubeArmor's job" — see
	// assignEnginesAndTechniques(). Empty for non-engine scenarios
	// (insights, supply-chain, collector lifecycle). Set centrally in
	// assignEnginesAndTechniques(), NOT in every literal, so the
	// catalogue authoring stays unchanged and the mapping stays
	// auditable in one place.
	Engine secEngine `json:"engine"`
	// Technique is the attack-technique facet the operator filters the
	// matrix by (exec / file-read / file-write / network / capability /
	// dns / mount / chain). Like Engine it is stamped centrally from
	// scenarioTechnique in assignEnginesAndTechniques(), NOT in the
	// literals, so the catalogue authoring stays clean and the mapping is
	// auditable in one block. Empty for non-native scenarios (insights,
	// ingest, supply-chain).
	Technique technique `json:"technique"`
	Desc      string    `json:"description"`
	Expected  string    `json:"expected"`
	KomutaUI  string    `json:"komutaUi"`
	NeedsM2M  bool      `json:"needsM2M"`
	run       func(ctx context.Context) any
}

// technique is the attack-technique facet used to group/filter the
// native attack matrix in the console. It is orthogonal to secEngine:
// engine answers "whose job is it to catch this" (KubeArmor/Tetragon/
// Hubble), technique answers "what kind of action is it".
type technique string

const (
	techExec       technique = "exec"
	techFileRead   technique = "file-read"
	techFileWrite  technique = "file-write"
	techNetwork    technique = "network"
	techCapability technique = "capability"
	techDNS        technique = "dns"
	techMount      technique = "mount"
	techChain      technique = "chain"
)

// techniqueLabels exposes localized (tr/en) display names for each
// technique facet so the console can render human-readable facet chips
// without hard-coding them client-side. Surfaced on /control/scenarios.
var techniqueLabels = map[technique]map[string]string{
	techExec:       {"tr": "Süreç çalıştırma", "en": "Process exec"},
	techFileRead:   {"tr": "Dosya okuma", "en": "File read"},
	techFileWrite:  {"tr": "Dosya yazma", "en": "File write"},
	techNetwork:    {"tr": "Ağ bağlantısı", "en": "Network connect"},
	techCapability: {"tr": "Ayrıcalık (capability)", "en": "Capability use"},
	techDNS:        {"tr": "DNS sorgusu", "en": "DNS lookup"},
	techMount:      {"tr": "Bağlama (mount)", "en": "Mount"},
	techChain:      {"tr": "Saldırı zinciri", "en": "Attack chain"},
}

// secEngine identifies which runtime engine owns detection/enforcement
// of a scenario. Used purely for grouping/badging in the console.
type secEngine string

const (
	engNone      secEngine = ""          // insights / supply-chain / lifecycle
	engKubeArmor secEngine = "KubeArmor" // LSM policy enforcement (block)
	engTetragon  secEngine = "Tetragon"  // eBPF runtime observability (detect)
	engHubble    secEngine = "Hubble"    // L3/L4/L7 flow visibility
	engMixed     secEngine = "Mixed"     // multi-stage chain spanning engines
)

// scenarioEngine maps scenario ID → owning engine. Single source of
// truth for the Tetragon-vs-KubeArmor split the operator asked for.
// Anything not listed stays engNone (no engine badge in the console).
var scenarioEngine = map[string]secEngine{
	// ── security-native: exec (KubeArmor process-exec rule) ──────────
	"sec-exec-shell":       engKubeArmor,
	"sec-exec-bash":        engKubeArmor,
	"sec-exec-kubectl":     engKubeArmor,
	"sec-exec-curl":        engKubeArmor,
	"sec-exec-wget":        engKubeArmor,
	"sec-exec-nc":          engKubeArmor,
	"sec-exec-socat":       engKubeArmor,
	"sec-exec-python":      engKubeArmor,
	"sec-exec-perl":        engKubeArmor,
	"sec-exec-nmap":        engKubeArmor,
	"sec-install-tool":     engKubeArmor,
	"sec-exec-base64":      engKubeArmor,
	"sec-exec-chmod":       engKubeArmor,
	"sec-exec-crontab":     engKubeArmor,
	"sec-exec-ssh":         engKubeArmor,
	"sec-exec-dropped-bin": engKubeArmor,
	// ── security-native: file-read (KubeArmor sensitive-file rule) ───
	"sec-read-secret":           engKubeArmor, // /etc/shadow
	"sec-read-passwd":           engKubeArmor,
	"sec-read-ssh-key":          engKubeArmor,
	"sec-read-sa-token":         engKubeArmor,
	"sec-read-proc-environ":     engKubeArmor,
	"sec-read-kubeconfig-admin": engKubeArmor,
	"sec-read-kubelet-conf":     engKubeArmor,
	"sec-read-aws-creds":        engKubeArmor,
	"sec-read-kube-config":      engKubeArmor,
	"sec-honey-path":            engTetragon, // deterministic honey-path TracingPolicy
	// ── security-native: file-write (KubeArmor write-outside-mounts) ─
	"sec-file-tamper":     engKubeArmor, // /etc/passwd.injected
	"sec-write-authkeys":  engKubeArmor,
	"sec-write-cron":      engKubeArmor,
	"sec-write-usrbin":    engKubeArmor,
	"sec-write-ldpreload": engKubeArmor,
	"sec-write-bashrc":    engKubeArmor,
	"sec-write-spoolcron": engKubeArmor,
	// ── security-native: network (Hubble/Cilium flow visibility) ─────
	"sec-network-egress": engHubble, // egress to example.com
	"sec-net-dns-tcp":    engHubble, // 1.1.1.1:53
	"sec-net-oddport":    engHubble, // 8.8.8.8:9999
	"sec-net-metadata":   engHubble, // 169.254.169.254:80 SSRF
	"sec-net-revshell":   engHubble, // :4444 reverse-shell port
	// ── security-native: DDoS flood (DdosFlowToIncidentProjector) ────
	"sec-ddos-flood-self":  engHubble, // flood own stable svc → tenant-attributed incident
	"sec-ddos-flood-world": engHubble, // flood external host → cluster-scoped incident
	// ── security-native: capability (KubeArmor capability rule) ──────
	"sec-capability-use":  engKubeArmor, // CAP_CHOWN
	"sec-cap-setuid":      engKubeArmor,
	"sec-cap-net-raw":     engKubeArmor,
	"sec-cap-ptrace":      engKubeArmor,
	"sec-cap-sethostname": engKubeArmor,
	"sec-cap-mknod":       engKubeArmor,
	// ── security-native: dns (Tetragon DNS tracing) ─────────────────
	"sec-dns-exfil":     engTetragon,
	"sec-dns-longlabel": engTetragon,
	// ── security-native: mount (KubeArmor mount rule) ────────────────
	"sec-mount-attempt":     engKubeArmor, // tmpfs -> /mnt
	"sec-mount-procremount": engKubeArmor,
	// ── security-native: chain (multi-engine kill chains) ────────────
	"sec-attack-chain":      engMixed, // exec→cap→secret→egress
	"sec-chain-cred-access": engMixed, // SA token → metadata → egress
	"sec-chain-privesc":     engMixed, // exec sh → chmod → setuid
	// ── security-ingest (synthetic batches — engine is explicit) ─────
	"sec-ingest-runtime-tetragon":  engTetragon,
	"sec-ingest-runtime-kubearmor": engKubeArmor,
	"sec-ingest-runtime-hubble":    engHubble,
	"sec-ingest-observations":      engKubeArmor,
}

// scenarioTechnique maps every native scenario ID → its attack-technique
// facet. Single source of truth for the technique filter the operator
// asked for; stamped onto scenario.Technique in
// assignEnginesAndTechniques() so catalogue literals stay clean.
var scenarioTechnique = map[string]technique{
	// exec
	"sec-exec-shell":       techExec,
	"sec-exec-bash":        techExec,
	"sec-exec-kubectl":     techExec,
	"sec-exec-curl":        techExec,
	"sec-exec-wget":        techExec,
	"sec-exec-nc":          techExec,
	"sec-exec-socat":       techExec,
	"sec-exec-python":      techExec,
	"sec-exec-perl":        techExec,
	"sec-exec-nmap":        techExec,
	"sec-install-tool":     techExec,
	"sec-exec-base64":      techExec,
	"sec-exec-chmod":       techExec,
	"sec-exec-crontab":     techExec,
	"sec-exec-ssh":         techExec,
	"sec-exec-dropped-bin": techExec,
	// file-read
	"sec-read-secret":           techFileRead,
	"sec-read-passwd":           techFileRead,
	"sec-read-ssh-key":          techFileRead,
	"sec-read-sa-token":         techFileRead,
	"sec-read-proc-environ":     techFileRead,
	"sec-read-kubeconfig-admin": techFileRead,
	"sec-read-kubelet-conf":     techFileRead,
	"sec-read-aws-creds":        techFileRead,
	"sec-read-kube-config":      techFileRead,
	"sec-honey-path":            techFileRead,
	// file-write
	"sec-file-tamper":     techFileWrite,
	"sec-write-authkeys":  techFileWrite,
	"sec-write-cron":      techFileWrite,
	"sec-write-usrbin":    techFileWrite,
	"sec-write-ldpreload": techFileWrite,
	"sec-write-bashrc":    techFileWrite,
	"sec-write-spoolcron": techFileWrite,
	// network
	"sec-network-egress":   techNetwork,
	"sec-net-dns-tcp":      techNetwork,
	"sec-net-oddport":      techNetwork,
	"sec-net-metadata":     techNetwork,
	"sec-net-revshell":     techNetwork,
	"sec-ddos-flood-self":  techNetwork,
	"sec-ddos-flood-world": techNetwork,
	// capability
	"sec-capability-use":  techCapability,
	"sec-cap-setuid":      techCapability,
	"sec-cap-net-raw":     techCapability,
	"sec-cap-ptrace":      techCapability,
	"sec-cap-sethostname": techCapability,
	"sec-cap-mknod":       techCapability,
	// dns
	"sec-dns-exfil":     techDNS,
	"sec-dns-longlabel": techDNS,
	// mount
	"sec-mount-attempt":     techMount,
	"sec-mount-procremount": techMount,
	// chain
	"sec-attack-chain":      techChain,
	"sec-chain-cred-access": techChain,
	"sec-chain-privesc":     techChain,
}

// assignEnginesAndTechniques stamps scenario.Engine and
// scenario.Technique from the central tables. Called once at the end of
// buildScenarios() so the catalogue literals stay untouched and both
// mappings are reviewable in one block.
func assignEnginesAndTechniques() {
	for i := range scenarioList {
		if e, ok := scenarioEngine[scenarioList[i].ID]; ok {
			scenarioList[i].Engine = e
		}
		if t, ok := scenarioTechnique[scenarioList[i].ID]; ok {
			scenarioList[i].Technique = t
		}
	}
}

type scenarioRun struct {
	ScenarioID string    `json:"scenarioId"`
	StartedAt  time.Time `json:"startedAt"`
	EndedAt    time.Time `json:"endedAt"`
	OK         bool      `json:"ok"`
	Result     any       `json:"result"`
}

var (
	scenarioMu   sync.RWMutex
	lastRuns     = map[string]*scenarioRun{}
	scenarioList []scenario
)

func serviceID() string { return os.Getenv("KOMUTA_SERVICE_ID") }

func recordRun(id string, started time.Time, result any, ok bool) {
	scenarioMu.Lock()
	lastRuns[id] = &scenarioRun{
		ScenarioID: id, StartedAt: started, EndedAt: time.Now(),
		OK: ok, Result: result,
	}
	scenarioMu.Unlock()
}

func getLastRun(id string) *scenarioRun {
	scenarioMu.RLock()
	defer scenarioMu.RUnlock()
	return lastRuns[id]
}

// triggerOK treats "denied" as success too — a denied verdict means a
// policy IS enforced, which is a valid (often desired) test outcome.
func nativeRun(fn func() triggerOutcome) func(context.Context) any {
	return func(context.Context) any { return fn() }
}

func buildScenarios() {
	svc := serviceID()
	pipelineRun := "komuta-test-app-" + newUUID()[:8]
	imageRef := "ghcr.io/microzon-tech/komuta-test-app:scenario-" + newUUID()[:6]

	scenarioList = []scenario{
		// ── Insights ────────────────────────────────────────────────
		{
			ID: "insights-baseline-traffic", Name: "Steady L7 baseline", Category: catInsights,
			Desc:     "Start a realistic weighted e-commerce traffic mix at ~40 RPS.",
			Expected: "L7 telemetry flows; endpoint pulse + latency heatmap populate; baseline window builds.",
			KomutaUI: "Service → Insights → Genel Bakış / Gecikme: endpoints appear with p50/p95 within ~1–2 min.",
			run: func(context.Context) any {
				startTrafficGenerator(trafficCfg{RPS: 40}, port())
				return map[string]any{"trafficStarted": true, "rps": 40}
			},
		},
		{
			ID: "insights-latency-regression", Name: "Latency regression on checkout", Category: catInsights,
			Desc:     "Inject +600ms on POST /api/checkout for 5 min on top of steady traffic.",
			Expected: "Anomaly z-score trips; deploy/latency heatmap shows the hot endpoint; top-contributing-endpoint chip flags POST /api/checkout.",
			KomutaUI: "Service → Insights → Gecikme + Anomali: POST /api/checkout p95 spikes; anomaly card lights up.",
			run: func(context.Context) any {
				startTrafficGeneratorIfIdle()
				setLatencyInjection("POST /api/checkout", 600*time.Millisecond, 300*time.Second)
				return map[string]any{"injected": "POST /api/checkout +600ms / 300s"}
			},
		},
		{
			ID: "insights-error-spike", Name: "5xx error budget burn", Category: catInsights,
			Desc:     "Return 500 on 35% of GET /api/items for 4 min.",
			Expected: "SLO burn-rate alert fires; success-rate panel drops; alert pulse increments.",
			KomutaUI: "Service → Insights → SLO / Uyarılar: burn-rate alert active; success rate < SLO target.",
			run: func(context.Context) any {
				startTrafficGeneratorIfIdle()
				setErrorInjection("GET /api/items", 0.35, 500, 240*time.Second)
				return map[string]any{"injected": "GET /api/items 35% 500 / 240s"}
			},
		},
		{
			ID: "insights-path-clustering", Name: "Path clustering fan-out", Category: catInsights,
			Desc:     "Fire 60 distinct /api/search?q=… and /api/items/{id} paths.",
			Expected: "Path clustering collapses high-cardinality paths into stable templates.",
			KomutaUI: "Service → Insights → Yollar/Kümeleme: /api/search and /api/items/{id} appear as clustered templates, not 60 rows.",
			run:      func(context.Context) any { return fanOutPaths(port()) },
		},
		{
			ID: "insights-deploy-impact", Name: "Deploy-impact (v1.0→v1.1-bug→v1.2-fix)", Category: catInsights,
			Desc:     "Operator-driven: redeploy this image under 3 tags. App marks /readyz with the active version so Insights can label rows.",
			Expected: "Insights → Etki classifies the sequence stable → regressed → improved.",
			KomutaUI: "Service → Insights → Etki: three release rows; middle one 'regressed', last 'improved'. (Redeploy via Komuta service form, changing APP_VERSION.)",
			run: func(context.Context) any {
				return map[string]any{
					"activeVersion": AppVersion,
					"instructions":  "Redeploy with APP_VERSION=v1.0-clean, then v1.1-bug, then v1.2-fix; allow ~5 min traffic between each.",
				}
			},
		},

		// ── Security: cluster-native attack matrix (category a) ──────
		// Grouped by technique. Engine + Technique are stamped centrally
		// in assignEnginesAndTechniques(); the literals stay declarative.

		// exec (KubeArmor process-exec rule) ─────────────────────────
		secNative("sec-exec-shell", "Exec shell (process block)",
			"Spawn `sh -c 'id; uname -a'` inside the pod.",
			"KubeArmor process rule flags an unexpected exec; observation → finding.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Operation=Exec, Path=/bin/sh.",
			trigExecShell),
		secNative("sec-exec-bash", "Exec bash",
			"Run `bash -c id`.",
			"KubeArmor process rule flags the bash exec.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=/bin/bash.",
			execTrig("bash", "bash", "-c", "id")),
		secNative("sec-exec-kubectl", "Exec kubectl (in-pod cluster tooling)",
			"Run `kubectl version --client`.",
			"Process-exec rule flags cluster tooling running inside a workload pod.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=…/kubectl.",
			execTrig("kubectl", "kubectl", "version", "--client")),
		secNative("sec-exec-curl", "Exec curl",
			"Run `curl --version`.",
			"Process-exec rule flags the curl binary (common download primitive).",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=…/curl.",
			execTrig("curl", "curl", "--version")),
		secNative("sec-exec-wget", "Exec wget",
			"Run `wget --version`.",
			"Process-exec rule flags the wget binary (download primitive).",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=…/wget.",
			execTrig("wget", "wget", "--version")),
		secNative("sec-exec-nc", "Exec netcat",
			"Run `nc -h`.",
			"Process-exec rule flags netcat (reverse-shell / port primitive).",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=…/nc.",
			execTrig("nc", "nc", "-h")),
		secNative("sec-exec-socat", "Exec socat",
			"Run `socat -V`.",
			"Process-exec rule flags socat (relay / reverse-shell primitive).",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=…/socat.",
			execTrig("socat", "socat", "-V")),
		secNative("sec-exec-python", "Exec python3",
			"Run `python3 -c 'print(1)'`.",
			"Process-exec rule flags an interpreter exec inside the workload.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=…/python3.",
			execTrig("python3", "python3", "-c", "print(1)")),
		secNative("sec-exec-perl", "Exec perl",
			"Run `perl -e 'print 1'`.",
			"Process-exec rule flags an interpreter exec inside the workload.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=…/perl.",
			execTrig("perl", "perl", "-e", "print 1")),
		secNative("sec-exec-nmap", "Exec nmap (recon scanner)",
			"Run `nmap --version`.",
			"Process-exec rule flags a network scanner running in the pod.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=…/nmap.",
			execTrig("nmap", "nmap", "--version")),
		secNative("sec-install-tool", "Package manager invocation",
			"Invoke apk/apt-get/dnf --help.",
			"Process-block rule flags package-manager exec.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=package-manager binary.",
			trigInstallTool),
		secNative("sec-exec-base64", "Exec base64 (encode/exfil primitive)",
			"Run `base64 --help`.",
			"Process-exec rule flags base64 (common encoding/exfil helper).",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=…/base64.",
			execTrig("base64", "base64", "--help")),
		secNative("sec-exec-chmod", "Exec chmod +x (make executable)",
			"Run `chmod +x /tmp/komuta-x`.",
			"Process-exec rule flags chmod turning a dropped file executable.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=…/chmod.",
			execTrig("chmod", "chmod", "+x", "/tmp/komuta-x")),
		secNative("sec-exec-crontab", "Exec crontab (persistence primitive)",
			"Run `crontab -l`.",
			"Process-exec rule flags crontab (scheduled-task persistence).",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=…/crontab.",
			execTrig("crontab", "crontab", "-l")),
		secNative("sec-exec-ssh", "Exec ssh (lateral movement primitive)",
			"Run `ssh -V`.",
			"Process-exec rule flags the ssh client (lateral movement).",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=…/ssh.",
			execTrig("ssh", "ssh", "-V")),
		secNative("sec-exec-dropped-bin", "Drop + exec a binary in /tmp",
			"Copy /bin/busybox (or /bin/sh) to /tmp/komuta-dropped (0755), exec it, clean up.",
			"Process-exec rule flags exec of a binary outside the image's known set.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Exec; row Path=/tmp/komuta-dropped.",
			trigDroppedBinExec),

		// file-read (KubeArmor sensitive-file rule) ──────────────────
		secNative("sec-read-secret", "Read /etc/shadow (sensitive file)",
			"Read /etc/shadow.",
			"KubeArmor file rule flags sensitive-file access; finding raised.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Path=/etc/shadow, Operation=Read.",
			trigReadSecret),
		secNative("sec-read-passwd", "Read /etc/passwd",
			"Read /etc/passwd.",
			"File rule flags reading the account database.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Path=/etc/passwd.",
			readTrig("/etc/passwd")),
		secNative("sec-read-ssh-key", "Read root SSH private key",
			"Read /root/.ssh/id_rsa.",
			"File rule flags private-key access (credential theft).",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Path=/root/.ssh/id_rsa.",
			readTrig("/root/.ssh/id_rsa")),
		secNative("sec-read-sa-token", "Read Kubernetes service-account token",
			"Read /var/run/secrets/kubernetes.io/serviceaccount/token.",
			"File rule flags SA-token access (in-cluster credential theft).",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Path=…/serviceaccount/token.",
			readTrig("/var/run/secrets/kubernetes.io/serviceaccount/token")),
		secNative("sec-read-proc-environ", "Read /proc/1/environ (PID 1 env)",
			"Read /proc/1/environ.",
			"File rule flags reading another process's environment (secret leak).",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Path=/proc/1/environ.",
			readTrig("/proc/1/environ")),
		secNative("sec-read-kubeconfig-admin", "Read cluster admin kubeconfig",
			"Read /etc/kubernetes/admin.conf.",
			"File rule flags access to cluster-admin credentials.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Path=/etc/kubernetes/admin.conf.",
			readTrig("/etc/kubernetes/admin.conf")),
		secNative("sec-read-kubelet-conf", "Read kubelet config",
			"Read /var/lib/kubelet/config.yaml.",
			"File rule flags access to node/kubelet configuration.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Path=/var/lib/kubelet/config.yaml.",
			readTrig("/var/lib/kubelet/config.yaml")),
		secNative("sec-read-aws-creds", "Read AWS credentials",
			"Read /root/.aws/credentials.",
			"File rule flags cloud-credential theft.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Path=/root/.aws/credentials.",
			readTrig("/root/.aws/credentials")),
		secNative("sec-read-kube-config", "Read user kubeconfig",
			"Read /root/.kube/config.",
			"File rule flags kubeconfig credential theft.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Path=/root/.kube/config.",
			readTrig("/root/.kube/config")),
		secNative("sec-honey-path", "Honey-path access (deterministic Tetragon)",
			"open() the configured Security Center honey path.",
			"Honey-path TracingPolicy emits a Tetragon event → high-severity finding.",
			"Security Center → Bulgular: filter Kaynak=Tetragon; row tagged honey-path; check Olay Müdahale Playbook'ları.",
			trigHoneyPath),

		// file-write (KubeArmor write-outside-mounts rule) ───────────
		secNative("sec-file-tamper", "Tamper /etc (write outside /tmp)",
			"Write /etc/passwd.injected then clean up.",
			"KubeArmor write rule flags a write outside the allowed mounts.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Operation=Write, Path under /etc.",
			trigFileTamper),
		secNative("sec-write-authkeys", "Write SSH authorized_keys (persistence)",
			"Write /root/.ssh/authorized_keys then clean up.",
			"Write rule flags planting an SSH backdoor key.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Operation=Write, Path=/root/.ssh/authorized_keys.",
			writeTrig("/root/.ssh/authorized_keys")),
		secNative("sec-write-cron", "Write /etc/cron.d (persistence)",
			"Write /etc/cron.d/komuta-test then clean up.",
			"Write rule flags planting a cron persistence job.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Operation=Write, Path=/etc/cron.d/komuta-test.",
			writeTrig("/etc/cron.d/komuta-test")),
		secNative("sec-write-usrbin", "Write /usr/bin (drop binary)",
			"Write /usr/bin/komuta-dropped then clean up.",
			"Write rule flags dropping a file into a system bin directory.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Operation=Write, Path=/usr/bin/komuta-dropped.",
			writeTrig("/usr/bin/komuta-dropped")),
		secNative("sec-write-ldpreload", "Write /etc/ld.so.preload (hijack)",
			"Write /etc/ld.so.preload then clean up.",
			"Write rule flags ld.so.preload tampering (library hijack).",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Operation=Write, Path=/etc/ld.so.preload.",
			writeTrig("/etc/ld.so.preload")),
		secNative("sec-write-bashrc", "Write /root/.bashrc (persistence)",
			"Write /root/.bashrc then clean up.",
			"Write rule flags shell-startup persistence tampering.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Operation=Write, Path=/root/.bashrc.",
			writeTrig("/root/.bashrc")),
		secNative("sec-write-spoolcron", "Write /var/spool/cron (persistence)",
			"Write /var/spool/cron/crontabs/root then clean up.",
			"Write rule flags a user-crontab persistence write.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=File; row Operation=Write, Path=/var/spool/cron/crontabs/root.",
			writeTrig("/var/spool/cron/crontabs/root")),

		// network (Hubble/Cilium flow visibility) ────────────────────
		secNative("sec-network-egress", "Unexpected egress to public internet",
			"HTTP GET http://example.com.",
			"Cilium/Hubble network policy flags off-allowlist egress.",
			"Security Center → Bulgular: filter Kaynak=Hubble Tür=Network; row NetworkConnect to example.com.",
			trigNetworkEgress),
		secNative("sec-net-dns-tcp", "TCP to public DNS (1.1.1.1:53)",
			"Open TCP to 1.1.1.1:53.",
			"Network policy flags direct egress to an external DNS resolver.",
			"Security Center → Bulgular: filter Kaynak=Hubble Tür=Network; row dst=1.1.1.1:53.",
			connectTrig("1.1.1.1", 53)),
		secNative("sec-net-oddport", "TCP to odd high port (8.8.8.8:9999)",
			"Open TCP to 8.8.8.8:9999.",
			"Network policy flags egress to an unusual high port.",
			"Security Center → Bulgular: filter Kaynak=Hubble Tür=Network; row dst=8.8.8.8:9999.",
			connectTrig("8.8.8.8", 9999)),
		secNative("sec-net-metadata", "Cloud metadata SSRF (169.254.169.254:80)",
			"Open TCP to 169.254.169.254:80.",
			"Network policy flags access to the cloud metadata endpoint (SSRF / credential theft).",
			"Security Center → Bulgular: filter Kaynak=Hubble Tür=Network; row dst=169.254.169.254:80.",
			connectTrig("169.254.169.254", 80)),
		secNative("sec-net-revshell", "Reverse-shell port egress (:4444)",
			"Open TCP to 203.0.113.77:4444 (reverse-shell port).",
			"Network policy flags egress to a canonical reverse-shell port.",
			"Security Center → Bulgular: filter Kaynak=Hubble Tür=Network; row dst=…:4444.",
			connectTrig("203.0.113.77", 4444)),

		// DDoS flood (DdosFlowToIncidentProjector, Hubble → l4_traffic_5m)
		// Background fresh-connection flood; run() returns immediately.
		{
			ID: "sec-ddos-flood-self", Name: "DDoS flood — self-service (auto-resolve, world fallback)", Category: catSecNative,
			Desc:     "Background fresh-TCP flood at ~50 conn/s for ~12 min (≈36000 flows; threshold >10000). Target auto-resolves: DDOS_TARGET → <svc>-stable.<ns>.svc:8080 → external world fallback. The returned JSON reports the chosen target/mode/attribution.",
			Expected: "DdosFlowToIncidentProjector raises a DDoSSuspected incident within ~2–4 min. In self-service mode the target resolves to this tenant's service so ServiceId is stamped (attributed); if it fell back to world mode the incident is cluster-scoped.",
			KomutaUI: "Security Center → Ağ / DDoS: an Open DDoSSuspected incident appears (ServiceId=this service when self-service). Stop via /control/ddos/stop or the 'Stop DDoS flood' scenario.",
			run: func(context.Context) any {
				return startFloodFrom(resolveDdosFloodTarget())
			},
		},
		{
			ID: "sec-ddos-flood-world", Name: "DDoS flood — external host (cluster-scoped)", Category: catSecNative,
			Desc:     "Background fresh-TCP flood at ~50 conn/s for ~12 min against an external host (DDOS_WORLD_TARGET → DDOS_TARGET → 1.1.1.1:80). Uses the CNP world-egress path; always works.",
			Expected: "DdosFlowToIncidentProjector raises a DDoSSuspected incident for the source→world flow; the destination is not tenant-owned, so the incident is cluster-scoped (unattributed).",
			KomutaUI: "Security Center → Ağ / DDoS (host view): an Open DDoSSuspected incident with an external destination and no tenant service attribution.",
			run: func(context.Context) any {
				return startFloodFrom(resolveDdosWorldTarget())
			},
		},
		{
			ID: "sec-ddos-stop", Name: "Stop DDoS flood", Category: catSecNative,
			Desc:     "Cancel any running DDoS flood immediately.",
			Expected: "The background flood stops; no new flows are generated. The already-raised incident stays Open until the detector auto-resolves it after the window clears.",
			KomutaUI: "No new DDoS flows after this; the incident's flow_count stops climbing in Security Center → Ağ / DDoS.",
			run: func(context.Context) any {
				stopDdosFlood()
				return snapshotDdosFlood()
			},
		},

		// capability (KubeArmor capability rule) ─────────────────────
		secNative("sec-capability-use", "Privileged capability: chown",
			"chown(/etc/hostname, 0, 0).",
			"KubeArmor capability rule flags CAP_CHOWN use.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Capability; row CAP_CHOWN.",
			trigCapabilityUse),
		secNative("sec-cap-setuid", "Privileged capability: setuid(0)",
			"syscall setuid(0) (CAP_SETUID).",
			"Capability rule flags a setuid-to-root attempt; a dropped-cap pod returns EPERM (denied).",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Capability; row CAP_SETUID.",
			trigSetuidRoot),
		secNative("sec-cap-net-raw", "Privileged capability: raw socket",
			"Open a raw ICMP socket (CAP_NET_RAW).",
			"Capability rule flags raw-socket creation.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Capability; row CAP_NET_RAW.",
			trigRawSocket),
		secNative("sec-cap-ptrace", "Privileged capability: ptrace",
			"ptrace-attach to PID 1 (CAP_SYS_PTRACE).",
			"Capability rule flags a ptrace attach (process injection).",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Capability; row CAP_SYS_PTRACE.",
			trigPtrace),
		secNative("sec-cap-sethostname", "Privileged capability: sethostname",
			"sethostname (CAP_SYS_ADMIN); restores on success.",
			"Capability rule flags a CAP_SYS_ADMIN operation.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Capability; row CAP_SYS_ADMIN.",
			trigSethostname),
		secNative("sec-cap-mknod", "Privileged capability: mknod",
			"mknod /tmp/komuta-dev (CAP_MKNOD); unlinks on success.",
			"Capability rule flags device-node creation.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Capability; row CAP_MKNOD.",
			trigMknod),

		// dns (Tetragon DNS tracing) ─────────────────────────────────
		secNative("sec-dns-exfil", "Suspicious DNS (exfil/C2 indicator)",
			"Resolve a random *.attacker-c2.example host.",
			"Tetragon DNS tracing flags the lookup.",
			"Security Center → Bulgular / Denetim Kaydı: filter Kaynak=Tetragon Tür=DNS; row query=…attacker-c2.example.",
			trigDNSExfil),
		secNative("sec-dns-longlabel", "DNS exfil via long base64-ish label",
			"Resolve a long base64-style label under a look-alike domain.",
			"Tetragon DNS tracing flags the abnormally long / high-entropy query (DNS tunnelling).",
			"Security Center → Bulgular / Denetim Kaydı: filter Kaynak=Tetragon Tür=DNS; row with a long-label query.",
			dnsTrig("a2xvbWVudGFyeWV4ZmlsZGF0YWNodW5rMDAx."+"data-"+"exfil.attacker-c2.example")),

		// mount (KubeArmor mount rule) ───────────────────────────────
		secNative("sec-mount-attempt", "Mount tmpfs (container-escape precursor)",
			"mount -t tmpfs none /mnt.",
			"KubeArmor mount rule denies; finding raised.",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Mount; row target=/mnt.",
			trigMountAttempt),
		secNative("sec-mount-procremount", "Remount /proc (escape precursor)",
			"mount -o remount /proc.",
			"KubeArmor mount rule flags a /proc remount (namespace-escape precursor).",
			"Security Center → Bulgular: filter Kaynak=KubeArmor Tür=Mount; row target=/proc.",
			execTrig("mount:proc-remount", "mount", "-o", "remount", "/proc")),

		// chain (multi-engine kill chains) ───────────────────────────
		{
			ID: "sec-attack-chain", Name: "Multi-stage kill chain", Category: catSecNative,
			Desc:     "Ordered: exec → capability → secret read → egress (0.8s apart).",
			Expected: "Multiple correlated findings within a tight window; IR playbook should match the pattern.",
			KomutaUI: "Security Center → Bulgular (4 correlated rows) + Olay Müdahale Playbook'ları (matched playbook + dispatch history).",
			run:      func(context.Context) any { return map[string]any{"chain": trigAttackChain()} },
		},
		{
			ID: "sec-chain-cred-access", Name: "Credential-access chain (token → metadata → egress)", Category: catSecNative,
			Desc:     "Ordered: read SA token → connect 169.254.169.254 → egress (0.8s apart).",
			Expected: "Correlated credential-access → SSRF → exfil findings; IR playbook should match.",
			KomutaUI: "Security Center → Bulgular (3 correlated rows: File read + Network 169.254.169.254 + egress) + Olay Müdahale Playbook'ları.",
			run:      func(context.Context) any { return map[string]any{"chain": trigChainCredAccess()} },
		},
		{
			ID: "sec-chain-privesc", Name: "Privilege-escalation chain (shell → chmod → setuid)", Category: catSecNative,
			Desc:     "Ordered: exec sh → chmod +x → setuid(0) (0.8s apart).",
			Expected: "Correlated exec + capability findings; IR playbook should match the privesc pattern.",
			KomutaUI: "Security Center → Bulgular (correlated Exec + Capability rows) + Olay Müdahale Playbook'ları.",
			run:      func(context.Context) any { return map[string]any{"chain": trigChainPrivesc()} },
		},

		// ── Security: direct synthetic ingest (category b) ───────────
		{
			ID: "sec-ingest-runtime-tetragon", Name: "Synthetic Tetragon runtime batch", Category: catSecIngest, NeedsM2M: true,
			Desc:     "POST an NDJSON batch (PROCESS_EXEC, FILE_OPEN, NET_CONNECT) with source=Tetragon.",
			Expected: "Events stored; Tetragon collector flips to Healthy; events visible in timeline.",
			KomutaUI: "Security Center → Genel Bakış (Toplayıcı sağlığı: Tetragon=Healthy) + İhlaller/Denetim Kaydı (events).",
			run: func(ctx context.Context) any {
				return ingestTokens.ingestRuntime(ctx, "Tetragon", []runtimeRecord{
					synthRuntime("Tetragon", "PROCESS_EXEC", 7, svc, "/bin/sh", "-c 'id'"),
					synthRuntime("Tetragon", "FILE_OPEN", 8, svc, "/etc/shadow", "O_RDONLY"),
					synthRuntime("Tetragon", "NET_CONNECT", 6, svc, "", "tcp 10.0.0.5:443->203.0.113.9:443"),
				})
			},
		},
		{
			ID: "sec-ingest-runtime-kubearmor", Name: "Synthetic KubeArmor runtime batch", Category: catSecIngest, NeedsM2M: true,
			Desc:     "POST an NDJSON batch with source=KubeArmor (process + file deny).",
			Expected: "Events stored; KubeArmor collector Healthy.",
			KomutaUI: "Security Center → Genel Bakış: Toplayıcı sağlığı KubeArmor=Healthy; Denetim Kaydı shows the events.",
			run: func(ctx context.Context) any {
				return ingestTokens.ingestRuntime(ctx, "KubeArmor", []runtimeRecord{
					synthRuntime("KubeArmor", "FILE_DENY", 9, svc, "/etc/passwd", "write blocked"),
					synthRuntime("KubeArmor", "PROCESS_EXEC", 7, svc, "/usr/bin/nmap", "-sS"),
				})
			},
		},
		{
			ID: "sec-ingest-runtime-hubble", Name: "Synthetic Hubble runtime batch", Category: catSecIngest, NeedsM2M: true,
			Desc:     "POST an NDJSON batch with source=Hubble (NETWORK_FLOW + NETWORK_DROP).",
			Expected: "Events stored; Hubble collector Healthy.",
			KomutaUI: "Security Center → Genel Bakış: Hubble collector Healthy.",
			run: func(ctx context.Context) any {
				return ingestTokens.ingestRuntime(ctx, "Hubble", []runtimeRecord{
					synthRuntime("Hubble", "NETWORK_FLOW", 4, svc, "", "egress tcp :443 verdict=FORWARDED"),
					synthRuntime("Hubble", "NETWORK_DROP", 7, svc, "", "egress tcp :4444 verdict=DROPPED"),
				})
			},
		},
		{
			ID: "sec-ingest-observations", Name: "KubeArmor observations → finding", Category: catSecIngest, NeedsM2M: true,
			Desc:     "POST a security-observations batch (Write/Exec/NetworkConnect) for this service.",
			Expected: "Observations upserted; KubeArmor observation projector raises an AppSecurityFinding.",
			KomutaUI: "Security Center → İhlaller: new finding per (operation,path); Service → Güvenlik tab shows the observation rows.",
			run: func(ctx context.Context) any {
				if svc == "" {
					return map[string]any{"error": "KOMUTA_SERVICE_ID not set — needed to target observations"}
				}
				return ingestTokens.ingestObservations(ctx, []observationEvent{
					{ServiceID: svc, Operation: "Exec", Path: "/bin/busybox", Action: "Audit", Severity: 7, RuleName: "komuta-test-exec"},
					{ServiceID: svc, Operation: "Write", Path: "/etc/cron.d/evil", Action: "Block", Severity: 9, RuleName: "komuta-test-write"},
					{ServiceID: svc, Operation: "NetworkConnect", Path: "203.0.113.10:4444", Action: "Audit", Severity: 8, RuleName: "komuta-test-net"},
				})
			},
		},
		{
			ID: "sec-collector-decay", Name: "Collector heartbeat then silence", Category: catSecIngest, NeedsM2M: true,
			Desc:     "Send one runtime batch (collector→Healthy) then stop. Operator waits past decay thresholds.",
			Expected: "Collector transitions Healthy → Degraded → Unhealthy → Unknown as no further events arrive.",
			KomutaUI: "Security Center → Genel Bakış (Toplayıcı sağlığı): watch the source decay over the configured windows.",
			run: func(ctx context.Context) any {
				r := ingestTokens.ingestRuntime(ctx, "Tetragon", []runtimeRecord{
					synthRuntime("Tetragon", "PROCESS_EXEC", 3, svc, "/bin/true", ""),
				})
				return map[string]any{"seeded": r, "note": "now do NOT run any Tetragon scenario; watch the decay ladder in the UI"}
			},
		},
		{
			ID: "sec-synthetic-attack", Name: "Synthetic attack run trigger", Category: catSecIngest, NeedsM2M: true,
			Desc:     "Trigger a synthetic-attack run (env SYNTHETIC_SCENARIO_ID, else first catalog scenario).",
			Expected: "Pending run created + WORM SyntheticAttackTriggered; evaluator job later marks Detected/NotDetected vs the SLA window.",
			KomutaUI: "Security Center → Sentetik Saldırılar (Daha Fazla menüsü): run appears Pending; pair with a matching finding scenario to see Detected.",
			run: func(ctx context.Context) any {
				sc := os.Getenv("SYNTHETIC_SCENARIO_ID")
				if sc == "" {
					sc = "kubearmor-exec-baseline"
				}
				return ingestTokens.triggerSyntheticAttack(ctx, sc, svc)
			},
		},

		// ── Supply chain (category b, Tekton ingest → WORM 40-43) ────
		{
			ID: "supply-sbom", Name: "Build artifact: SBOM", Category: catSupplyChn, NeedsM2M: true,
			Desc:     "POST an SBOM task payload for a synthetic pipeline run.",
			Expected: "Build-artifact row created; WORM BuildArtifactSbom appended.",
			KomutaUI: "Security Center → Tedarik Zinciri / build-artifacts: row for the pipeline run + WORM entry in Denetim Kaydı.",
			run: func(ctx context.Context) any {
				return ingestTokens.ingestSbom(ctx, pipelineRun, imageRef, "s3://komuta-sbom/"+pipelineRun+".json")
			},
		},
		{
			ID: "supply-scan-critical", Name: "Build artifact: scan (critical CVEs)", Category: catSupplyChn, NeedsM2M: true,
			Desc:     "POST a scan result with 2 critical / 5 high CVEs.",
			Expected: "Scan attached to the artifact row; high/critical counts surface; WORM BuildArtifactScanned.",
			KomutaUI: "Security Center → Tedarik Zinciri: artifact shows Critical=2 High=5; finding/risk reflects it.",
			run: func(ctx context.Context) any {
				return ingestTokens.ingestScan(ctx, pipelineRun, imageRef, 2, 5, 11, 23)
			},
		},
		{
			ID: "supply-sign", Name: "Build artifact: signature", Category: catSupplyChn, NeedsM2M: true,
			Desc:     "POST a Sigstore/Rekor signature record.",
			Expected: "Artifact marked signed; WORM BuildArtifactSigned.",
			KomutaUI: "Security Center → Tedarik Zinciri: artifact shows Signed + Rekor uuid.",
			run: func(ctx context.Context) any {
				return ingestTokens.ingestSignature(ctx, pipelineRun, imageRef)
			},
		},
		{
			ID: "supply-fail", Name: "Build artifact: failure", Category: catSupplyChn, NeedsM2M: true,
			Desc:     "POST a build-failure record for a different pipeline run.",
			Expected: "Failure recorded; WORM BuildArtifactFailed.",
			KomutaUI: "Security Center → Tedarik Zinciri: failed build row; Denetim Kaydı WORM entry.",
			run: func(ctx context.Context) any {
				return ingestTokens.ingestBuildFailure(ctx,
					"komuta-test-app-"+newUUID()[:8], imageRef, "trivy gate failed: 3 critical CVEs")
			},
		},
	}

	// Stamp the runtime-engine owner AND attack-technique facet onto
	// every scenario from the central tables so the console can group/
	// badge/filter by engine and technique without touching any
	// catalogue literal.
	assignEnginesAndTechniques()
}

func secNative(id, name, desc, expected, ui string, fn func() triggerOutcome) scenario {
	return scenario{
		ID: id, Name: name, Category: catSecNative,
		Desc: desc, Expected: expected, KomutaUI: ui,
		run: nativeRun(fn),
	}
}

func synthRuntime(source, evtType string, sev int, svc, binary, args string) runtimeRecord {
	return runtimeRecord{
		EventTime: now(), Source: source, EventType: evtType, Severity: sev,
		ServiceID: svc, NodeName: "komuta-test-node", PodName: hostname(),
		ContainerName: "komuta-test-app", BinaryPath: binary, Args: args,
		EvidenceJSON: fmt.Sprintf(`{"synthetic":true,"source":%q,"type":%q}`, source, evtType),
	}
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "komuta-test-app"
	}
	return h
}

func port() string {
	p := os.Getenv("PORT")
	if p == "" {
		return "8080"
	}
	return p
}

func startTrafficGeneratorIfIdle() {
	if !trafficRunning() {
		startTrafficGenerator(trafficCfg{RPS: 40}, port())
	}
}

func trafficRunning() bool {
	trafficState.mu.Lock()
	defer trafficState.mu.Unlock()
	return trafficState.cancel != nil
}
