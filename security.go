package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Category-(a) cluster-native security triggers. Each does ONE
// isolated syscall / network pattern that a tightened KubeArmor or
// Tetragon policy in the cluster should catch; the cluster's
// komuta-security-agent then forwards it through the real ingest
// chain. Triggers never escalate privilege or attempt cluster-wide
// damage — they only attempt actions a hardened tenant workload
// should not be able to perform.
//
// Each trigger is a pure func returning a triggerOutcome so the
// scenario layer can invoke it directly; the HTTP handlers below are
// thin wrappers kept for ad-hoc curl use.

type triggerOutcome struct {
	Action  string `json:"action"`
	Verdict string `json:"verdict"` // "denied" (policy enforced) | "allowed" (not enforced)
	Output  string `json:"output"`
	Err     string `json:"error,omitempty"`
}

// classifyVerdict separates a REAL policy denial from an environment error.
// The block-test only means something when the syscall actually reached the
// kernel: "allowed" = it ran (a runtime event was produced), "denied" = a
// policy/LSM refused it (blocked), "error" = it never ran (the binary/target
// isn't in the image, or PATH lookup failed) so nothing was blocked and
// nothing reached Komuta. Treating "executable not found" as "denied" — the
// old behaviour — reads as a bogus "Blocked" on a distroless image.
func classifyVerdict(err error) string {
	if err == nil {
		return "allowed"
	}
	// Binary not in PATH / on disk → the execve never happened.
	if errors.Is(err, exec.ErrNotFound) {
		return "error"
	}
	// Permission / LSM denial → a real block.
	if errors.Is(err, os.ErrPermission) ||
		errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return "denied"
	}
	// A process that ran but was killed by a signal (KubeArmor block often
	// SIGKILLs the offending exec) is a denial.
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return "denied"
		}
	}
	// String fallback for the "not found" phrasings the errors.Is checks miss.
	msg := err.Error()
	if strings.Contains(msg, "executable file not found") ||
		strings.Contains(msg, "no such file or directory") {
		return "error"
	}
	// The syscall reached the kernel and something refused it → treat as a
	// denial (the operator can read the error to confirm it was a policy).
	return "denied"
}

func outcome(action string, out []byte, err error) triggerOutcome {
	o := triggerOutcome{Action: action, Verdict: classifyVerdict(err)}
	if err != nil {
		o.Err = err.Error()
	}
	s := strings.TrimSpace(string(out))
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	o.Output = s
	return o
}

// ── Generic trigger factories ──────────────────────────────────────
//
// Each returns a `func() triggerOutcome` so the scenario layer can
// register it directly through secNative(...). They all funnel through
// outcome(...) so the allowed/denied verdict contract stays uniform:
// err != nil ⇒ "denied" (policy enforced), else "allowed" (not
// enforced). Every factory performs exactly ONE isolated action and
// cleans up after itself.

// execTrig runs a single external command. A denied exec (permission
// denied / not found because a policy blocked the binary) surfaces as
// "denied"; a clean run surfaces as "allowed" (process-exec NOT blocked).
func execTrig(label, name string, args ...string) func() triggerOutcome {
	return func() triggerOutcome {
		out, err := exec.Command(name, args...).CombinedOutput()
		return outcome("exec:"+label, out, err)
	}
}

// readTrig reads a single sensitive path. err (EACCES/ENOENT because a
// KubeArmor file rule denied it) ⇒ "denied".
func readTrig(path string) func() triggerOutcome {
	return func() triggerOutcome {
		data, err := os.ReadFile(path)
		return outcome("read:"+path, data, err)
	}
}

// writeTrig writes then immediately removes a file under a protected
// path. A successful write means the write-outside-mounts policy did NOT
// fire, so it is flagged loudly.
func writeTrig(path string) func() triggerOutcome {
	return func() triggerOutcome {
		if err := os.WriteFile(path, []byte("# komuta-test-app write probe\n"), 0o644); err != nil {
			return outcome("write:"+path, nil, err)
		}
		_ = os.Remove(path)
		return outcome("write:"+path, []byte("write succeeded — POLICY NOT ENFORCED"), nil)
	}
}

// connectTrig opens a single short-timeout TCP connection. A refused/
// timed-out dial (because a Cilium/Hubble policy dropped it) ⇒ "denied";
// a successful connect ⇒ "allowed" (egress NOT enforced) and is closed
// immediately.
func connectTrig(host string, port int) func() triggerOutcome {
	return func() triggerOutcome {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			return outcome("connect:"+addr, nil, err)
		}
		_ = conn.Close()
		return outcome("connect:"+addr, []byte("connected — POLICY NOT ENFORCED"), nil)
	}
}

// dnsTrig resolves a single hostname. The lookup itself is the observable
// event (Tetragon DNS tracing); an NXDOMAIN is expected and still emits
// the query, so it is reported as "allowed" (query observed) rather than
// a hard denial.
func dnsTrig(host string) func() triggerOutcome {
	return func() triggerOutcome {
		if _, err := net.LookupHost(host); err != nil {
			return outcome("dns:"+host,
				[]byte("DNS query emitted (NXDOMAIN expected — query still observed)"), nil)
		}
		return outcome("dns:"+host, []byte("resolved — unexpected"), nil)
	}
}

// ── Named triggers (used by chains + HTTP wrappers) ────────────────
// Most are thin aliases over the generic factories; the ones with
// bespoke logic (install-tool, honey-path, dropped-bin, chains) stay
// hand-written.

func trigExecShell() triggerOutcome  { return execTrig("shell:sh", "sh", "-c", "id; uname -a")() }
func trigReadSecret() triggerOutcome { return readTrig("/etc/shadow")() }

func trigInstallTool() triggerOutcome {
	for _, c := range []string{"apk", "apt-get", "dnf", "yum"} {
		if _, err := exec.LookPath(c); err != nil {
			continue
		}
		out, err := exec.Command(c, "--help").CombinedOutput()
		return outcome("install-tool:"+c, out, err)
	}
	return outcome("install-tool", []byte("no package manager in PATH"), nil)
}

func trigFileTamper() triggerOutcome { return writeTrig("/etc/passwd.injected")() }

func trigNetworkEgress() triggerOutcome {
	target := "http://example.com"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return outcome("network-egress:"+target, nil, err)
	}
	defer resp.Body.Close()
	return outcome("network-egress:"+target,
		[]byte(fmt.Sprintf("HTTP %d — POLICY NOT ENFORCED", resp.StatusCode)), nil)
}

// trigHoneyPath touches a path the operator wired as a Security
// Center "honey path" TracingPolicy. Reading it is otherwise
// harmless, which is exactly why it's the most deterministic
// on-cluster Tetragon trigger. HONEY_PATH env overrides the default.
func trigHoneyPath() triggerOutcome {
	p := os.Getenv("HONEY_PATH")
	if p == "" {
		p = "/var/run/secrets/komuta-honey-token"
	}
	data, err := os.ReadFile(p)
	if err != nil {
		// A non-existent honey file STILL produces a FILE_OPEN
		// syscall Tetragon can flag — the deny/enoent is expected.
		return outcome("honey-path:"+p,
			[]byte("open() attempted (file may not exist — syscall still observed)"), err)
	}
	return outcome("honey-path:"+p, data, nil)
}

// trigDNSExfil resolves a suspicious look-alike domain — a canonical
// DNS-based exfil/C2 indicator Tetragon DNS tracing flags.
func trigDNSExfil() triggerOutcome {
	return dnsTrig("exfil-" + newUUID()[:8] + ".attacker-c2.example")()
}

// trigCapabilityUse attempts a privileged capability (chown of a
// system file) a hardened pod should not hold.
func trigCapabilityUse() triggerOutcome {
	err := os.Chown("/etc/hostname", 0, 0)
	if err != nil {
		return outcome("capability-use:chown(/etc/hostname)", nil, err)
	}
	return outcome("capability-use:chown(/etc/hostname)",
		[]byte("chown succeeded — POLICY NOT ENFORCED"), nil)
}

// trigMountAttempt tries to mount a tmpfs — a container-escape
// precursor KubeArmor's mount rules deny.
func trigMountAttempt() triggerOutcome {
	out, err := exec.Command("mount", "-t", "tmpfs", "none", "/mnt").CombinedOutput()
	return outcome("mount-attempt:tmpfs->/mnt", out, err)
}

// trigDroppedBinExec drops a copy of a known-good binary into /tmp,
// makes it executable, runs it, and cleans up. Exercises the classic
// "attacker drops a tool and runs it" pattern KubeArmor process-exec
// rules should catch (exec of a binary outside the image's known set).
func trigDroppedBinExec() triggerOutcome {
	const dst = "/tmp/komuta-dropped"
	var src string
	for _, c := range []string{"/bin/busybox", "/bin/true", "/bin/sh"} {
		if _, err := os.Stat(c); err == nil {
			src = c
			break
		}
	}
	if src == "" {
		return outcome("exec:dropped-bin", []byte("no source binary to drop"), nil)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return outcome("exec:dropped-bin", nil, err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		return outcome("exec:dropped-bin", nil, err)
	}
	defer os.Remove(dst)
	out, err := exec.Command(dst, "true").CombinedOutput()
	if err != nil {
		return outcome("exec:dropped-bin:"+dst, out, err)
	}
	return outcome("exec:dropped-bin:"+dst,
		[]byte("dropped binary executed — POLICY NOT ENFORCED"), nil)
}

// runChain runs an ordered sequence of triggers ~0.8s apart so the
// backend's finding correlation + IR playbook matcher have a realistic
// window to stitch together.
func runChain(steps ...func() triggerOutcome) []triggerOutcome {
	out := make([]triggerOutcome, 0, len(steps))
	for i, s := range steps {
		out = append(out, s())
		if i < len(steps)-1 {
			time.Sleep(800 * time.Millisecond) // ordered, not simultaneous
		}
	}
	return out
}

// trigAttackChain: recon exec → capability → secret read → egress.
func trigAttackChain() []triggerOutcome {
	return runChain(trigExecShell, trigCapabilityUse, trigReadSecret, trigNetworkEgress)
}

// trigChainCredAccess: read the mounted SA token → reach the cloud
// metadata endpoint → egress to the public internet. Mimics a
// credential-access → SSRF → exfil kill chain.
func trigChainCredAccess() []triggerOutcome {
	return runChain(
		readTrig("/var/run/secrets/kubernetes.io/serviceaccount/token"),
		connectTrig("169.254.169.254", 80),
		trigNetworkEgress,
	)
}

// trigChainPrivesc: spawn a shell → chmod a dropped file executable →
// attempt setuid(0). Mimics a local privilege-escalation chain.
func trigChainPrivesc() []triggerOutcome {
	return runChain(
		execTrig("shell:sh", "sh", "-c", "id"),
		execTrig("chmod:+x", "chmod", "+x", "/tmp/komuta-x"),
		trigSetuidRoot,
	)
}

// ── HTTP wrappers (ad-hoc curl; scenarios call the funcs directly) ──

func registerSecurityRoutes(mux *http.ServeMux) {
	wrap := func(fn func() triggerOutcome) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, fn())
		}
	}
	mux.HandleFunc("POST /control/security/exec-shell", wrap(trigExecShell))
	mux.HandleFunc("POST /control/security/read-secret", wrap(trigReadSecret))
	mux.HandleFunc("POST /control/security/install-tool", wrap(trigInstallTool))
	mux.HandleFunc("POST /control/security/file-tamper", wrap(trigFileTamper))
	mux.HandleFunc("POST /control/security/network-egress", wrap(trigNetworkEgress))
	mux.HandleFunc("POST /control/security/honey-path", wrap(trigHoneyPath))
	mux.HandleFunc("POST /control/security/dns-exfil", wrap(trigDNSExfil))
	mux.HandleFunc("POST /control/security/capability-use", wrap(trigCapabilityUse))
	mux.HandleFunc("POST /control/security/mount-attempt", wrap(trigMountAttempt))
	mux.HandleFunc("POST /control/security/dropped-bin", wrap(trigDroppedBinExec))
	chain := func(fn func() []triggerOutcome) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"chain": fn()})
		}
	}
	mux.HandleFunc("POST /control/security/attack-chain", chain(trigAttackChain))
	mux.HandleFunc("POST /control/security/chain-cred-access", chain(trigChainCredAccess))
	mux.HandleFunc("POST /control/security/chain-privesc", chain(trigChainPrivesc))
}
