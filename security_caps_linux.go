//go:build linux

package main

import (
	"net"
	"syscall"
)

// Linux-only privileged-capability triggers. Each attempts ONE isolated
// privileged syscall a hardened tenant pod should not be able to make.
// They never persist an escalation: setuid(0) inside a non-root pod
// fails with EPERM (which is exactly the "denied" signal we want); the
// raw socket is closed immediately; ptrace detaches; sethostname is
// restored best-effort; mknod is unlinked. All funnel through
// outcome(...) so err != nil ⇒ "denied" (capability dropped/enforced).

// trigSetuidRoot attempts setuid(0) — needs CAP_SETUID. In a non-root,
// capability-dropped pod this returns EPERM ⇒ denied (the desired state).
func trigSetuidRoot() triggerOutcome {
	if err := syscall.Setuid(0); err != nil {
		return outcome("capability:setuid(0)", nil, err)
	}
	return outcome("capability:setuid(0)",
		[]byte("setuid(0) succeeded — POLICY NOT ENFORCED"), nil)
}

// trigRawSocket opens a raw ICMP socket — needs CAP_NET_RAW. Closed
// immediately on success.
func trigRawSocket() triggerOutcome {
	pc, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return outcome("capability:raw-socket(CAP_NET_RAW)", nil, err)
	}
	_ = pc.Close()
	return outcome("capability:raw-socket(CAP_NET_RAW)",
		[]byte("raw ICMP socket opened — POLICY NOT ENFORCED"), nil)
}

// trigPtrace attempts to ptrace-attach to PID 1 — needs CAP_SYS_PTRACE.
// Detaches immediately if it somehow succeeds.
func trigPtrace() triggerOutcome {
	if err := syscall.PtraceAttach(1); err != nil {
		return outcome("capability:ptrace-attach(pid1)", nil, err)
	}
	_ = syscall.PtraceDetach(1)
	return outcome("capability:ptrace-attach(pid1)",
		[]byte("ptrace attach succeeded — POLICY NOT ENFORCED"), nil)
}

// trigSethostname attempts to change the hostname — needs CAP_SYS_ADMIN.
// On the (undesired) success path it restores the previous hostname.
func trigSethostname() triggerOutcome {
	prev := hostname() // current hostname, for best-effort restore
	if err := syscall.Sethostname([]byte("komuta-test-probe")); err != nil {
		return outcome("capability:sethostname(CAP_SYS_ADMIN)", nil, err)
	}
	_ = syscall.Sethostname([]byte(prev)) // best-effort restore
	return outcome("capability:sethostname(CAP_SYS_ADMIN)",
		[]byte("sethostname succeeded — POLICY NOT ENFORCED"), nil)
}

// trigMknod attempts to create a character device node — needs CAP_MKNOD.
func trigMknod() triggerOutcome {
	const dev = "/tmp/komuta-dev"
	_ = syscall.Unlink(dev)
	// S_IFCHR | 0600, dev_t for major 1 / minor 3 (/dev/null).
	if err := syscall.Mknod(dev, syscall.S_IFCHR|0o600, mkdevT(1, 3)); err != nil {
		return outcome("capability:mknod(CAP_MKNOD)", nil, err)
	}
	_ = syscall.Unlink(dev)
	return outcome("capability:mknod(CAP_MKNOD)",
		[]byte("mknod succeeded — POLICY NOT ENFORCED"), nil)
}

// mkdevT packs a (major,minor) pair into a Linux dev_t (as the int
// syscall.Mknod expects).
func mkdevT(major, minor int) int {
	return (major << 8) | minor
}
