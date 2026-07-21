//go:build !linux

package main

// Non-Linux stubs for the privileged-capability triggers. The real
// target is Linux (the app deploys on Linux); these exist only so
// `go build` succeeds on the macOS dev machine. Each returns an
// "allowed" outcome noting the platform gap so an accidental run on a
// dev box is obvious rather than a build break.

func capUnsupported(action string) triggerOutcome {
	return outcome("capability:"+action,
		[]byte("not supported on this platform (linux-only trigger)"), nil)
}

func trigSetuidRoot() triggerOutcome  { return capUnsupported("setuid(0)") }
func trigRawSocket() triggerOutcome   { return capUnsupported("raw-socket(CAP_NET_RAW)") }
func trigPtrace() triggerOutcome      { return capUnsupported("ptrace-attach(pid1)") }
func trigSethostname() triggerOutcome { return capUnsupported("sethostname(CAP_SYS_ADMIN)") }
func trigMknod() triggerOutcome       { return capUnsupported("mknod(CAP_MKNOD)") }
