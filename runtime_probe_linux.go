//go:build linux

package main

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
)

func readProbeFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return "", err
	}
	if len(b) > 16384 {
		return "", errors.New("probe file exceeded bound")
	}
	return strings.TrimSpace(string(b)), nil
}

func observeRuntime() runtimeProbeReport {
	r := runtimeProbeReport{SchemaVersion: 1, Observation: "process-observation-not-enforcement-proof", Process: map[string]string{}}
	if status, err := readProbeFile("/proc/self/status"); err == nil {
		r.Process = selectedProcessStatus(status)
	}
	// Use the LSM-specific file. A generic attr/current label could belong to
	// another LSM and must not be presented as an AppArmor profile.
	profile, err := readProbeFile("/proc/self/attr/apparmor/current")
	if err == nil && profile != "" {
		r.AppArmorProfile = profile
		return r
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		r.AppArmorReadError = "not_found"
	case errors.Is(err, os.ErrPermission):
		r.AppArmorReadError = "permission_denied"
	case errors.Is(err, syscall.EINVAL):
		r.AppArmorReadError = "invalid_argument"
	default:
		r.AppArmorReadError = "unavailable"
	}
	return r
}
