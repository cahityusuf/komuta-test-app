//go:build !linux

package main

func observeRuntime() runtimeProbeReport {
	return runtimeProbeReport{SchemaVersion: 1, Observation: "unsupported-platform", Process: map[string]string{}, AppArmorReadError: "unsupported-platform"}
}
