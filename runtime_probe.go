package main

import (
	"encoding/json"
	"io"
	"strings"
)

// This diagnostic is CLI-only. It starts no HTTP listener, telemetry exporter,
// token manager or fault injection and never reads environment or secret files.
type runtimeProbeReport struct {
	ProcessRole       string            `json:"processRole"`
	SchemaVersion     int               `json:"schemaVersion"`
	Observation       string            `json:"observation"`
	Process           map[string]string `json:"process"`
	AppArmorProfile   string            `json:"appArmorProfile,omitempty"`
	AppArmorReadError string            `json:"appArmorReadError,omitempty"`
}

func writeRuntimeProbe(w io.Writer) {
	writeRuntimeObservation(w, "diagnostic-exec")
}

func writeRuntimeObservation(w io.Writer, role string) {
	r := observeRuntime()
	r.ProcessRole = role
	_ = json.NewEncoder(w).Encode(r)
}

func selectedProcessStatus(status string) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(status, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "Name", "Uid", "NoNewPrivs", "Seccomp", "CapEff":
			result[key] = strings.TrimSpace(value)
		}
	}
	return result
}
