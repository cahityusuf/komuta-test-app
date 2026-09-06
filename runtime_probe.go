package main

import (
	"encoding/json"
	"io"
	"strings"
)

// This diagnostic is CLI-only. It starts no HTTP listener, telemetry exporter,
// token manager or fault injection and never reads environment or secret files.
type runtimeProbeReport struct {
	SchemaVersion     int               `json:"schemaVersion"`
	Observation       string            `json:"observation"`
	Process           map[string]string `json:"process"`
	AppArmorProfile   string            `json:"appArmorProfile,omitempty"`
	AppArmorReadError string            `json:"appArmorReadError,omitempty"`
}

func writeRuntimeProbe(w io.Writer) {
	_ = json.NewEncoder(w).Encode(observeRuntime())
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
