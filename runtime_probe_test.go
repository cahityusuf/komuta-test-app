package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRuntimeProbeOnlySelectsProcessSecurityFields(t *testing.T) {
	status := selectedProcessStatus("Name:\tapp\nUid:\t65532 65532 65532 65532\nNoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t0000\nEnvironment: must-not-leak\nCmdline: must-not-leak\n")
	if len(status) != 5 || status["Seccomp"] != "2" {
		t.Fatal(status)
	}
	if _, found := status["Environment"]; found {
		t.Fatal("unexpected field exposed")
	}
	var out bytes.Buffer
	writeRuntimeProbe(&out)
	var report runtimeProbeReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.SchemaVersion != 1 || report.Observation == "" || report.ProcessRole != "diagnostic-exec" {
		t.Fatal("invalid observation", err)
	}
}
