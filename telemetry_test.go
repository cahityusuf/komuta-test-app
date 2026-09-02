package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTelemetryExportsServerTraceOverOtlpHTTP(t *testing.T) {
	received := make(chan string, 1)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case received <- r.URL.Path:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	t.Setenv("OTEL_TRACES_SAMPLER", "always_on")

	shutdown, err := initTelemetry(context.Background())
	if err != nil {
		t.Fatalf("init telemetry: %v", err)
	}

	routes := http.NewServeMux()
	routes.HandleFunc("GET /orders/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/orders/42", nil)
	tracedHTTPHandler(routes, routes).ServeHTTP(recorder, request)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown telemetry: %v", err)
	}

	select {
	case path := <-received:
		if path != "/v1/traces" {
			t.Fatalf("unexpected OTLP path: %s", path)
		}
	case <-ctx.Done():
		t.Fatal("collector did not receive an OTLP trace export")
	}
}
