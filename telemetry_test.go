package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"
)

func TestTelemetryExportsServerTraceOverOtlpHTTP(t *testing.T) {
	received := make(chan *collectortracepb.ExportTraceServiceRequest, 1)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" {
			t.Errorf("unexpected OTLP path: %s", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read OTLP request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		request := &collectortracepb.ExportTraceServiceRequest{}
		if err := proto.Unmarshal(body, request); err != nil {
			t.Errorf("decode OTLP request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		select {
		case received <- request:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	t.Setenv("OTEL_TRACES_SAMPLER", "always_on")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "service.name=komuta-test-app,komuta.service_id=test-service-id")

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
	case exported := <-received:
		spans := exported.GetResourceSpans()
		if len(spans) != 1 || len(spans[0].GetScopeSpans()) != 1 || len(spans[0].GetScopeSpans()[0].GetSpans()) != 1 {
			t.Fatalf("unexpected exported span shape: %#v", exported)
		}
		span := spans[0].GetScopeSpans()[0].GetSpans()[0]
		if span.GetName() != "GET /orders/{id}" {
			t.Fatalf("unexpected span name: %q", span.GetName())
		}
		if got := attributeValue(span.GetAttributes(), "http.route"); got != "/orders/{id}" {
			t.Fatalf("unexpected http.route: %q", got)
		}
		resourceAttrs := spans[0].GetResource().GetAttributes()
		if got := attributeValue(resourceAttrs, "service.name"); got != "komuta-test-app" {
			t.Fatalf("unexpected service.name: %q", got)
		}
		if got := attributeValue(resourceAttrs, "komuta.service_id"); got != "test-service-id" {
			t.Fatalf("unexpected komuta.service_id: %q", got)
		}
	case <-ctx.Done():
		t.Fatal("collector did not receive an OTLP trace export")
	}
}

func attributeValue(attributes []*commonpb.KeyValue, key string) string {
	for _, item := range attributes {
		if item.GetKey() == key {
			return item.GetValue().GetStringValue()
		}
	}
	return ""
}
