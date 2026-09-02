package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// initTelemetry activates tracing only after Komuta has supplied the rollout
// configuration. This lets the SDK code ship before the wizard is completed,
// without assuming an OTLP destination or leaking a cluster address into the
// repository.
func initTelemetry(ctx context.Context) (func(context.Context) error, error) {
	exporterName := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_EXPORTER")))
	if exporterName == "" || exporterName == "none" {
		return func(context.Context) error { return nil }, nil
	}
	if exporterName != "otlp" {
		return nil, errors.New("OTEL_TRACES_EXPORTER must be otlp or none")
	}

	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}

	serviceResource, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			"",
			attribute.String("service.version", AppVersion),
		),
	)
	if err != nil {
		return nil, err
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(serviceResource),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	return provider.Shutdown, nil
}

// tracedHTTPHandler records inbound requests and updates the span with the
// Go 1.22 ServeMux route pattern after routing. Route templates keep IDs and
// search terms out of operation names and make endpoint grouping useful.
func tracedHTTPHandler(routes *http.ServeMux, next http.Handler) http.Handler {
	routeAware := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := routes.Handler(r)
		next.ServeHTTP(w, r)
		if pattern == "" {
			return
		}
		span := trace.SpanFromContext(r.Context())
		span.SetName(pattern)
		span.SetAttributes(attribute.String("http.route", pattern))
	})
	return otelhttp.NewHandler(
		routeAware,
		"HTTP request",
		otelhttp.WithFilter(func(r *http.Request) bool {
			return r.URL.Path != "/healthz" && r.URL.Path != "/readyz"
		}),
	)
}

func tracedHTTPClient(timeout time.Duration, transport http.RoundTripper) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: otelhttp.NewTransport(transport),
	}
}
