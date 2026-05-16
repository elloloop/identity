// Package observability wires OpenTelemetry traces for the identity
// server. Deployers point the server at any OTLP-compatible collector
// via GATEWAY_OTEL_*; when disabled, the no-op tracer provider is
// installed and the server pays no per-request cost.
package observability

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"

	"github.com/elloloop/identity/internal/config"
)

// ServiceName is the otel resource attribute every span carries.
const ServiceName = "identity"

// Config controls how the tracer provider is constructed. It mirrors
// the GATEWAY_OTEL_* env knobs; see config.Config for documentation.
type Config struct {
	Enabled        bool
	Endpoint       string
	Protocol       string // "grpc" or "http"
	SampleRatio    float64
	DeploymentEnv  string
	ServiceVersion string
	// Insecure skips TLS on the OTLP transport. Defaults to true since
	// most collectors run inside the cluster network; deployers who
	// front a TLS-only collector will need a follow-up knob.
	Insecure bool
}

// FromAppConfig translates a *config.Config into the observability
// Config used by Setup.
func FromAppConfig(c *config.Config) Config {
	return Config{
		Enabled:        c.OTelEnabled,
		Endpoint:       c.OTelExporterEndpoint,
		Protocol:       c.OTelExporterProtocol,
		SampleRatio:    c.OTelSampleRatio,
		DeploymentEnv:  c.OTelDeploymentEnv,
		ServiceVersion: c.OTelServiceVersion,
		Insecure:       true,
	}
}

// Setup installs the global tracer provider and propagators. When
// cfg.Enabled is false it leaves OTel's no-op default in place and
// returns a no-op shutdown — the hot path then incurs only the
// dispatch through the no-op tracer. The returned shutdown must be
// called during graceful termination; it flushes pending spans up to
// 5 s before forcing the exporter closed.
//
// Setup fails fast when cfg.Enabled is true but cfg.Endpoint is empty
// so a misconfigured deploy crashes at boot rather than silently
// dropping traces.
func Setup(ctx context.Context, cfg Config) (shutdown func(context.Context) error, err error) {
	if !cfg.Enabled {
		// Even with OTel off we install the W3C TraceContext
		// propagator so inbound trace IDs from upstream proxies
		// surface in zap logs. Cost is one map lookup per request.
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, propagation.Baggage{},
		))
		return noopShutdown, nil
	}

	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, errors.New("observability: GATEWAY_OTEL_ENABLED=true but GATEWAY_OTEL_EXPORTER_ENDPOINT is empty")
	}
	if cfg.SampleRatio < 0 || cfg.SampleRatio > 1 {
		return nil, fmt.Errorf("observability: GATEWAY_OTEL_SAMPLE_RATIO=%v out of range [0,1]", cfg.SampleRatio)
	}

	exporter, err := newOTLPExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("observability: build OTLP exporter: %w", err)
	}

	res, err := newResource(ctx, cfg)
	if err != nil {
		_ = exporter.Shutdown(ctx)
		return nil, fmt.Errorf("observability: build resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	return func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return tp.Shutdown(ctx)
	}, nil
}

func newOTLPExporter(ctx context.Context, cfg Config) (*otlptrace.Exporter, error) {
	switch strings.ToLower(cfg.Protocol) {
	case "", "grpc":
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(cfg.Endpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		return otlptracegrpc.New(ctx, opts...)
	case "http":
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(cfg.Endpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		return otlptracehttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("unsupported protocol %q: must be \"grpc\" or \"http\"", cfg.Protocol)
	}
}

func newResource(ctx context.Context, cfg Config) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(ServiceName),
		semconv.ServiceVersion(serviceVersion(cfg.ServiceVersion)),
	}
	if cfg.DeploymentEnv != "" {
		attrs = append(attrs, semconv.DeploymentEnvironmentName(cfg.DeploymentEnv))
	}
	return resource.New(ctx, resource.WithAttributes(attrs...))
}

func serviceVersion(override string) string {
	if override != "" {
		return override
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func noopShutdown(context.Context) error { return nil }
