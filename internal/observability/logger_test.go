package observability

import (
	"context"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// TestLoggerFor_AttachesTraceID asserts the M8 correlation contract:
// when a span is recording in the context, LoggerFor returns a logger
// whose lines carry the active trace id.
func TestLoggerFor_AttachesTraceID(t *testing.T) {
	t.Parallel()

	// Stand up an isolated TracerProvider so the global noop default
	// doesn't leak into this assertion.
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	ctx, span := tp.Tracer("test").Start(context.Background(), "root")
	defer span.End()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	LoggerFor(ctx, logger).Info("hello")

	if logs.Len() != 1 {
		t.Fatalf("want 1 log line, got %d", logs.Len())
	}
	got := logs.All()[0].ContextMap()
	want := span.SpanContext().TraceID().String()
	if got[TraceIDLogField] != want {
		t.Errorf("trace_id = %v, want %v", got[TraceIDLogField], want)
	}
}

// TestLoggerFor_NoSpanReturnsBase asserts no junk trace_id fields are
// added when the context carries no active span. This keeps log
// lines free of all-zero trace ids when OTel is disabled.
func TestLoggerFor_NoSpanReturnsBase(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	LoggerFor(context.Background(), logger).Info("hello")

	if logs.Len() != 1 {
		t.Fatalf("want 1 log line, got %d", logs.Len())
	}
	if _, ok := logs.All()[0].ContextMap()[TraceIDLogField]; ok {
		t.Errorf("trace_id should not be set for non-recording context")
	}
}

func TestTraceIDFromContext(t *testing.T) {
	t.Parallel()

	if got := TraceIDFromContext(context.Background()); got != "" {
		t.Errorf("empty context: trace_id = %q, want \"\"", got)
	}

	tp := sdktrace.NewTracerProvider()
	defer func() { _ = tp.Shutdown(context.Background()) }()
	ctx, span := tp.Tracer("t").Start(context.Background(), "n")
	defer span.End()
	if got := TraceIDFromContext(ctx); got != span.SpanContext().TraceID().String() {
		t.Errorf("trace_id = %q, want %q", got, span.SpanContext().TraceID().String())
	}
}
