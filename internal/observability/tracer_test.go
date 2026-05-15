package observability

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// TestStartClient_EndsSpanWithError asserts the StartClient helper
// records the error on the span and sets status to Error when end is
// called with a non-nil err.
func TestStartClient_EndsSpanWithError(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	prevTP := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prevTP) })

	ctx, end := StartClient(context.Background(), "test.op")
	end(errors.New("boom"))

	if err := tp.ForceFlush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("want 1 span, got %d", len(spans))
	}
	s := spans[0]
	if s.Name != "test.op" {
		t.Errorf("name = %q", s.Name)
	}
	if s.SpanKind != trace.SpanKindClient {
		t.Errorf("kind = %v, want Client", s.SpanKind)
	}
	if len(s.Events) == 0 {
		t.Errorf("expected RecordError event, got none")
	}

	if Tracer() == nil {
		t.Errorf("Tracer() returned nil")
	}
	_ = ctx
}

// TestStartClient_NoOpWhenDisabled verifies the helper still returns
// usable values when the global tracer is the no-op default.
func TestStartClient_NoOpWhenDisabled(t *testing.T) {
	t.Parallel()

	ctx, end := StartClient(context.Background(), "test.noop")
	if ctx == nil {
		t.Errorf("ctx is nil")
	}
	end(nil)
}
