package observability

import (
	"context"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// TraceIDLogField is the zap field name carried on every log line
// emitted via LoggerFor(ctx, ...). Deployers searching their log
// backend for a specific trace pivot on this key regardless of the
// backend's structured-log conventions.
const TraceIDLogField = "trace_id"

// LoggerFor returns base with the active trace id from ctx attached as
// a structured field. If no span is recording (e.g. OTel disabled or
// caller serves a request that bypassed instrumentation) the original
// logger is returned unchanged. This avoids polluting log lines with
// the well-known all-zeros trace id.
func LoggerFor(ctx context.Context, base *zap.Logger) *zap.Logger {
	if base == nil {
		return zap.NewNop()
	}
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() || !sc.HasTraceID() {
		return base
	}
	return base.With(zap.String(TraceIDLogField, sc.TraceID().String()))
}

// TraceIDFromContext returns the active trace id from ctx as a hex
// string, or "" if the context carries no recording span. Callers
// embedding the id into non-zap structures (audit details, response
// headers) use this to avoid pulling in the otel/trace package
// directly.
func TraceIDFromContext(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() || !sc.HasTraceID() {
		return ""
	}
	return sc.TraceID().String()
}
