package observability

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// TracerName is the instrumentation name carried on every outbound span
// emitted by this server.
const TracerName = "github.com/elloloop/identity"

// Tracer returns the named tracer. Callers should not cache the
// returned trace.Tracer across the global TracerProvider being
// replaced (currently it isn't, after Setup runs once at boot).
func Tracer() trace.Tracer {
	return otel.Tracer(TracerName)
}

// StartClient opens a client-kind span for an outbound call. The
// returned end function records the error (if non-nil) on the span and
// calls span.End() — callers use it as:
//
//	ctx, end := observability.StartClient(ctx, "db.GetUser",
//	    attribute.String("db.tenant", tenantID))
//	defer func() { end(err) }()
//
// When OTel is disabled the global no-op tracer is in effect and this
// allocates only the (very small) no-op Span struct.
func StartClient(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, func(error)) {
	ctx, span := Tracer().Start(
		ctx, name,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)
	return ctx, func(err error) {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}
}
