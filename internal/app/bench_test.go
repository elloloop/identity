package app

import (
	"context"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/observability"
)

// BenchmarkRPC_OTelDisabled measures the per-RPC overhead when
// GATEWAY_OTEL_ENABLED is false. The DoD says < 100 ns; in practice
// the disabled path is dominated by the in-memory repo work, but
// keeping the benchmark in the suite guards against accidentally
// adding allocation-heavy code on the off path.
func BenchmarkRPC_OTelDisabled(b *testing.B) {
	prevTP := otel.GetTracerProvider()
	otel.SetTracerProvider(tracenoop.NewTracerProvider())
	b.Cleanup(func() { otel.SetTracerProvider(prevTP) })

	cfg := newTestConfig()
	cfg.OTelEnabled = false

	handler, _, stop := buildTestApp(b, cfg)
	defer stop()

	srv := httptest.NewServer(handler)
	defer srv.Close()
	client := identityconnectgen.NewIdentityServiceClient(srv.Client(), srv.URL)

	b.ResetTimer()
	for b.Loop() {
		// Logout with an empty refresh token returns immediately; both
		// bench variants take the same fast path so the delta isolates
		// the OTel overhead.
		_, err := client.Logout(context.Background(), connect.NewRequest(&identitypb.LogoutRequest{}))
		if err != nil {
			b.Fatalf("Logout: %v", err)
		}
	}
}

// BenchmarkObservability_StartClient_NoOp measures the per-call cost
// of the observability.StartClient helper when the global no-op tracer
// is in effect (i.e. GATEWAY_OTEL_ENABLED=false). This is the
// hot-path cost every outbound DB / mailer / IDV span pays on the off
// path; it must stay deep sub-100ns.
func BenchmarkObservability_StartClient_NoOp(b *testing.B) {
	prevTP := otel.GetTracerProvider()
	otel.SetTracerProvider(tracenoop.NewTracerProvider())
	b.Cleanup(func() { otel.SetTracerProvider(prevTP) })
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, end := observability.StartClient(ctx, "bench.op")
		end(nil)
	}
}

// BenchmarkRPC_OTelEnabled measures the per-RPC cost when OTel is on
// with an in-memory exporter so the export step doesn't dominate.
// The delta vs OTelDisabled is what the M8 DoD's "< 100 ns when off"
// is measured against (off path additional cost, not absolute).
func BenchmarkRPC_OTelEnabled(b *testing.B) {
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	b.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	prevTP := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	b.Cleanup(func() { otel.SetTracerProvider(prevTP) })

	cfg := newTestConfig()
	cfg.OTelEnabled = true
	cfg.OTelExporterEndpoint = "ignored"

	handler, _, stop := buildTestApp(b, cfg)
	defer stop()

	srv := httptest.NewServer(handler)
	defer srv.Close()
	client := identityconnectgen.NewIdentityServiceClient(srv.Client(), srv.URL)

	b.ResetTimer()
	for b.Loop() {
		// Logout with an empty refresh token returns immediately; both
		// bench variants take the same fast path so the delta isolates
		// the OTel overhead.
		_, err := client.Logout(context.Background(), connect.NewRequest(&identitypb.LogoutRequest{}))
		if err != nil {
			b.Fatalf("Logout: %v", err)
		}
	}
}
