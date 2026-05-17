package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

func newTestConfig() *config.Config {
	// #nosec G101 -- passkey relying-party settings are public WebAuthn metadata.
	return &config.Config{
		DefaultTenantID:               "tenant",
		AuthAllowLocal:                true,
		PasswordSignupEnabled:         true,
		PasswordResetEnabled:          true,
		AllowedOrigins:                "http://localhost:9002",
		JWTExpirySeconds:              900,
		RefreshExpirySeconds:          604800,
		LoginMaxFailedAttempts:        5,
		LoginLockoutSeconds:           900,
		LoginChallengeExpirySeconds:   300,
		PasskeyRPID:                   "localhost",
		PasskeyRPName:                 "Identity Test",
		PasskeyOrigin:                 "http://localhost:9002",
		PasskeyChallengeExpirySeconds: 300,
		QRLoginBaseURL:                "http://localhost:9002",
		QRLoginExpirySeconds:          300,
		TOTPIssuer:                    "Identity Test",
		PasswordResetExpirySeconds:    3600,
	}
}

func buildTestApp(tb testing.TB, cfg *config.Config) (http.Handler, *prometheus.Registry, func()) {
	tb.Helper()

	signer := jwttest.NewSigner(tb, "otel-test")
	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   "localhost",
		RPName: "Identity Test",
		Origin: "http://localhost:9002",
	})
	if err != nil {
		tb.Fatalf("NewWebAuthnService: %v", err)
	}
	repo := memory.New()
	reg := prometheus.NewRegistry()

	handler, stop, err := New(Deps{
		Config:             cfg,
		Logger:             zap.NewNop(),
		Signer:             signer,
		Repo:               repo,
		DB:                 repo,
		Passkeys:           pkSvc,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		MetricsRegistry:    reg,
	})
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	return handler, reg, stop
}

// TestOTel_EnabledProducesSpans_ForRPC asserts the M8 contract: a
// Connect RPC routed through the handler chain produces a span when
// OTel is on. The otelconnect interceptor names the span after the
// procedure, so we assert on PasswordSignup in the recorded names.
func TestOTel_EnabledProducesSpans_ForRPC(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	prevTP := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prevTP) })

	cfg := newTestConfig()
	cfg.OTelEnabled = true
	cfg.OTelExporterEndpoint = "ignored"

	handler, _, stop := buildTestApp(t, cfg)
	defer stop()

	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := identityconnectgen.NewIdentityServiceClient(srv.Client(), srv.URL)
	resp, err := client.PasswordSignup(context.Background(), connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "otel-spans@example.com",
		Password: "Password-12345678a",
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	if resp.Msg.GetUser().GetEmail() != "otel-spans@example.com" {
		t.Fatalf("PasswordSignup: email mismatch")
	}

	if err := tp.ForceFlush(context.Background()); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected spans recorded, got 0")
	}

	var rootCount int
	for _, s := range spans {
		if !s.Parent.IsValid() {
			rootCount++
			if !strings.Contains(s.Name, "PasswordSignup") {
				t.Errorf("root span %q does not name the RPC", s.Name)
			}
		}
	}
	if rootCount == 0 {
		t.Errorf("no root span found; names=%v", spanNames(spans))
	}
}

func spanNames(spans tracetest.SpanStubs) []string {
	out := make([]string, 0, len(spans))
	for _, s := range spans {
		out = append(out, s.Name)
	}
	return out
}

// TestOTel_DisabledNoSpansButMetricsRecord asserts the zero-cost
// contract: GATEWAY_OTEL_ENABLED=false records no spans (the global
// no-op tracer is in effect) but the Prometheus RED metrics still
// observe duration / code labels.
func TestOTel_DisabledNoSpansButMetricsRecord(t *testing.T) {
	prevTP := otel.GetTracerProvider()
	otel.SetTracerProvider(tracenoop.NewTracerProvider())
	t.Cleanup(func() { otel.SetTracerProvider(prevTP) })

	cfg := newTestConfig()
	cfg.OTelEnabled = false

	handler, reg, stop := buildTestApp(t, cfg)
	defer stop()

	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := identityconnectgen.NewIdentityServiceClient(srv.Client(), srv.URL)
	_, err := client.PasswordSignup(context.Background(), connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "otel-off@example.com",
		Password: "Password-12345678a",
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("registry.Gather: %v", err)
	}
	var sawRequests, sawDuration bool
	for _, mf := range mfs {
		switch mf.GetName() {
		case "identity_rpc_requests_total":
			sawRequests = len(mf.GetMetric()) > 0
		case "identity_rpc_duration_seconds":
			sawDuration = len(mf.GetMetric()) > 0
		}
	}
	if !sawRequests || !sawDuration {
		t.Errorf("missing RED metrics; requests=%v duration=%v", sawRequests, sawDuration)
	}
}
