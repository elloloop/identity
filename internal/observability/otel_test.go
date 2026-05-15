package observability

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/elloloop/identity/internal/config"
)

// TestSetup_Disabled_NoOp confirms that when OTel is off the global
// tracer provider stays on the no-op default and Setup returns a
// no-op shutdown. This guards against accidentally bringing the SDK
// machinery in on the off path.
func TestSetup_Disabled_NoOp(t *testing.T) {
	t.Parallel()

	before := otel.GetTracerProvider()
	shutdown, err := Setup(context.Background(), Config{Enabled: false})
	if err != nil {
		t.Fatalf("Setup(disabled): %v", err)
	}
	defer func() {
		if err := shutdown(context.Background()); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	}()

	// The disabled path may have changed the propagator (we install
	// W3C TraceContext unconditionally) but must NOT have changed the
	// tracer provider.
	if otel.GetTracerProvider() != before {
		// Tolerate "no-op vs no-op" — if the runtime default is itself
		// the noop provider we're good.
		if _, ok := otel.GetTracerProvider().(*tracenoop.TracerProvider); !ok {
			t.Errorf("Setup(disabled) replaced TracerProvider; want unchanged")
		}
	}
}

// TestSetup_EnabledRequiresEndpoint asserts the fail-fast contract:
// GATEWAY_OTEL_ENABLED=true with no endpoint must crash boot, not
// drop traces silently.
func TestSetup_EnabledRequiresEndpoint(t *testing.T) {
	t.Parallel()

	_, err := Setup(context.Background(), Config{Enabled: true, Endpoint: "  "})
	if err == nil {
		t.Fatal("Setup(enabled, empty endpoint): want error, got nil")
	}
	if !strings.Contains(err.Error(), "GATEWAY_OTEL_EXPORTER_ENDPOINT") {
		t.Errorf("error %q does not mention the env var name", err.Error())
	}
}

// TestSetup_EnabledRejectsBadSampleRatio guards the [0,1] contract.
func TestSetup_EnabledRejectsBadSampleRatio(t *testing.T) {
	t.Parallel()

	_, err := Setup(context.Background(), Config{
		Enabled:     true,
		Endpoint:    "localhost:4317",
		SampleRatio: 2.0,
	})
	if err == nil {
		t.Fatal("Setup(sampleRatio=2): want error, got nil")
	}
}

// TestSetup_EnabledRejectsBadProtocol guards the grpc|http contract.
func TestSetup_EnabledRejectsBadProtocol(t *testing.T) {
	t.Parallel()

	_, err := Setup(context.Background(), Config{
		Enabled:     true,
		Endpoint:    "localhost:4317",
		Protocol:    "telepathy",
		SampleRatio: 0.1,
	})
	if err == nil {
		t.Fatal("Setup(protocol=telepathy): want error, got nil")
	}
	if !errors.Is(err, err) {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestFromAppConfig copies env-driven fields into Config; deployers
// rely on this single seam being right.
func TestFromAppConfig(t *testing.T) {
	t.Parallel()

	c := FromAppConfig(&config.Config{
		OTelEnabled:          true,
		OTelExporterEndpoint: "collector:4318",
		OTelExporterProtocol: "http",
		OTelSampleRatio:      0.5,
		OTelDeploymentEnv:    "staging",
		OTelServiceVersion:   "1.2.3",
	})
	if !c.Enabled || c.Endpoint != "collector:4318" || c.Protocol != "http" ||
		c.SampleRatio != 0.5 || c.DeploymentEnv != "staging" || c.ServiceVersion != "1.2.3" {
		t.Fatalf("FromAppConfig produced %#v", c)
	}
}
