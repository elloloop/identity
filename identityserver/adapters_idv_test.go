package identityserver

import (
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
)

func TestBuildIDVProvider_Disabled(t *testing.T) {
	t.Parallel()

	got, err := buildIDVProvider(&config.Config{}, zap.NewNop())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != nil {
		t.Fatalf("got = %v; want nil", got)
	}
}

func TestBuildIDVProvider_Stub(t *testing.T) {
	t.Parallel()

	got, err := buildIDVProvider(&config.Config{IDVProvider: "stub"}, zap.NewNop())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got == nil || got.Name() != "stub" {
		t.Fatalf("got = %v", got)
	}
}

func TestBuildIDVProvider_Azure(t *testing.T) {
	t.Parallel()

	got, err := buildIDVProvider(&config.Config{
		IDVProvider:           "azure",
		IDVAzureEndpoint:      "https://test.cognitiveservices.azure.com",
		IDVAzureKey:           "k",
		IDVAzureSessionTTLSec: 600,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got == nil || got.Name() != "azure" {
		t.Fatalf("got = %v", got)
	}
}

func TestBuildIDVProvider_AzureMissingEndpoint(t *testing.T) {
	t.Parallel()

	_, err := buildIDVProvider(&config.Config{IDVProvider: "azure", IDVAzureKey: "k"}, zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("err = %v; want endpoint error", err)
	}
}

func TestBuildIDVProvider_Unknown(t *testing.T) {
	t.Parallel()

	_, err := buildIDVProvider(&config.Config{IDVProvider: "snake-oil"}, zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "snake-oil") {
		t.Fatalf("err = %v", err)
	}
}
