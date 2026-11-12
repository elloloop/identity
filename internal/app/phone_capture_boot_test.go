package app

import (
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/config"
)

// A deployment that captures phone codes boots only when it is plainly local:
// one public address off the machine stops the boot, naming it.
func TestNew_PhoneCodeCaptureBootsOnlyOnALocalDeployment(t *testing.T) {
	capture := func(issuer string) *config.Config {
		return &config.Config{
			DefaultProjectAccessMode: "open",
			SMSEnabled:               true,
			SMSProvider:              config.SMSProviderLocalCapture,
			TemplateMessageProvider:  config.TemplateMessageProviderLocalCapture,
			JWTIssuer:                issuer,
			AppBaseURL:               "http://localhost:9002",
		}
	}

	_, err := New(bootDeps(t, capture("https://auth.example.com")))
	if err == nil {
		t.Fatal("capture with a public issuer booted")
	}
	if !strings.Contains(err.Error(), "GATEWAY_JWT_ISSUER") {
		t.Errorf("the refusal does not name the issuer: %v", err)
	}

	core, logs := observer.New(zapcore.WarnLevel)
	deps := bootDeps(t, capture("http://localhost:9002"))
	deps.Logger = zap.New(core)
	built, err := New(deps)
	if err != nil {
		t.Fatalf("capture on a local deployment: %v", err)
	}
	t.Cleanup(built.Stop)
	if n := logs.FilterMessage("phone_codes_captured_to_email").Len(); n != 1 {
		t.Errorf("got %d capture warnings at boot, want 1", n)
	}
}
