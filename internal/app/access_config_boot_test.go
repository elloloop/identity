package app

import (
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

// bootDeps is the minimum viable Deps for New, with the access policy left to
// the caller so each case varies only the thing under test.
func bootDeps(t *testing.T, cfg *config.Config) Deps {
	t.Helper()
	passkeyService, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   "localhost",
		RPName: "Identity Test",
		Origin: "http://localhost:9002",
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	repo := memory.New()

	cfg.DefaultTenantID = "tenant"
	cfg.AuthAllowLocal = true
	cfg.AllowedOrigins = "http://localhost:9002"
	cfg.JWTExpirySeconds = 900
	cfg.RefreshExpirySeconds = 604800
	cfg.LoginChallengeExpirySeconds = 300
	cfg.PasskeyRPID = "localhost"
	cfg.PasskeyRPName = "Identity Test"
	cfg.PasskeyOrigin = "http://localhost:9002"
	cfg.PasskeyChallengeExpirySeconds = 300
	cfg.QRLoginBaseURL = "http://localhost:9002"
	cfg.QRLoginExpirySeconds = 300
	cfg.TOTPIssuer = "Identity Test"

	return Deps{
		Config:             cfg,
		Logger:             zap.NewNop(),
		Signer:             jwttest.NewSigner(t, "app-test"),
		Repo:               repo,
		DB:                 repo,
		Passkeys:           passkeyService,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
	}
}

// An invalid default-project access policy must stop the boot, and the message
// has to name the variables the operator actually set. The validator is shared
// with the config_json path and speaks its vocabulary ("access.blocked_domains"),
// which is right for a stored project config and useless to someone whose
// container just died holding only GATEWAY_* variables — so the wrapping is the
// only thing carrying that, and nothing else would notice if it regressed.
func TestNew_InvalidDefaultProjectAccess_FailsBootNamingTheEnvVars(t *testing.T) {
	// The deny layer is inert on a mode that admits nobody, and "closed" is the
	// default — so this is the misconfiguration an operator hits first.
	_, err := New(bootDeps(t, &config.Config{
		DefaultProjectAccessMode:              "closed",
		DefaultProjectBlockPublicEmailDomains: true,
	}))
	if err == nil {
		t.Fatal("expected New to fail on a deny layer that can never fire")
	}

	for _, want := range []string{
		"GATEWAY_DEFAULT_PROJECT_ACCESS_MODE",
		"GATEWAY_DEFAULT_PROJECT_BLOCK_PUBLIC_EMAIL_DOMAINS",
		"GATEWAY_DEFAULT_PROJECT_BLOCKED_EMAIL_DOMAINS",
		"GATEWAY_DEFAULT_PROJECT_EXEMPT_EMAILS",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("boot error does not name %s — an operator cannot act on it\ngot: %v", want, err)
		}
	}
	// The underlying reason survives the wrapping.
	if !strings.Contains(err.Error(), "inert") {
		t.Errorf("boot error lost the validator's explanation: %v", err)
	}
}

// The mirror case: a well-formed deny layer on a mode that admits someone boots
// cleanly, so the guard above is refusing the misconfiguration and not the
// feature.
func TestNew_ValidDefaultProjectDenyLayer_Boots(t *testing.T) {
	built, err := New(bootDeps(t, &config.Config{
		DefaultProjectAccessMode:              "open",
		DefaultProjectBlockPublicEmailDomains: true,
		DefaultProjectBlockedEmailDomains:     "rival.example",
		DefaultProjectExemptEmails:            "contractor@gmail.com",
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	built.Start()
	t.Cleanup(built.Stop)
}
