package app

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

func newSingleModeDeps(t *testing.T) Deps {
	t.Helper()
	signer := jwttest.NewSigner(t, "mode-test")
	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   "localhost",
		RPName: "ModeTest",
		Origin: "http://localhost:9002",
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	repo := memory.New()
	return Deps{
		Config: &config.Config{ // #nosec G101 -- passkey relying-party settings are public WebAuthn metadata.
			DefaultTenantID:               "tenant",
			IdentityMode:                  config.IdentityModeSingle,
			AuthAllowLocal:                true,
			PasswordSignupEnabled:         true,
			AllowedOrigins:                "http://localhost:9002",
			JWTExpirySeconds:              900,
			RefreshExpirySeconds:          604800,
			LoginMaxFailedAttempts:        5,
			LoginLockoutSeconds:           900,
			LoginChallengeExpirySeconds:   300,
			PasskeyRPID:                   "localhost",
			PasskeyRPName:                 "ModeTest",
			PasskeyOrigin:                 "http://localhost:9002",
			PasskeyChallengeExpirySeconds: 300,
			QRLoginBaseURL:                "http://localhost:9002",
			QRLoginExpirySeconds:          300,
			TOTPIssuer:                    "ModeTest",
			PasswordResetExpirySeconds:    3600,
		},
		Logger:             zap.NewNop(),
		Signer:             signer,
		Repo:               repo,
		DB:                 repo,
		Passkeys:           pkSvc,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
	}
}

func TestIdentityModeGuard_UnknownMode_Rejected(t *testing.T) {
	deps := newSingleModeDeps(t)
	deps.Config.IdentityMode = "wat"

	_, _, err := New(deps)
	if err == nil {
		t.Fatalf("expected error for unknown mode, got nil")
	}
	if !strings.Contains(err.Error(), "unknown value") {
		t.Fatalf("expected 'unknown value' error, got: %v", err)
	}
}

func TestIdentityModeGuard_Single_RequiresDefaultTenant(t *testing.T) {
	deps := newSingleModeDeps(t)
	deps.Config.DefaultTenantID = ""

	_, _, err := New(deps)
	if err == nil {
		t.Fatalf("expected error for missing default tenant, got nil")
	}
	if !strings.Contains(err.Error(), "DEFAULT_TENANT_ID") {
		t.Fatalf("expected 'DEFAULT_TENANT_ID' error, got: %v", err)
	}
}

func TestIdentityModeGuard_Multi_RequiresTenantAdminAndFactory(t *testing.T) {
	deps := newSingleModeDeps(t)
	deps.Config.IdentityMode = config.IdentityModeMulti

	// neither wired — both nil
	_, _, err := New(deps)
	if err == nil {
		t.Fatalf("expected error for missing wiring in multi mode, got nil")
	}
	if !strings.Contains(err.Error(), "TenantAdmin and RepositoryForTenant") {
		t.Fatalf("expected 'TenantAdmin and RepositoryForTenant' error, got: %v", err)
	}
}

func TestIdentityModeGuard_Multi_WiredOK(t *testing.T) {
	deps := newSingleModeDeps(t)
	deps.Config.IdentityMode = config.IdentityModeMulti

	// Provide minimal multi-mode wiring; the actual values are not
	// exercised here, only their presence is required by the guard.
	deps.TenantAdmin = &stubTenantAdmin{}
	deps.RepositoryForTenant = func(_ string) service.Repository {
		return memory.New()
	}

	_, stop, err := New(deps)
	if err != nil {
		t.Fatalf("expected successful boot in multi mode, got: %v", err)
	}
	if stop != nil {
		t.Cleanup(stop)
	}
}

// stubTenantAdmin is a no-op implementation used only to prove the
// boot guard accepts a non-nil TenantAdmin. The signup flow itself
// is exercised in the integration tests, not here.
type stubTenantAdmin struct{}

func (stubTenantAdmin) CreateTenant(_ context.Context, _, _ string) error { return nil }
func (stubTenantAdmin) PromoteTenantMember(_ context.Context, _, _, _ string) error {
	return nil
}
func (stubTenantAdmin) RemoveTenantMember(_ context.Context, _, _ string) error { return nil }
