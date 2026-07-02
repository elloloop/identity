package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/passkeys"
)

// perProjectOAuthService builds a service whose default project is
// "default" and whose env registry serves a single Google provider with the
// given client id, with per-project secret decryption wired.
func perProjectOAuthService(t *testing.T, repo *fakeRepo, envGoogleClientID string) *AuthService {
	t.Helper()
	cfg := testConfig()
	cfg.DefaultProjectID = "default"
	passkeysSvc, _ := passkeys.NewWebAuthnService(passkeys.Config{
		RPID: cfg.PasskeyRPID, RPName: cfg.PasskeyRPName, Origin: cfg.PasskeyOrigin,
	})
	return NewAuthServiceWithOAuth(
		repo, cfg, testKeyRing(t), passkeysSvc,
		audit.NewLogger(nil, "test", nil),
		testTotpKey(), testTotpRecoveryPepper(), email.NewLogOnly(zap.NewNop()), nil, zap.NewNop(),
		envGoogleRegistry(envGoogleClientID),
	).WithProjectOAuthSecrets(resolverSecretsKey(), nil)
}

func TestBeginOAuthLogin_PerProjectIsolation(t *testing.T) {
	svc := perProjectOAuthService(t, newFakeRepo(), "env-google")

	// Default project → env provider.
	defRes, err := svc.BeginOAuthLogin(
		WithProjectScope(context.Background(), &ProjectScope{ProjectID: "default"}),
		"google", "https://app/cb")
	if err != nil {
		t.Fatalf("default project BeginOAuthLogin: %v", err)
	}
	if !strings.Contains(defRes.AuthorizationURL, "client_id=env-google") {
		t.Errorf("default project must use env client_id, got %q", defRes.AuthorizationURL)
	}

	// A second project with its OWN google client_id → that client_id.
	projRes, err := svc.BeginOAuthLogin(projectGoogleScope(t, "proj-2", "proj2-google"), "google", "https://app/cb")
	if err != nil {
		t.Fatalf("project BeginOAuthLogin: %v", err)
	}
	if !strings.Contains(projRes.AuthorizationURL, "client_id=proj2-google") {
		t.Errorf("second project must use its own client_id, got %q", projRes.AuthorizationURL)
	}

	// A non-default project without a google config cannot use google.
	_, err = svc.BeginOAuthLogin(
		WithProjectScope(context.Background(), &ProjectScope{ProjectID: "proj-3"}),
		"google", "https://app/cb")
	if !errors.Is(err, ErrOAuthDisabled) {
		t.Errorf("non-default project without google must be disabled, got %v", err)
	}
}
