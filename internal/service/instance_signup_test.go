package service

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/passkeys"
)

const instanceBootstrapPassword = "Bootstrap1!" // upper+lower+digit+special, not common

// newTestAuthServiceMode builds an AuthService whose config carries the
// given identity mode, so the mode=multi rejection path can be tested.
func newTestAuthServiceMode(t *testing.T, repo *fakeRepo, mode string) *AuthService {
	t.Helper()
	cfg := testConfig()
	cfg.IdentityMode = mode
	kr := testKeyRing(t)
	passkeysSvc, _ := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	return NewAuthServiceWithOAuth(
		repo, cfg, kr, passkeysSvc,
		audit.NewLogger(newRecordingAuditWriter(), "test-tenant", nil),
		testTotpKey(), testTotpRecoveryPepper(), email.NewLogOnly(zap.NewNop()), nil, zap.NewNop(),
		defaultTestOAuthRegistry(),
	)
}

func TestInstanceSignup_CreatesFirstAdmin(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)

	res, err := svc.InstanceSignup(ctx, "owner@example.com", instanceBootstrapPassword, "Owner")
	if err != nil {
		t.Fatalf("InstanceSignup: %v", err)
	}
	if res.User == nil || res.User.Role != "admin" {
		t.Fatalf("want role=admin active user, got %#v", res.User)
	}
	if res.User.Status != "active" {
		t.Fatalf("want status=active, got %q", res.User.Status)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatal("want non-empty access + refresh tokens")
	}

	// The admin must be persisted and the guard must now be closed.
	stored, err := repo.GetUser(ctx, res.User.ID)
	if err != nil || stored == nil {
		t.Fatalf("GetUser after signup: %v %#v", err, stored)
	}
	if stored.Role != "admin" {
		t.Fatalf("stored role = %q, want admin", stored.Role)
	}
	if has, _ := repo.HasAnyAdmin(ctx); !has {
		t.Fatal("HasAnyAdmin should be true after bootstrap")
	}
	if got := writer.countByEventType(string(audit.EventInstanceSignup)); got != 1 {
		t.Fatalf("instance_signup audit events = %d, want 1", got)
	}
}

func TestInstanceSignup_RejectedWhenAdminExists(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)

	if _, err := svc.InstanceSignup(ctx, "first@example.com", instanceBootstrapPassword, ""); err != nil {
		t.Fatalf("first InstanceSignup: %v", err)
	}

	// A second attempt — with a different email — must be refused now
	// that an admin exists. The guard is self-disabling.
	_, err := svc.InstanceSignup(ctx, "second@example.com", instanceBootstrapPassword, "")
	if !errors.Is(err, ErrInstanceAlreadyInitialized) {
		t.Fatalf("second InstanceSignup err = %v, want ErrInstanceAlreadyInitialized", err)
	}

	// The rejection must be audited (one success + one rejection event) so
	// post-bootstrap probing of the endpoint is observable.
	if got := writer.countByEventType(string(audit.EventInstanceSignup)); got != 2 {
		t.Fatalf("instance_signup audit events = %d, want 2 (1 success + 1 rejection)", got)
	}
}

func TestInstanceSignup_MemberDoesNotBlockBootstrap(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	// A pre-existing non-admin user must NOT block the first-admin bootstrap.
	if _, err := repo.CreateUser(ctx, &User{Email: "member@example.com", Role: "member", Status: "active"}); err != nil {
		t.Fatalf("seed member: %v", err)
	}

	res, err := svc.InstanceSignup(ctx, "owner@example.com", instanceBootstrapPassword, "")
	if err != nil {
		t.Fatalf("InstanceSignup with a member present: %v", err)
	}
	if res.User.Role != "admin" {
		t.Fatalf("want admin, got %q", res.User.Role)
	}
}

func TestInstanceSignup_MultiModeUnimplemented(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthServiceMode(t, repo, config.IdentityModeMulti)

	_, err := svc.InstanceSignup(ctx, "owner@example.com", instanceBootstrapPassword, "")
	if !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("multi-mode InstanceSignup err = %v, want ErrUnimplemented", err)
	}
	// And it must not have created anything.
	if has, _ := repo.HasAnyAdmin(ctx); has {
		t.Fatal("multi-mode InstanceSignup must not create an admin")
	}
}

func TestInstanceSignup_WeakPasswordRejected(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.InstanceSignup(ctx, "owner@example.com", "weak", "")
	if !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("weak-password err = %v, want ErrWeakPassword", err)
	}
	if has, _ := repo.HasAnyAdmin(ctx); has {
		t.Fatal("no admin should exist after a rejected bootstrap")
	}
}

func TestInstanceSignup_InvalidEmailRejected(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.InstanceSignup(ctx, "not-an-email", instanceBootstrapPassword, "")
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid-email err = %v, want ErrInvalidArgument", err)
	}
}
