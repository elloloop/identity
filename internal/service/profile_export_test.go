package service

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// newExportProfileService wires a ProfileService over the full fakeRepo (user,
// TOTP, linked identities, audit events) and a fakeDB (sessions, passkeys) —
// ExportMyData aggregates from both sources.
func newExportProfileService(repo *fakeRepo, db *fakeDB) *ProfileService {
	auditLog := audit.NewLogger(nil, "test-tenant", zap.NewNop())
	return NewProfileService(repo, db, "test-tenant", auditLog, zap.NewNop())
}

func TestExportMyData_AggregatesCallerData(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	db := newFakeDB()
	svc := newExportProfileService(repo, db)

	const farFuture = int64(9_000_000_000_000)
	aliceID, err := repo.CreateUser(ctx, &User{
		Email: "alice@export.test", Name: "Alice", Role: "member",
		Status: StatusActive, PasswordHash: "argon2-secret-hash",
	})
	if err != nil {
		t.Fatalf("CreateUser alice: %v", err)
	}
	bobID, err := repo.CreateUser(ctx, &User{Email: "bob@export.test", Status: StatusActive})
	if err != nil {
		t.Fatalf("CreateUser bob: %v", err)
	}

	// Session + passkey live in the graph DB (what ListMySessions/ListMyPasskeys read).
	db.addRefreshToken("sess-alice", aliceID, farFuture)
	db.addPasskey("pk-alice", aliceID, "cred-alice", "Alice iPhone")
	// Bob's session/passkey must never surface in Alice's export.
	db.addRefreshToken("sess-bob", bobID, farFuture)
	db.addPasskey("pk-bob", bobID, "cred-bob", "Bob Pixel")

	if err := repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: aliceID, Provider: "google", ProviderUserID: "g-alice",
		EmailAtLinkTime: "alice@export.test", CreatedAt: 500,
	}); err != nil {
		t.Fatalf("CreateOAuthIdentity: %v", err)
	}
	if _, err := repo.CreateTotpCredential(ctx, &TotpCredRecord{
		UserID: aliceID, SecretEncrypted: "totp-secret-never-exported", Verified: true,
	}); err != nil {
		t.Fatalf("CreateTotpCredential: %v", err)
	}

	// Audit: Alice as actor, Alice as target (admin action), and Bob's event.
	seedAudit(t, repo, &AuditEvent{EventType: "login_success", ActorUserID: aliceID, TargetUserID: aliceID, CreatedAt: 100})
	seedAudit(t, repo, &AuditEvent{EventType: "admin_reset_password", ActorUserID: "system:admin", TargetUserID: aliceID, CreatedAt: 300})
	seedAudit(t, repo, &AuditEvent{EventType: "login_failure", ActorUserID: bobID, TargetUserID: bobID, CreatedAt: 200})

	export, err := svc.ExportMyData(ctx, aliceID)
	if err != nil {
		t.Fatalf("ExportMyData: %v", err)
	}

	if export.FormatVersion != ExportFormatVersion {
		t.Errorf("FormatVersion = %d, want %d", export.FormatVersion, ExportFormatVersion)
	}
	if export.ExportedAtMs <= 0 {
		t.Errorf("ExportedAtMs = %d, want > 0", export.ExportedAtMs)
	}
	if export.User == nil || export.User.ID != aliceID || export.User.Email != "alice@export.test" {
		t.Fatalf("User = %#v, want alice", export.User)
	}
	if len(export.Sessions) != 1 || export.Sessions[0].ID != "sess-alice" {
		t.Fatalf("Sessions = %#v, want only alice's", export.Sessions)
	}
	if len(export.Passkeys) != 1 || export.Passkeys[0].CredentialID != "cred-alice" {
		t.Fatalf("Passkeys = %#v, want only alice's", export.Passkeys)
	}
	if len(export.LinkedIdentities) != 1 || export.LinkedIdentities[0].Provider != "google" {
		t.Fatalf("LinkedIdentities = %#v, want google", export.LinkedIdentities)
	}
	if !export.TotpEnabled {
		t.Error("TotpEnabled = false, want true (verified credential present)")
	}
	if len(export.AuditEvents) != 2 {
		t.Fatalf("AuditEvents = %d, want 2 (alice actor + alice target)", len(export.AuditEvents))
	}
	// Newest first: the admin reset (300) precedes the login (100).
	if export.AuditEvents[0].CreatedAt != 300 || export.AuditEvents[1].CreatedAt != 100 {
		t.Errorf("audit order = %d,%d, want 300,100", export.AuditEvents[0].CreatedAt, export.AuditEvents[1].CreatedAt)
	}
}

// TestExportMyData_NeverIncludesAnotherUser is the scoping guarantee: nothing
// belonging to a second user may appear in the caller's export.
func TestExportMyData_NeverIncludesAnotherUser(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	db := newFakeDB()
	svc := newExportProfileService(repo, db)

	const farFuture = int64(9_000_000_000_000)
	aliceID, _ := repo.CreateUser(ctx, &User{Email: "alice2@export.test", Status: StatusActive})
	bobID, _ := repo.CreateUser(ctx, &User{Email: "bob2@export.test", Status: StatusActive})

	db.addRefreshToken("bob-sess", bobID, farFuture)
	db.addPasskey("bob-pk", bobID, "bob-cred", "Bob device")
	if err := repo.CreateOAuthIdentity(ctx, &OAuthIdentity{UserID: bobID, Provider: "github", ProviderUserID: "gh-bob", CreatedAt: 10}); err != nil {
		t.Fatalf("CreateOAuthIdentity bob: %v", err)
	}
	seedAudit(t, repo, &AuditEvent{EventType: "login_success", ActorUserID: bobID, TargetUserID: bobID, CreatedAt: 10})

	export, err := svc.ExportMyData(ctx, aliceID)
	if err != nil {
		t.Fatalf("ExportMyData: %v", err)
	}
	if len(export.Sessions) != 0 {
		t.Errorf("Sessions = %#v, want none of bob's", export.Sessions)
	}
	if len(export.Passkeys) != 0 {
		t.Errorf("Passkeys = %#v, want none of bob's", export.Passkeys)
	}
	if len(export.LinkedIdentities) != 0 {
		t.Errorf("LinkedIdentities = %#v, want none of bob's", export.LinkedIdentities)
	}
	if len(export.AuditEvents) != 0 {
		t.Errorf("AuditEvents = %#v, want none of bob's", export.AuditEvents)
	}
	if export.TotpEnabled {
		t.Error("TotpEnabled = true, want false (alice has no TOTP)")
	}
}

// TestExportMyData_OmitsSecrets asserts no secret material leaves the boundary.
func TestExportMyData_OmitsSecrets(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	db := newFakeDB()
	svc := newExportProfileService(repo, db)

	aliceID, _ := repo.CreateUser(ctx, &User{
		Email: "secret@export.test", Status: StatusActive, PasswordHash: "top-secret-hash",
	})
	if _, err := repo.CreateTotpCredential(ctx, &TotpCredRecord{
		UserID: aliceID, SecretEncrypted: "enc-totp-secret", Verified: true,
	}); err != nil {
		t.Fatalf("CreateTotpCredential: %v", err)
	}

	export, err := svc.ExportMyData(ctx, aliceID)
	if err != nil {
		t.Fatalf("ExportMyData: %v", err)
	}
	if export.User.PasswordHash != "" {
		t.Errorf("export leaked password hash: %q", export.User.PasswordHash)
	}
	// TOTP status is a bare bool — the secret is only ever reflected as enabled.
	if !export.TotpEnabled {
		t.Error("TotpEnabled = false, want true")
	}
}

func TestExportMyData_Validation(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newExportProfileService(repo, newFakeDB())

	if _, err := svc.ExportMyData(ctx, "  "); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("blank user_id: err = %v, want ErrInvalidArgument", err)
	}
	if _, err := svc.ExportMyData(ctx, "nonexistent-user"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown user: err = %v, want ErrNotFound", err)
	}
}

func seedAudit(t *testing.T, repo *fakeRepo, e *AuditEvent) {
	t.Helper()
	if _, err := repo.CreateAuditEvent(context.Background(), e); err != nil {
		t.Fatalf("CreateAuditEvent: %v", err)
	}
}
