package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/graph"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
)

func newTestAdminService(db *fakeDB) *AdminService {
	return newTestAdminServiceWithRepo(db, newFakeRepo())
}

func newTestAdminServiceWithRepo(db *fakeDB, repo Repository) *AdminService {
	auditLog := audit.NewLogger(nil, "test-tenant", zap.NewNop())
	cfg := config.Load()
	return NewAdminService(repo, db, "test-tenant", auditLog, cfg, nil, zap.NewNop())
}

// newTestAdminServiceWithAudit builds an AdminService whose audit
// logger writes to the supplied recordingAuditWriter so the DeleteUser
// tests can assert the EventUserDeleted event was emitted.
func newTestAdminServiceWithAudit(db *fakeDB, repo Repository, writer *recordingAuditWriter) *AdminService {
	auditLog := audit.NewLogger(writer, "test-tenant", zap.NewNop())
	cfg := config.Load()
	return NewAdminService(repo, db, "test-tenant", auditLog, cfg, nil, zap.NewNop())
}

func TestAdminService_InviteUser_HappyPath(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	svc := newTestAdminService(db)

	result, err := svc.InviteUser(
		context.Background(), "admin-1",
		"new@test.com", "New User", "member", "recover@test.com",
		1024*1024, false,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.User == nil {
		t.Fatal("expected user in result")
	}
	if result.User.Email != "new@test.com" {
		t.Errorf("expected email new@test.com, got %q", result.User.Email)
	}
	if result.User.Status != "invited" {
		t.Errorf("expected status invited, got %q", result.User.Status)
	}
	if result.InvitationToken == "" {
		t.Error("expected non-empty invitation token")
	}
	if !strings.Contains(result.SetupURL, result.InvitationToken) {
		t.Error("setup URL should contain the invitation token")
	}
	if result.TemporaryPassword != "" {
		t.Error("expected no temp password for non-immediate invite")
	}
}

func TestAdminService_InviteUser_CreateImmediately(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	svc := newTestAdminService(db)

	result, err := svc.InviteUser(
		context.Background(), "admin-1",
		"imm@test.com", "Immediate", "member", "", 0, true,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.User.Status != "active" {
		t.Errorf("expected status active, got %q", result.User.Status)
	}
	if result.TemporaryPassword == "" {
		t.Error("expected a temp password for immediate invite")
	}
}

func TestAdminService_InviteUser_NonAdminDenied(t *testing.T) {
	db := newFakeDB()
	db.addUser("member-1", "member@test.com", "Member", "member", "active")
	svc := newTestAdminService(db)

	_, err := svc.InviteUser(
		context.Background(), "member-1",
		"new@test.com", "New", "member", "", 0, false,
	)
	if err == nil {
		t.Fatal("expected error for non-admin")
	}
	if !strings.Contains(err.Error(), "admin role required") {
		t.Errorf("expected admin role required, got %q", err.Error())
	}
}

func TestAdminService_InviteUser_DuplicateEmail(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("existing-1", "dup@test.com", "Existing", "member", "active")
	svc := newTestAdminService(db)

	_, err := svc.InviteUser(
		context.Background(), "admin-1",
		"dup@test.com", "Dup", "member", "", 0, false,
	)
	if err == nil {
		t.Fatal("expected error for duplicate email")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected already exists error, got %q", err.Error())
	}
}

func TestAdminService_InviteUser_InvalidEmail(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	svc := newTestAdminService(db)

	_, err := svc.InviteUser(
		context.Background(), "admin-1",
		"bademail", "Bad", "member", "", 0, false,
	)
	if err == nil {
		t.Fatal("expected error for invalid email")
	}
}

func TestAdminService_InviteUser_DeniedByAccessMode(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	svc := newTestAdminService(db)

	// Allowlist project that does NOT list the invitee: the invite would
	// dead-end at redemption, so it must be refused up front.
	ctx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "test-tenant",
		Access:    ProjectAccessConfig{Mode: AccessModeAllowlist, AllowedEmails: []string{"allowed@test.com"}},
	})
	_, err := svc.InviteUser(ctx, "admin-1", "outsider@test.com", "Outsider", "member", "", 1024, false)
	if !errors.Is(err, ErrAccessNotAllowed) {
		t.Fatalf("expected ErrAccessNotAllowed, got %v", err)
	}
}

func TestAdminService_InviteUser_AllowedByAccessMode(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	svc := newTestAdminService(db)

	// Same allowlist project, invitee IS on the list → the invite proceeds.
	ctx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "test-tenant",
		Access:    ProjectAccessConfig{Mode: AccessModeAllowlist, AllowedEmails: []string{"allowed@test.com"}},
	})
	result, err := svc.InviteUser(ctx, "admin-1", "allowed@test.com", "Allowed", "member", "", 1024, false)
	if err != nil {
		t.Fatalf("unexpected error for on-list invitee: %v", err)
	}
	if result.User == nil || result.User.Email != "allowed@test.com" {
		t.Fatalf("expected invited user allowed@test.com, got %+v", result.User)
	}
}

func TestAdminService_DeactivateUser_HappyPath(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("target-1", "target@test.com", "Target", "member", "active")
	svc := newTestAdminService(db)

	err := svc.DeactivateUser(context.Background(), "admin-1", "target-1", "leaving")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify status changed.
	node, _ := db.GetNode(context.Background(), "", "", typeUser, "target-1")
	if node == nil {
		t.Fatal("target user should still exist")
	}
	if pstr(node.Payload, ufStatus) != "deactivated" {
		t.Errorf("expected deactivated, got %q", pstr(node.Payload, ufStatus))
	}
}

func TestAdminService_DeactivateUser_CannotSelf(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	svc := newTestAdminService(db)

	err := svc.DeactivateUser(context.Background(), "admin-1", "admin-1", "")
	if err == nil {
		t.Fatal("expected error when deactivating self")
	}
	if !strings.Contains(err.Error(), "cannot deactivate themselves") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAdminService_ReactivateUser_HappyPath(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("target-1", "target@test.com", "Target", "member", "deactivated")
	svc := newTestAdminService(db)

	err := svc.ReactivateUser(context.Background(), "admin-1", "target-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	node, _ := db.GetNode(context.Background(), "", "", typeUser, "target-1")
	if pstr(node.Payload, ufStatus) != "active" {
		t.Errorf("expected active, got %q", pstr(node.Payload, ufStatus))
	}
}

// TestAdminService_ReactivateUser_PendingParentalConsentRejected proves that an
// admin cannot use the ordinary reactivation path to flip a child-band account
// out of pending_parental_consent, which would bypass the COPPA consent gate
// (issue #256). The only valid exit from that state is the dedicated
// parental-consent flow.
func TestAdminService_ReactivateUser_PendingParentalConsentRejected(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("child-1", "child@test.com", "Child", "member", StatusPendingParentalConsent)
	svc := newTestAdminService(db)

	err := svc.ReactivateUser(context.Background(), "admin-1", "child-1")
	if !errors.Is(err, ErrParentalConsentRequired) {
		t.Fatalf("expected ErrParentalConsentRequired, got %v", err)
	}

	// Status must be unchanged — the account stays gated.
	node, _ := db.GetNode(context.Background(), "", "", typeUser, "child-1")
	if pstr(node.Payload, ufStatus) != StatusPendingParentalConsent {
		t.Errorf("expected status to remain %q, got %q",
			StatusPendingParentalConsent, pstr(node.Payload, ufStatus))
	}
}

func TestAdminService_ResetUserPassword_TempPassword(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("target-1", "target@test.com", "Target", "member", "active")
	svc := newTestAdminService(db)

	result, err := svc.ResetUserPassword(context.Background(), "admin-1", "target-1", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TemporaryPassword == "" {
		t.Error("expected a temporary password")
	}
	if result.ResetToken != "" {
		t.Error("expected no reset token when generating temp password")
	}
}

func TestAdminService_ResetUserPassword_ResetToken(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("target-1", "target@test.com", "Target", "member", "active")
	svc := newTestAdminService(db)

	result, err := svc.ResetUserPassword(context.Background(), "admin-1", "target-1", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResetToken == "" {
		t.Error("expected a reset token")
	}
	if result.TemporaryPassword != "" {
		t.Error("expected no temp password when generating reset token")
	}
}

func TestAdminService_SetUserQuota_HappyPath(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("target-1", "target@test.com", "Target", "member", "active")
	svc := newTestAdminService(db)

	err := svc.SetUserQuota(context.Background(), "admin-1", "target-1", 1024*1024*1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAdminService_SetUserQuota_NegativeRejected(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("target-1", "target@test.com", "Target", "member", "active")
	svc := newTestAdminService(db)

	err := svc.SetUserQuota(context.Background(), "admin-1", "target-1", -100)
	if err == nil {
		t.Fatal("expected error for negative quota")
	}
}

func TestAdminService_ListUsers_WithFilter(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("user-1", "alice@test.com", "Alice", "member", "active")
	db.addUser("user-2", "bob@test.com", "Bob", "member", "deactivated")
	svc := newTestAdminService(db)

	users, _, total, err := svc.ListUsers(context.Background(), "admin-1", "active", "", "", 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should include admin-1 and user-1 (both active).
	if total < 2 {
		t.Errorf("expected at least 2 active users, got %d", total)
	}
	for _, u := range users {
		if u.Status != "active" {
			t.Errorf("expected active, got %q for user %s", u.Status, u.ID)
		}
	}
}

func TestAdminService_GetUser_NotFound(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	svc := newTestAdminService(db)

	_, err := svc.GetUser(context.Background(), "admin-1", "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found, got %q", err.Error())
	}
}

func TestAdminService_UpdateUser_HappyPath(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("user-1", "user@test.com", "Old Name", "member", "active")
	svc := newTestAdminService(db)

	user, err := svc.UpdateUser(context.Background(), "admin-1", "user-1", "New Name", "guest", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Name != "New Name" {
		t.Errorf("expected New Name, got %q", user.Name)
	}
	if user.Role != "guest" {
		t.Errorf("expected guest, got %q", user.Role)
	}
}

func TestAdminService_DBError_Propagated(t *testing.T) {
	db := newFakeDB()
	db.err = errors.New("db unavailable")
	svc := newTestAdminService(db)

	_, err := svc.InviteUser(context.Background(), "admin-1", "a@b.com", "", "member", "", 0, false)
	if err == nil {
		t.Fatal("expected error when DB fails")
	}
}

// ── DeactivateUser revocation (Finding D) ──────────────────────────────

func TestAdminService_DeactivateUser_RevokesSessionsAndRefreshTokens(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("target-1", "target@test.com", "Target", "member", "active")

	repo := newFakeRepo()
	repo.users["target-1"] = &User{ID: "target-1", Email: "target@test.com", Status: "active"}
	if _, err := repo.CreateRefreshToken(ctx, &RefreshTokenRecord{TokenHash: "rt-1", UserID: "target-1", ExpiresAt: 9_000_000_000_000}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	if _, err := repo.CreateSession(ctx, &SessionRecord{SID: "sid-1", UserID: "target-1", CreatedAtMs: 100}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	svc := newTestAdminServiceWithRepo(db, repo)
	if err := svc.DeactivateUser(ctx, "admin-1", "target-1", "leaving"); err != nil {
		t.Fatalf("DeactivateUser: %v", err)
	}

	if rec, err := repo.FindRefreshTokenByHashIncludingConsumed(ctx, "rt-1"); err != nil || rec != nil {
		t.Fatalf("refresh token must be deleted: err=%v rec=%#v", err, rec)
	}
	sess, err := repo.GetSessionBySid(ctx, "sid-1")
	if err != nil || sess == nil {
		t.Fatalf("session lookup: err=%v rec=%#v", err, sess)
	}
	if sess.RevokedAtMs == 0 {
		t.Fatalf("session must be revoked, RevokedAtMs=%d", sess.RevokedAtMs)
	}
}

// ── DeleteUser ─────────────────────────────────────────────────────────

func TestAdminService_DeleteUser_HappyPath(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")

	repo := newFakeRepo()
	repo.users["target-1"] = &User{ID: "target-1", Email: "target@test.com", Status: "active"}
	if _, err := repo.CreateRefreshToken(ctx, &RefreshTokenRecord{TokenHash: "rt-1", UserID: "target-1", ExpiresAt: 9_000_000_000_000}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	if _, err := repo.CreateSession(ctx, &SessionRecord{SID: "sid-1", UserID: "target-1", CreatedAtMs: 100}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	writer := newRecordingAuditWriter()
	svc := newTestAdminServiceWithAudit(db, repo, writer)

	if err := svc.DeleteUser(ctx, "admin-1", "target-1"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	// User gone from the repo.
	if u, err := repo.GetUser(ctx, "target-1"); err != nil || u != nil {
		t.Fatalf("user must be deleted: err=%v rec=%#v", err, u)
	}
	// Refresh tokens gone.
	if rec, err := repo.FindRefreshTokenByHashIncludingConsumed(ctx, "rt-1"); err != nil || rec != nil {
		t.Fatalf("refresh token must be deleted: err=%v rec=%#v", err, rec)
	}
	// Session gone (cascade delete).
	if sess, err := repo.GetSessionBySid(ctx, "sid-1"); err != nil || sess != nil {
		t.Fatalf("session must be deleted: err=%v rec=%#v", err, sess)
	}
	// Email reusable.
	if _, err := repo.CreateUser(ctx, &User{Email: "target@test.com", Status: "active"}); err != nil {
		t.Fatalf("email must be reusable after delete: %v", err)
	}
	// Audit event emitted.
	if n := writer.countByEventType(string(audit.EventUserDeleted)); n != 1 {
		t.Fatalf("expected 1 user_deleted audit event, got %d", n)
	}
}

func TestAdminService_DeleteUser_CleansGroupMemberOfEdges(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")

	repo := newFakeRepo()
	repo.users["target-1"] = &User{ID: "target-1", Email: "g@test.com", Status: "active"}

	// Seed two MEMBER_OF edges from the target user to two groups, plus
	// an unrelated user's edge that must survive.
	seed := []graph.Operation{
		{Type: graph.OpCreateEdge, EdgeTypeID: edgeMemberOf, FromNodeID: "target-1", ToNodeID: "grp-1"},
		{Type: graph.OpCreateEdge, EdgeTypeID: edgeMemberOf, FromNodeID: "target-1", ToNodeID: "grp-2"},
		{Type: graph.OpCreateEdge, EdgeTypeID: edgeMemberOf, FromNodeID: "other-user", ToNodeID: "grp-1"},
	}
	if _, err := db.ExecuteAtomic(ctx, "t", "system:admin", seed); err != nil {
		t.Fatalf("seed edges: %v", err)
	}

	svc := newTestAdminServiceWithRepo(db, repo)
	if err := svc.DeleteUser(ctx, "admin-1", "target-1"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	// The cross-user edge read MUST use the tenant-admin actor; a per-user
	// actor (user:<admin>) would silently return zero rows on a graph backend
	// and make this cleanup a no-op. Asserting it here catches a
	// regression that the edge-existence checks below cannot (the fake
	// ignores the actor for filtering).
	if got := db.lastEdgesFromActor; got != tenantAdminActor {
		t.Fatalf("GetEdgesFrom actor = %q, want %q (cross-user read must use tenant-admin)", got, tenantAdminActor)
	}

	// The target's memberships are gone. (The membership edges were seeded
	// by system:admin while the delete is driven by admin-1 — the realistic
	// different-creator case.)
	if edges, err := db.GetEdgesFrom(ctx, "t", "system:admin", "target-1", edgeMemberOf); err != nil || len(edges) != 0 {
		t.Fatalf("target memberships must be cleaned: err=%v edges=%#v", err, edges)
	}
	// grp-1 no longer has the target, but still has the unrelated user.
	edgesTo, err := db.GetEdgesTo(ctx, "t", "system:admin", "grp-1", edgeMemberOf)
	if err != nil {
		t.Fatalf("GetEdgesTo: %v", err)
	}
	for _, e := range edgesTo {
		if e.FromNodeID == "target-1" {
			t.Fatalf("grp-1 still references the deleted user")
		}
	}
	if len(edgesTo) != 1 || edgesTo[0].FromNodeID != "other-user" {
		t.Fatalf("unrelated membership must survive, got %#v", edgesTo)
	}
}

func TestAdminService_DeleteUser_CannotSelf(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	repo := newFakeRepo()
	repo.users["admin-1"] = &User{ID: "admin-1", Email: "admin@test.com", Status: "active"}
	svc := newTestAdminServiceWithRepo(db, repo)

	err := svc.DeleteUser(context.Background(), "admin-1", "admin-1")
	if err == nil || !strings.Contains(err.Error(), "cannot delete themselves") {
		t.Fatalf("expected cannot-delete-self error, got %v", err)
	}
}

func TestAdminService_DeleteUser_NotFound(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	svc := newTestAdminServiceWithRepo(db, newFakeRepo())

	err := svc.DeleteUser(context.Background(), "admin-1", "ghost")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestAdminService_DeleteUser_NonAdminDenied(t *testing.T) {
	db := newFakeDB()
	db.addUser("member-1", "member@test.com", "Member", "member", "active")
	repo := newFakeRepo()
	repo.users["target-1"] = &User{ID: "target-1", Email: "target@test.com", Status: "active"}
	svc := newTestAdminServiceWithRepo(db, repo)

	err := svc.DeleteUser(context.Background(), "member-1", "target-1")
	if err == nil || !strings.Contains(err.Error(), "admin role required") {
		t.Fatalf("expected admin-role-required error, got %v", err)
	}
	// Target must NOT have been deleted.
	if u, _ := repo.GetUser(context.Background(), "target-1"); u == nil {
		t.Fatal("target must survive a denied delete")
	}
}

func TestAdminService_DeleteUser_EmptyTarget(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	svc := newTestAdminServiceWithRepo(db, newFakeRepo())

	err := svc.DeleteUser(context.Background(), "admin-1", "")
	if err == nil || !strings.Contains(err.Error(), "user_id is required") {
		t.Fatalf("expected user_id-required error, got %v", err)
	}
}

// ── DeleteUser repository error branches ───────────────────────────────
//
// Each case drives one failure injected into the repo so the
// corresponding wrap in AdminService.DeleteUser is exercised and the
// returned error carries the right context. The errorRepo embeds the
// happy fakeRepo, so only the targeted call fails.

func TestAdminService_DeleteUser_FetchUserError(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	repo := &errorRepo{fakeRepo: newFakeRepo(), failGetUser: true}
	repo.users["target-1"] = &User{ID: "target-1", Email: "target@test.com", Status: "active"}
	svc := newTestAdminServiceWithRepo(db, repo)

	err := svc.DeleteUser(context.Background(), "admin-1", "target-1")
	if err == nil || !strings.Contains(err.Error(), "fetch user") {
		t.Fatalf("expected fetch-user error, got %v", err)
	}
}

func TestAdminService_DeleteUser_RevokeRefreshTokensError(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	repo := &errorRepo{fakeRepo: newFakeRepo(), failDeleteRefreshTokensForUser: true}
	repo.users["target-1"] = &User{ID: "target-1", Email: "target@test.com", Status: "active"}
	svc := newTestAdminServiceWithRepo(db, repo)

	err := svc.DeleteUser(context.Background(), "admin-1", "target-1")
	if err == nil || !strings.Contains(err.Error(), "revoke refresh tokens") {
		t.Fatalf("expected revoke-refresh-tokens error, got %v", err)
	}
	// The user must survive a failed cascade.
	if u, _ := repo.GetUser(context.Background(), "target-1"); u == nil {
		t.Fatal("target must survive a failed delete cascade")
	}
}

func TestAdminService_DeleteUser_RevokeSessionsError(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	repo := &errorRepo{fakeRepo: newFakeRepo(), failRevokeSessionsForUser: true}
	repo.users["target-1"] = &User{ID: "target-1", Email: "target@test.com", Status: "active"}
	svc := newTestAdminServiceWithRepo(db, repo)

	err := svc.DeleteUser(context.Background(), "admin-1", "target-1")
	if err == nil || !strings.Contains(err.Error(), "revoke sessions") {
		t.Fatalf("expected revoke-sessions error, got %v", err)
	}
}

func TestAdminService_DeleteUser_DeleteUserError(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	repo := &errorRepo{fakeRepo: newFakeRepo(), failDeleteUser: true}
	repo.users["target-1"] = &User{ID: "target-1", Email: "target@test.com", Status: "active"}
	svc := newTestAdminServiceWithRepo(db, repo)

	err := svc.DeleteUser(context.Background(), "admin-1", "target-1")
	if err == nil || !strings.Contains(err.Error(), "delete user") {
		t.Fatalf("expected delete-user error, got %v", err)
	}
}

// ── DeactivateUser revoke error branches ───────────────────────────────
//
// DeactivateUser revokes refresh tokens and sessions AFTER flipping the
// status row. These cover the two new revoke wraps' error paths.

func TestAdminService_DeactivateUser_RevokeRefreshTokensError(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("target-1", "target@test.com", "Target", "member", "active")
	repo := &errorRepo{fakeRepo: newFakeRepo(), failDeleteRefreshTokensForUser: true}
	svc := newTestAdminServiceWithRepo(db, repo)

	err := svc.DeactivateUser(context.Background(), "admin-1", "target-1", "leaving")
	if err == nil || !strings.Contains(err.Error(), "deactivate user: revoke refresh tokens") {
		t.Fatalf("expected deactivate revoke-refresh-tokens error, got %v", err)
	}
}

func TestAdminService_DeactivateUser_RevokeSessionsError(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("target-1", "target@test.com", "Target", "member", "active")
	repo := &errorRepo{fakeRepo: newFakeRepo(), failRevokeSessionsForUser: true}
	svc := newTestAdminServiceWithRepo(db, repo)

	err := svc.DeactivateUser(context.Background(), "admin-1", "target-1", "leaving")
	if err == nil || !strings.Contains(err.Error(), "deactivate user: revoke sessions") {
		t.Fatalf("expected deactivate revoke-sessions error, got %v", err)
	}
}
