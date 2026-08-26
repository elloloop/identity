package service

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// newTestProfileServiceForDeletion builds a ProfileService over the full
// fakeRepo (so session/refresh-token revocation is observable) whose audit
// logger writes to writer, with the default 30-day grace window.
func newTestProfileServiceForDeletion(repo *fakeRepo, writer *recordingAuditWriter) *ProfileService {
	auditLog := audit.NewLogger(writer, "test-tenant", zap.NewNop())
	return NewProfileService(repo, newFakeDB(), "test-tenant", auditLog, zap.NewNop()).
		WithAccountDeletionGraceDays(30)
}

func seedRevocableUser(t *testing.T, repo *fakeRepo, email, status string) *User {
	t.Helper()
	u := seedUser(repo, email, "hash", status)
	if _, err := repo.CreateRefreshToken(context.Background(), &RefreshTokenRecord{
		TokenHash: "rt-" + u.ID, UserID: u.ID, ExpiresAt: 9_000_000_000_000,
	}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	if _, err := repo.CreateSession(context.Background(), &SessionRecord{
		SID: "sid-" + u.ID, UserID: u.ID, CreatedAtMs: 100,
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return u
}

func TestDeleteMyAccount_SchedulesDisablesAndRevokes(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestProfileServiceForDeletion(repo, writer)
	u := seedRevocableUser(t, repo, "self@example.com", StatusActive)

	before := nowMs()
	scheduledAt, err := svc.DeleteMyAccount(ctx, u.ID, "no longer needed")
	if err != nil {
		t.Fatalf("DeleteMyAccount: %v", err)
	}

	// The purge is scheduled a full grace window (30 days) out.
	wantMin := before + 30*msPerDay
	if scheduledAt < wantMin {
		t.Fatalf("scheduledAt = %d, want >= %d (now + 30d)", scheduledAt, wantMin)
	}

	got, _ := repo.GetUser(ctx, u.ID)
	if got.Status != StatusPendingDeletion {
		t.Fatalf("status = %q, want %q", got.Status, StatusPendingDeletion)
	}
	if got.DeletionScheduledAtMs != scheduledAt {
		t.Fatalf("stored scheduled = %d, want %d", got.DeletionScheduledAtMs, scheduledAt)
	}

	// Access is cut off immediately: refresh token deleted, session revoked.
	if rec, err := repo.FindRefreshTokenByHashIncludingConsumed(ctx, "rt-"+u.ID); err != nil || rec != nil {
		t.Fatalf("refresh token must be deleted: err=%v rec=%#v", err, rec)
	}
	sess, err := repo.GetSessionBySid(ctx, "sid-"+u.ID)
	if err != nil || sess == nil || sess.RevokedAtMs == 0 {
		t.Fatalf("session must be revoked: err=%v sess=%#v", err, sess)
	}

	if n := writer.countByEventType(string(audit.EventAccountDeletionRequested)); n != 1 {
		t.Fatalf("want 1 account_deletion_requested audit event, got %d", n)
	}
}

func TestDeleteMyAccount_Idempotent(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestProfileServiceForDeletion(repo, newRecordingAuditWriter())
	u := seedRevocableUser(t, repo, "self@example.com", StatusActive)

	first, err := svc.DeleteMyAccount(ctx, u.ID, "")
	if err != nil {
		t.Fatalf("first DeleteMyAccount: %v", err)
	}
	second, err := svc.DeleteMyAccount(ctx, u.ID, "")
	if err != nil {
		t.Fatalf("second DeleteMyAccount: %v", err)
	}
	if first != second {
		t.Fatalf("idempotency: first=%d second=%d, want equal", first, second)
	}
}

func TestDeleteMyAccount_RejectsAdminDisabledStates(t *testing.T) {
	ctx := context.Background()
	for _, status := range []string{"deactivated", "suspended"} {
		repo := newFakeRepo()
		svc := newTestProfileServiceForDeletion(repo, newRecordingAuditWriter())
		u := seedUser(repo, status+"@example.com", "hash", status)

		_, err := svc.DeleteMyAccount(ctx, u.ID, "")
		if !errors.Is(err, ErrAccountDeletionNotAllowed) {
			t.Fatalf("status %q: want ErrAccountDeletionNotAllowed, got %v", status, err)
		}
		// State is unchanged.
		got, _ := repo.GetUser(ctx, u.ID)
		if got.Status != status {
			t.Fatalf("status %q mutated to %q", status, got.Status)
		}
	}
}

func TestDeleteMyAccount_Unauthenticated(t *testing.T) {
	svc := newTestProfileServiceForDeletion(newFakeRepo(), newRecordingAuditWriter())
	if _, err := svc.DeleteMyAccount(context.Background(), "", ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("empty actor: want ErrUnauthenticated, got %v", err)
	}
}

func TestCancelAccountDeletion_RestoresActive(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestProfileServiceForDeletion(repo, writer)
	u := seedRevocableUser(t, repo, "self@example.com", StatusActive)

	if _, err := svc.DeleteMyAccount(ctx, u.ID, ""); err != nil {
		t.Fatalf("DeleteMyAccount: %v", err)
	}
	status, err := svc.CancelAccountDeletion(ctx, u.ID)
	if err != nil {
		t.Fatalf("CancelAccountDeletion: %v", err)
	}
	if status != StatusActive {
		t.Fatalf("returned status = %q, want %q", status, StatusActive)
	}
	got, _ := repo.GetUser(ctx, u.ID)
	if got.Status != StatusActive || got.DeletionScheduledAtMs != 0 {
		t.Fatalf("after cancel: status=%q scheduled=%d", got.Status, got.DeletionScheduledAtMs)
	}
	if n := writer.countByEventType(string(audit.EventAccountDeletionCancelled)); n != 1 {
		t.Fatalf("want 1 account_deletion_cancelled audit event, got %d", n)
	}
}

func TestCancelAccountDeletion_IdempotentWhenNotPending(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestProfileServiceForDeletion(repo, writer)
	u := seedUser(repo, "active@example.com", "hash", StatusActive)

	status, err := svc.CancelAccountDeletion(ctx, u.ID)
	if err != nil {
		t.Fatalf("CancelAccountDeletion on active: %v", err)
	}
	if status != StatusActive {
		t.Fatalf("status = %q, want active", status)
	}
	// No cancel event is emitted when there was nothing pending.
	if n := writer.countByEventType(string(audit.EventAccountDeletionCancelled)); n != 0 {
		t.Fatalf("want 0 cancel events for a non-pending account, got %d", n)
	}
}

// TestPasswordLogin_AutoCancelsPendingDeletion drives the real interactive
// login chokepoint: a PENDING_DELETION owner who signs back in during the grace
// window authenticates AND has the pending deletion auto-cancelled before tokens
// are issued.
func TestPasswordLogin_AutoCancelsPendingDeletion(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	authSvc := newTestAuthServiceWithAudit(t, repo, writer)

	pwHash := hashPW(t, strongPW)
	u := seedUser(repo, "returning@example.com", pwHash, StatusPendingDeletion)
	u.DeletionScheduledAtMs = nowMs() + 10*msPerDay

	result, err := authSvc.PasswordLogin(ctx, "returning@example.com", strongPW, "1.2.3.4", "Agent")
	if err != nil {
		t.Fatalf("PENDING_DELETION user must be able to log in: %v", err)
	}
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatalf("expected tokens issued, got %+v", result)
	}

	got, _ := repo.GetUser(ctx, u.ID)
	if got.Status != StatusActive || got.DeletionScheduledAtMs != 0 {
		t.Fatalf("login must auto-cancel deletion: status=%q scheduled=%d", got.Status, got.DeletionScheduledAtMs)
	}
	if n := writer.countByEventType(string(audit.EventAccountDeletionCancelled)); n != 1 {
		t.Fatalf("want 1 account_deletion_cancelled audit event from login, got %d", n)
	}
}

// TestPurgeExpiredPendingDeletions_PurgesOnlyDue verifies the sweeper entry
// point hard-deletes past-due pending_deletion accounts (reusing the admin
// cascade) and leaves future-due and non-pending accounts intact.
func TestPurgeExpiredPendingDeletions_PurgesOnlyDue(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	admin := newTestAdminServiceWithAudit(db, repo, writer)

	// due: scheduled in the past; future: scheduled later; active: never pending.
	due := seedRevocableUser(t, repo, "due@example.com", StatusPendingDeletion)
	due.DeletionScheduledAtMs = 100
	future := seedUser(repo, "future@example.com", "hash", StatusPendingDeletion)
	future.DeletionScheduledAtMs = 9_000
	active := seedUser(repo, "active@example.com", "hash", StatusActive)

	purged, err := admin.PurgeExpiredPendingDeletions(ctx, 500, 100)
	if err != nil {
		t.Fatalf("PurgeExpiredPendingDeletions: %v", err)
	}
	if purged != 1 {
		t.Fatalf("purged = %d, want 1", purged)
	}

	// The due account is gone (hard delete), the others remain.
	if got, _ := repo.GetUser(ctx, due.ID); got != nil {
		t.Fatalf("due account must be purged, got %#v", got)
	}
	if got, _ := repo.GetUser(ctx, future.ID); got == nil {
		t.Fatal("future-due account must survive the sweep")
	}
	if got, _ := repo.GetUser(ctx, active.ID); got == nil {
		t.Fatal("active account must survive the sweep")
	}
	// The purge reused the delete cascade → a user_deleted audit entry.
	if n := writer.countByEventType(string(audit.EventUserDeleted)); n != 1 {
		t.Fatalf("want 1 user_deleted audit event from purge, got %d", n)
	}
	// Its refresh token was revoked as part of the cascade.
	if rec, _ := repo.FindRefreshTokenByHashIncludingConsumed(ctx, "rt-"+due.ID); rec != nil {
		t.Fatalf("purged account's refresh token must be gone, got %#v", rec)
	}
}

// TestPurgeAccount_IsTheSharedCascade pins the AccountPurger seam: the
// exported entry point the guardian-initiated child erasure calls runs the
// SAME cascade the admin DeleteUser RPC and the deletion sweeper run, so the
// three can never drift into three different definitions of "erased".
func TestPurgeAccount_IsTheSharedCascade(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	admin := newTestAdminServiceWithAudit(db, repo, writer)

	target := seedRevocableUser(t, repo, "purge@example.com", StatusActive)

	if err := admin.PurgeAccount(ctx, "guardian-1", target); err != nil {
		t.Fatalf("PurgeAccount: %v", err)
	}
	if u, _ := repo.GetUser(ctx, target.ID); u != nil {
		t.Fatal("the account must be erased")
	}
	// Sessions and refresh tokens die with it — the cascade, not just the row.
	repo.mu.Lock()
	defer repo.mu.Unlock()
	for _, rt := range repo.refreshTokens {
		if rt.UserID == target.ID {
			t.Fatal("refresh tokens must be deleted by the cascade")
		}
	}
	if n := writer.countByEventTypeActorTarget(string(audit.EventUserDeleted), "guardian-1", target.ID); n != 1 {
		t.Fatalf("audit events = %d, want 1 naming the acting principal", n)
	}
}
