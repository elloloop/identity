package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

func newTestProfileService(db *fakeDB) *ProfileService {
	auditLog := audit.NewLogger(nil, "test-tenant", zap.NewNop())
	return NewProfileService(db, "test-tenant", auditLog, zap.NewNop())
}

func TestProfileService_UpdateProfile_HappyPath(t *testing.T) {
	db := newFakeDB()
	db.addUser("user-1", "alice@test.com", "Alice", "member", "active")
	svc := newTestProfileService(db)

	user, err := svc.UpdateProfile(context.Background(), "user-1", "Alice Updated", "https://cdn.example.com/avatar.jpg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Name != "Alice Updated" {
		t.Errorf("expected Alice Updated, got %q", user.Name)
	}
	if user.AvatarURL != "https://cdn.example.com/avatar.jpg" {
		t.Errorf("expected avatar URL, got %q", user.AvatarURL)
	}
}

func TestProfileService_UpdateProfile_NotFound(t *testing.T) {
	db := newFakeDB()
	svc := newTestProfileService(db)

	_, err := svc.UpdateProfile(context.Background(), "nonexistent", "Name", "")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProfileService_ListMySessions_HappyPath(t *testing.T) {
	db := newFakeDB()
	now := nowMs()
	db.addRefreshToken("sess-1", "user-1", now+3600*1000)
	db.addRefreshToken("sess-2", "user-1", now+7200*1000)
	db.addRefreshToken("sess-3", "user-1", now-1000) // expired
	svc := newTestProfileService(db)

	sessions, err := svc.ListMySessions(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != 2 {
		t.Errorf("expected 2 active sessions, got %d", len(sessions))
	}
}

func TestProfileService_RevokeSession_HappyPath(t *testing.T) {
	db := newFakeDB()
	db.addRefreshToken("sess-1", "user-1", nowMs()+3600*1000)
	svc := newTestProfileService(db)

	err := svc.RevokeSession(context.Background(), "user-1", "sess-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify deleted.
	node, _ := db.GetNode(context.Background(), "", "", typeRefreshToken, "sess-1")
	if node != nil {
		t.Error("expected session to be deleted")
	}
}

func TestProfileService_RevokeSession_WrongUser(t *testing.T) {
	db := newFakeDB()
	db.addRefreshToken("sess-1", "user-1", nowMs()+3600*1000)
	svc := newTestProfileService(db)

	err := svc.RevokeSession(context.Background(), "user-2", "sess-1")
	if err == nil {
		t.Fatal("expected error for wrong user")
	}
	if !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProfileService_RevokeAllSessions_HappyPath(t *testing.T) {
	db := newFakeDB()
	pwHash, _ := passwords.Hash("Str0ng!Pass")
	db.addUserWithPassword("user-1", "alice@test.com", "Alice", "member", "active", pwHash)
	db.addRefreshToken("sess-1", "user-1", nowMs()+3600*1000)
	db.addRefreshToken("sess-2", "user-1", nowMs()+3600*1000)
	svc := newTestProfileService(db)

	count, err := svc.RevokeAllSessions(context.Background(), "user-1", "Str0ng!Pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 revoked, got %d", count)
	}
}

func TestProfileService_RevokeAllSessions_WrongPassword(t *testing.T) {
	db := newFakeDB()
	pwHash, _ := passwords.Hash("Str0ng!Pass")
	db.addUserWithPassword("user-1", "alice@test.com", "Alice", "member", "active", pwHash)
	svc := newTestProfileService(db)

	_, err := svc.RevokeAllSessions(context.Background(), "user-1", "WrongPassword!")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if !strings.Contains(err.Error(), "invalid password") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProfileService_ListMyPasskeys_HappyPath(t *testing.T) {
	db := newFakeDB()
	db.addPasskey("pk-1", "user-1", "cred-abc", "YubiKey 5")
	db.addPasskey("pk-2", "user-1", "cred-xyz", "iPhone 15")
	svc := newTestProfileService(db)

	passkeys, err := svc.ListMyPasskeys(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(passkeys) != 2 {
		t.Errorf("expected 2 passkeys, got %d", len(passkeys))
	}
}

func TestProfileService_DeletePasskey_HappyPath(t *testing.T) {
	db := newFakeDB()
	db.addPasskey("pk-1", "user-1", "cred-abc", "YubiKey 5")
	svc := newTestProfileService(db)

	err := svc.DeletePasskey(context.Background(), "user-1", "cred-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProfileService_DeletePasskey_WrongUser(t *testing.T) {
	db := newFakeDB()
	db.addPasskey("pk-1", "user-1", "cred-abc", "YubiKey 5")
	svc := newTestProfileService(db)

	err := svc.DeletePasskey(context.Background(), "user-2", "cred-abc")
	if err == nil {
		t.Fatal("expected error for wrong user")
	}
	if !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProfileService_ChangePassword_HappyPath(t *testing.T) {
	db := newFakeDB()
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	db.addUserWithPassword("user-1", "alice@test.com", "Alice", "member", "active", pwHash)
	svc := newTestProfileService(db)

	err := svc.ChangePassword(context.Background(), "user-1", "OldStr0ng!Pass", "NewStr0ng!Pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify new password works.
	node, _ := db.GetNode(context.Background(), "", "", typeUser, "user-1")
	newHash := pstr(node.Payload, ufPasswordHash)
	if !passwords.Verify("NewStr0ng!Pass", newHash) {
		t.Error("expected new password to verify")
	}
}

func TestProfileService_ChangePassword_WrongCurrent(t *testing.T) {
	db := newFakeDB()
	pwHash, _ := passwords.Hash("Str0ng!Pass")
	db.addUserWithPassword("user-1", "alice@test.com", "Alice", "member", "active", pwHash)
	svc := newTestProfileService(db)

	err := svc.ChangePassword(context.Background(), "user-1", "WrongPass!", "NewStr0ng!Pass")
	if err == nil {
		t.Fatal("expected error for wrong current password")
	}
	if !strings.Contains(err.Error(), "incorrect") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProfileService_ChangePassword_WeakNew(t *testing.T) {
	db := newFakeDB()
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	db.addUserWithPassword("user-1", "alice@test.com", "Alice", "member", "active", pwHash)
	svc := newTestProfileService(db)

	err := svc.ChangePassword(context.Background(), "user-1", "OldStr0ng!Pass", "weak")
	if err == nil {
		t.Fatal("expected error for weak new password")
	}
	if !strings.Contains(err.Error(), "too weak") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProfileService_ListAuditEvents_AdminOnly(t *testing.T) {
	db := newFakeDB()
	db.addUser("member-1", "member@test.com", "Member", "member", "active")
	svc := newTestProfileService(db)

	_, _, err := svc.ListAuditEvents(
		context.Background(), "member-1", "", "", 0, 0, "", 50,
	)
	if err == nil {
		t.Fatal("expected error for non-admin")
	}
	if !strings.Contains(err.Error(), "admin role required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProfileService_ListAuditEvents_HappyPath(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	svc := newTestProfileService(db)

	events, nextCursor, err := svc.ListAuditEvents(
		context.Background(), "admin-1", "", "", 0, 0, "", 50,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No events yet, but should return empty list without error.
	if events == nil {
		t.Error("expected non-nil empty slice")
	}
	_ = nextCursor
}

func TestProfileService_DBError(t *testing.T) {
	db := newFakeDB()
	db.err = errors.New("db down")
	svc := newTestProfileService(db)

	_, err := svc.UpdateProfile(context.Background(), "user-1", "Name", "")
	if err == nil {
		t.Fatal("expected error when DB fails")
	}
}
