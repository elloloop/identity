package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
)

func newTestAdminService(db *fakeDB) *AdminService {
	auditLog := audit.NewLogger(nil, "test-tenant", zap.NewNop())
	cfg := config.Load()
	return NewAdminService(db, "test-tenant", auditLog, cfg, nil, zap.NewNop())
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
