package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

func newTestHelpService(db *fakeDB) *HelpService {
	auditLog := audit.NewLogger(nil, "test-tenant", zap.NewNop())
	return NewHelpService(db, "test-tenant", auditLog, zap.NewNop())
}

func TestHelpService_RequestAdminHelp_HappyPath(t *testing.T) {
	db := newFakeDB()
	svc := newTestHelpService(db)

	err := svc.RequestAdminHelp(
		context.Background(), "user@test.com", "I can't login",
		"10.0.0.1", "Mozilla/5.0",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify help request was created.
	nodes, _ := db.QueryNodes(context.Background(), "", "", typeAdminHelpReq, nil)
	if len(nodes) != 1 {
		t.Fatalf("expected 1 help request, got %d", len(nodes))
	}
	if pstr(nodes[0].Payload, hfEmail) != "user@test.com" {
		t.Errorf("expected email user@test.com, got %q", pstr(nodes[0].Payload, hfEmail))
	}
}

func TestHelpService_RequestAdminHelp_InvalidEmail(t *testing.T) {
	db := newFakeDB()
	svc := newTestHelpService(db)

	err := svc.RequestAdminHelp(context.Background(), "bademail", "", "", "")
	if err == nil {
		t.Fatal("expected error for invalid email")
	}
	if !strings.Contains(err.Error(), "email") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHelpService_RequestAdminHelp_RateLimit(t *testing.T) {
	db := newFakeDB()
	now := nowMs()
	// Pre-populate 3 recent pending requests.
	db.addHelpRequest("hr-1", "ratelimited@test.com", "pending", now-1000)
	db.addHelpRequest("hr-2", "ratelimited@test.com", "pending", now-2000)
	db.addHelpRequest("hr-3", "ratelimited@test.com", "pending", now-3000)
	svc := newTestHelpService(db)

	err := svc.RequestAdminHelp(
		context.Background(), "ratelimited@test.com", "try again", "", "",
	)
	// Should return nil (no enumeration), but no new node created.
	if err != nil {
		t.Fatalf("expected nil (rate limited silently), got: %v", err)
	}

	nodes, _ := db.QueryNodes(context.Background(), "", "", typeAdminHelpReq, nil)
	if len(nodes) != 3 {
		t.Errorf("expected 3 requests (no new one), got %d", len(nodes))
	}
}

func TestHelpService_ListHelpRequests_AdminOnly(t *testing.T) {
	db := newFakeDB()
	db.addUser("member-1", "member@test.com", "Member", "member", "active")
	svc := newTestHelpService(db)

	_, _, _, err := svc.ListHelpRequests(context.Background(), "member-1", "", "", 50)
	if err == nil {
		t.Fatal("expected error for non-admin")
	}
	if !strings.Contains(err.Error(), "admin role required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHelpService_ListHelpRequests_HappyPath(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addHelpRequest("hr-1", "a@test.com", "pending", nowMs())
	db.addHelpRequest("hr-2", "b@test.com", "resolved", nowMs())
	svc := newTestHelpService(db)

	requests, _, pendingCount, err := svc.ListHelpRequests(
		context.Background(), "admin-1", "", "", 50,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(requests) != 2 {
		t.Errorf("expected 2 requests, got %d", len(requests))
	}
	if pendingCount != 1 {
		t.Errorf("expected 1 pending, got %d", pendingCount)
	}
}

func TestHelpService_ResolveHelpRequest_HappyPath(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addHelpRequest("hr-1", "help@test.com", "pending", nowMs())
	svc := newTestHelpService(db)

	hr, err := svc.ResolveHelpRequest(
		context.Background(), "admin-1", "hr-1", false, "Password reset sent",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hr.Status != "resolved" {
		t.Errorf("expected resolved, got %q", hr.Status)
	}
	if hr.ResolvedBy != "admin-1" {
		t.Errorf("expected resolved by admin-1, got %q", hr.ResolvedBy)
	}
}

func TestHelpService_ResolveHelpRequest_Reject(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addHelpRequest("hr-1", "help@test.com", "pending", nowMs())
	svc := newTestHelpService(db)

	hr, err := svc.ResolveHelpRequest(
		context.Background(), "admin-1", "hr-1", true, "Looks like spam",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hr.Status != "rejected" {
		t.Errorf("expected rejected, got %q", hr.Status)
	}
}

func TestHelpService_ResolveHelpRequest_AlreadyResolved(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addHelpRequest("hr-1", "help@test.com", "resolved", nowMs())
	svc := newTestHelpService(db)

	_, err := svc.ResolveHelpRequest(
		context.Background(), "admin-1", "hr-1", false, "",
	)
	if err == nil {
		t.Fatal("expected error for already-resolved request")
	}
	if !strings.Contains(err.Error(), "not pending") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHelpService_ResolveHelpRequest_NotFound(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	svc := newTestHelpService(db)

	_, err := svc.ResolveHelpRequest(
		context.Background(), "admin-1", "nonexistent", false, "",
	)
	if err == nil {
		t.Fatal("expected error for nonexistent request")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHelpService_DBError(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	// Set error after the admin user exists — for list, the admin
	// check will pass but the query will fail.
	svc := newTestHelpService(db)

	db.err = errors.New("db down")
	_, _, _, err := svc.ListHelpRequests(context.Background(), "admin-1", "", "", 50)
	if err == nil {
		t.Fatal("expected error when DB fails")
	}
}
