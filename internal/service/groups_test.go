package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

func newTestGroupService(db *fakeDB) *GroupService {
	auditLog := audit.NewLogger(nil, "test-tenant", zap.NewNop())
	return NewGroupService(db, "test-tenant", auditLog, zap.NewNop())
}

func seedGroupAdmin(db *fakeDB) {
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
}

func TestGroupService_CreateGroup_HappyPath(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	svc := newTestGroupService(db)

	group, err := svc.CreateGroup(context.Background(), "admin-1", "Engineering", "The eng team")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if group.Name != "Engineering" {
		t.Errorf("expected Engineering, got %q", group.Name)
	}
	if group.Description != "The eng team" {
		t.Errorf("expected description, got %q", group.Description)
	}
	if group.ID == "" {
		t.Error("expected non-empty group ID")
	}
}

func TestGroupService_CreateGroup_EmptyName(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	svc := newTestGroupService(db)

	_, err := svc.CreateGroup(context.Background(), "admin-1", "", "desc")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if !strings.Contains(err.Error(), "name is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGroupService_UpdateGroup_HappyPath(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	db.addGroup("grp-1", "Old Name", "Old Desc")
	svc := newTestGroupService(db)

	group, err := svc.UpdateGroup(context.Background(), "admin-1", "grp-1", "New Name", "New Desc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if group.Name != "New Name" {
		t.Errorf("expected New Name, got %q", group.Name)
	}
	if group.Description != "New Desc" {
		t.Errorf("expected New Desc, got %q", group.Description)
	}
}

func TestGroupService_DeleteGroup_HappyPath(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	db.addGroup("grp-1", "ToDelete", "")
	svc := newTestGroupService(db)

	err := svc.DeleteGroup(context.Background(), "admin-1", "grp-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify removed.
	node, _ := db.GetNode(context.Background(), "", "", typeWorkingGroup, "grp-1")
	if node != nil {
		t.Error("expected group to be deleted")
	}
}

func TestGroupService_DeleteGroup_EmptyID(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	svc := newTestGroupService(db)

	err := svc.DeleteGroup(context.Background(), "admin-1", "")
	if err == nil {
		t.Fatal("expected error for empty group_id")
	}
}

func TestGroupService_ListGroups_Pagination(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	db.addGroup("grp-1", "Alpha", "")
	db.addGroup("grp-2", "Beta", "")
	db.addGroup("grp-3", "Gamma", "")
	svc := newTestGroupService(db)

	groups, nextCursor, err := svc.ListGroups(context.Background(), "admin-1", "", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(groups))
	}
	if nextCursor == "" {
		t.Error("expected a next cursor for pagination")
	}

	// Fetch second page.
	groups2, nextCursor2, err := svc.ListGroups(context.Background(), "admin-1", nextCursor, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups2) != 1 {
		t.Errorf("expected 1 group on second page, got %d", len(groups2))
	}
	if nextCursor2 != "" {
		t.Errorf("expected empty cursor on last page, got %q", nextCursor2)
	}
}

func TestGroupService_AddAndRemoveMember(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	db.addGroup("grp-1", "Team", "")
	db.addUser("user-1", "alice@test.com", "Alice", "member", "active")
	svc := newTestGroupService(db)

	err := svc.AddGroupMember(context.Background(), "admin-1", "grp-1", "user-1")
	if err != nil {
		t.Fatalf("add member: %v", err)
	}

	err = svc.RemoveGroupMember(context.Background(), "admin-1", "grp-1", "user-1")
	if err != nil {
		t.Fatalf("remove member: %v", err)
	}
}

func TestGroupService_AddGroupMember_MissingIDs(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	svc := newTestGroupService(db)

	err := svc.AddGroupMember(context.Background(), "admin-1", "", "user-1")
	if err == nil {
		t.Fatal("expected error for empty group_id")
	}
	err = svc.AddGroupMember(context.Background(), "admin-1", "grp-1", "")
	if err == nil {
		t.Fatal("expected error for empty user_id")
	}
}

func TestGroupService_ListGroupMembers_HappyPath(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	db.addGroup("grp-1", "Team", "")
	db.addUser("user-1", "alice@test.com", "Alice", "member", "active")
	svc := newTestGroupService(db)

	_ = svc.AddGroupMember(context.Background(), "admin-1", "grp-1", "user-1")

	members, err := svc.ListGroupMembers(context.Background(), "admin-1", "grp-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) != 1 || members[0].ID != "user-1" {
		t.Fatalf("members = %+v, want user-1", members)
	}
}

func TestGroupService_DBError(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	db.err = errors.New("db down")
	svc := newTestGroupService(db)

	_, err := svc.CreateGroup(context.Background(), "admin-1", "Test", "")
	if err == nil {
		t.Fatal("expected error when DB fails")
	}
}

func TestGroupService_NonAdminDenied(t *testing.T) {
	db := newFakeDB()
	db.addUser("member-1", "member@test.com", "Member", "member", "active")
	svc := newTestGroupService(db)

	_, err := svc.CreateGroup(context.Background(), "member-1", "Engineering", "The eng team")
	if err == nil {
		t.Fatal("expected non-admin denial")
	}
	if !strings.Contains(err.Error(), "admin role required") {
		t.Fatalf("unexpected error: %v", err)
	}
}
