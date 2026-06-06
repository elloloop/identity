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

func TestGroupService_DeleteGroup_DrainsMemberEdges(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB()
	seedGroupAdmin(db)
	db.addGroup("grp-1", "ToDelete", "")
	db.addGroup("grp-2", "Keep", "")
	db.addUser("user-1", "alice@test.com", "Alice", "member", "active")
	db.addUser("user-2", "bob@test.com", "Bob", "member", "active")
	svc := newTestGroupService(db)

	// Two members in grp-1, plus an unrelated membership in grp-2 that
	// must survive the delete of grp-1.
	for _, uid := range []string{"user-1", "user-2"} {
		if err := svc.AddGroupMember(ctx, "admin-1", "grp-1", uid); err != nil {
			t.Fatalf("AddGroupMember(%s): %v", uid, err)
		}
	}
	if err := svc.AddGroupMember(ctx, "admin-1", "grp-2", "user-1"); err != nil {
		t.Fatalf("AddGroupMember(grp-2): %v", err)
	}

	if err := svc.DeleteGroup(ctx, "admin-1", "grp-1"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}

	// The cross-user edge read MUST use the tenant-admin actor; a per-user
	// actor would silently return zero rows on real entdb and leave the
	// MEMBER_OF edges dangling. The fake ignores the actor for filtering,
	// so only this assertion catches that regression.
	if got := db.lastEdgesToActor; got != tenantAdminActor {
		t.Fatalf("GetEdgesTo actor = %q, want %q (cross-user read must use tenant-admin)", got, tenantAdminActor)
	}

	// The group node is gone.
	if node, _ := db.GetNode(ctx, "", "", typeWorkingGroup, "grp-1"); node != nil {
		t.Error("expected group to be deleted")
	}
	// Every inbound membership edge to grp-1 is drained.
	if edges, err := db.GetEdgesTo(ctx, "t", tenantAdminActor, "grp-1", edgeMemberOf); err != nil || len(edges) != 0 {
		t.Fatalf("grp-1 memberships must be drained: err=%v edges=%#v", err, edges)
	}
	// The unrelated grp-2 membership survives.
	if edges, err := db.GetEdgesTo(ctx, "t", tenantAdminActor, "grp-2", edgeMemberOf); err != nil || len(edges) != 1 {
		t.Fatalf("grp-2 membership must survive: err=%v edges=%#v", err, edges)
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
