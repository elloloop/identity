package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// TestRBAC_RoleLifecycle_EndToEnd drives the RBAC RPCs through the connect
// harness: an admin defines a scoped role, assigns it, and the assignee's
// effective permissions reflect exactly the role's subset.
func TestRBAC_RoleLifecycle_EndToEnd(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.db.addUser("admin-1", "admin@e.com", "Admin", "admin", "active")
	target := h.repo.seedUser(&service.User{Email: "billing@e.com", Status: "active", Role: "member"})

	// Define a custom role.
	created, err := h.client.CreateRole(ctx, authedReq(connect.NewRequest(&identitypb.CreateRoleRequest{
		Name: "billing-admin", Description: "billing ops", Permissions: []string{"billing:write", "billing:read"},
	}), "admin-1"))
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if created.Msg.Role.GetName() != "billing-admin" || len(created.Msg.Role.GetPermissions()) != 2 {
		t.Fatalf("CreateRole result: %#v", created.Msg.Role)
	}

	// It shows up in ListRoles.
	listed, err := h.client.ListRoles(ctx, authedReq(connect.NewRequest(&identitypb.ListRolesRequest{}), "admin-1"))
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(listed.Msg.Roles) != 1 {
		t.Fatalf("ListRoles: want 1, got %#v", listed.Msg.Roles)
	}

	// Assign it.
	if _, err := h.client.AssignRole(ctx, authedReq(connect.NewRequest(&identitypb.AssignRoleRequest{
		UserId: target.ID, RoleName: "billing-admin",
	}), "admin-1")); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	// The assignee's effective permission view is exactly the subset.
	perms, err := h.client.GetUserPermissions(ctx, authedReq(connect.NewRequest(&identitypb.GetUserPermissionsRequest{
		UserId: target.ID,
	}), "admin-1"))
	if err != nil {
		t.Fatalf("GetUserPermissions: %v", err)
	}
	if perms.Msg.Superset {
		t.Fatalf("assignee should not be superset")
	}
	if perms.Msg.RoleName != "billing-admin" || len(perms.Msg.Permissions) != 2 {
		t.Fatalf("perms view: %#v", perms.Msg)
	}
}

// TestRBAC_Unauthenticated rejects unauthenticated callers.
func TestRBAC_Unauthenticated(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.client.CreateRole(ctx, connect.NewRequest(&identitypb.CreateRoleRequest{
		Name: "r", Permissions: []string{"x"},
	})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want CodeUnauthenticated, got %v: %v", connectCodeOf(err), err)
	}
}

// TestRBAC_NonAdminDenied: a non-admin caller cannot manage roles.
func TestRBAC_NonAdminDenied(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.addUser("member-1", "member@e.com", "Member", "member", "active")

	_, err := h.client.CreateRole(ctx, authedReq(connect.NewRequest(&identitypb.CreateRoleRequest{
		Name: "r", Permissions: []string{"x"},
	}), "member-1"))
	if err == nil {
		t.Fatal("expected non-admin to be denied")
	}
}
