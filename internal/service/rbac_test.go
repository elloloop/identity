package service

import (
	"context"
	"errors"
	"testing"
)

// newRBACFixture builds an AdminService whose admin-authorization reads
// (db.GetNode) and whose RBAC reads (repo.GetUser) are both satisfied: the
// admin actor is seeded into the fakeDB AND the fakeRepo, and any target
// users are seeded into the fakeRepo.
func newRBACFixture(t *testing.T) (*AdminService, *fakeRepo) {
	t.Helper()
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	repo := newFakeRepo()
	if _, err := repo.CreateUser(context.Background(), &User{ID: "admin-1", Email: "admin@test.com", Role: "admin", Status: "active"}); err != nil {
		t.Fatalf("seed admin in repo: %v", err)
	}
	// CreateUser overwrites the ID; force it back to admin-1 so HasPermission
	// can resolve the admin actor by the same id the db check uses.
	repo.mu.Lock()
	for id, u := range repo.users {
		if u.Email == "admin@test.com" {
			delete(repo.users, id)
			u.ID = "admin-1"
			repo.users["admin-1"] = u
		}
	}
	repo.mu.Unlock()
	return newTestAdminServiceWithRepo(db, repo), repo
}

func seedRepoUser(t *testing.T, repo *fakeRepo, id, email, role string) {
	t.Helper()
	repo.mu.Lock()
	defer repo.mu.Unlock()
	repo.users[id] = &User{ID: id, Email: email, Role: role, Status: "active"}
}

func TestRBAC_CreateRole_Validation(t *testing.T) {
	svc, _ := newRBACFixture(t)
	ctx := context.Background()

	if _, err := svc.CreateRole(ctx, "admin-1", "  ", "", []string{"x"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank name: want ErrInvalidArgument, got %v", err)
	}
	if _, err := svc.CreateRole(ctx, "admin-1", "auditor", "", nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("no permissions: want ErrInvalidArgument, got %v", err)
	}
	if _, err := svc.CreateRole(ctx, "admin-1", "admin", "", []string{"x"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("reserved name: want ErrInvalidArgument, got %v", err)
	}

	role, err := svc.CreateRole(ctx, "admin-1", "Billing-Admin", "billing", []string{"billing:write", "billing:read", "billing:read"})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if role.Name != "billing-admin" {
		t.Fatalf("name should be normalized lower-case: %q", role.Name)
	}
	// De-duplicated + sorted.
	if len(role.Permissions) != 2 || role.Permissions[0] != "billing:read" || role.Permissions[1] != "billing:write" {
		t.Fatalf("permissions not canonicalized: %#v", role.Permissions)
	}

	// Duplicate.
	if _, err := svc.CreateRole(ctx, "admin-1", "billing-admin", "", []string{"x"}); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate: want ErrAlreadyExists, got %v", err)
	}
}

func TestRBAC_CreateRole_NonAdminDenied(t *testing.T) {
	svc, repo := newRBACFixture(t)
	seedRepoUser(t, repo, "member-1", "member@test.com", "member")
	// member-1 is not in the fakeDB admin graph, so requireAdmin fails.
	if _, err := svc.CreateRole(context.Background(), "member-1", "r", "", []string{"x"}); err == nil {
		t.Fatal("expected non-admin to be denied")
	}
}

func TestRBAC_AssignRole_And_HasPermission(t *testing.T) {
	svc, repo := newRBACFixture(t)
	ctx := context.Background()
	seedRepoUser(t, repo, "user-1", "u1@test.com", "member")

	if _, err := svc.CreateRole(ctx, "admin-1", "auditor", "read-only", []string{"audit:read"}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	// Assigning an unknown role fails.
	if err := svc.AssignRole(ctx, "admin-1", "user-1", "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("assign unknown role: want ErrNotFound, got %v", err)
	}

	if err := svc.AssignRole(ctx, "admin-1", "user-1", "auditor"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	// The assigned user may perform exactly the permitted action.
	if err := svc.HasPermission(ctx, "user-1", "audit:read"); err != nil {
		t.Fatalf("HasPermission audit:read: want allow, got %v", err)
	}
	// And is denied anything else.
	if err := svc.HasPermission(ctx, "user-1", "billing:write"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("HasPermission billing:write: want ErrPermissionDenied, got %v", err)
	}
}

func TestRBAC_AdminOwnerSuperset_NoRegression(t *testing.T) {
	svc, repo := newRBACFixture(t)
	ctx := context.Background()
	seedRepoUser(t, repo, "owner-1", "owner@test.com", "owner")

	// admin and owner are a full-access superset regardless of any role.
	if err := svc.HasPermission(ctx, "admin-1", "anything:at:all"); err != nil {
		t.Fatalf("admin superset: want allow, got %v", err)
	}
	if err := svc.HasPermission(ctx, "owner-1", "anything:at:all"); err != nil {
		t.Fatalf("owner superset: want allow, got %v", err)
	}

	superset, roleName, perms, err := svc.GetUserPermissions(ctx, "admin-1", "admin-1")
	if err != nil {
		t.Fatalf("GetUserPermissions: %v", err)
	}
	if !superset || roleName != "admin" || len(perms) != 0 {
		t.Fatalf("admin perms view: superset=%v role=%q perms=%#v", superset, roleName, perms)
	}
}

func TestRBAC_UnassignedUser_Denied(t *testing.T) {
	svc, repo := newRBACFixture(t)
	ctx := context.Background()
	seedRepoUser(t, repo, "user-2", "u2@test.com", "member")

	// No custom role and not an admin/owner: every permission is denied.
	if err := svc.HasPermission(ctx, "user-2", "doc:read"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("unassigned user: want ErrPermissionDenied, got %v", err)
	}
}

func TestRBAC_AssignEmptyRole_Clears(t *testing.T) {
	svc, repo := newRBACFixture(t)
	ctx := context.Background()
	seedRepoUser(t, repo, "user-3", "u3@test.com", "member")

	if _, err := svc.CreateRole(ctx, "admin-1", "reader", "", []string{"doc:read"}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := svc.AssignRole(ctx, "admin-1", "user-3", "reader"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if err := svc.HasPermission(ctx, "user-3", "doc:read"); err != nil {
		t.Fatalf("after assign: want allow, got %v", err)
	}
	// Empty role name clears the assignment.
	if err := svc.AssignRole(ctx, "admin-1", "user-3", ""); err != nil {
		t.Fatalf("clear assignment: %v", err)
	}
	if err := svc.HasPermission(ctx, "user-3", "doc:read"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("after clear: want ErrPermissionDenied, got %v", err)
	}
}

func TestRBAC_DeleteRole_CascadesAssignment(t *testing.T) {
	svc, repo := newRBACFixture(t)
	ctx := context.Background()
	seedRepoUser(t, repo, "user-4", "u4@test.com", "member")

	if _, err := svc.CreateRole(ctx, "admin-1", "temp", "", []string{"x:do"}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := svc.AssignRole(ctx, "admin-1", "user-4", "temp"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if err := svc.DeleteRole(ctx, "admin-1", "temp"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	// Role gone -> user denied; listing no longer returns it.
	if err := svc.HasPermission(ctx, "user-4", "x:do"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("after role delete: want ErrPermissionDenied, got %v", err)
	}
	roles, err := svc.ListRoles(ctx, "admin-1")
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("expected no roles after delete, got %#v", roles)
	}
}
