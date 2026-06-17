package service

import (
	"context"
	"errors"
	"strings"
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

func TestRBAC_CreateRole_PermissionTooLong(t *testing.T) {
	svc, _ := newRBACFixture(t)
	ctx := context.Background()
	long := strings.Repeat("p", maxPermissionLen+1)
	if _, err := svc.CreateRole(ctx, "admin-1", "ranger", "", []string{long}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("over-long permission: want ErrInvalidArgument, got %v", err)
	}
	longName := strings.Repeat("n", maxRoleNameLen+1)
	if _, err := svc.CreateRole(ctx, "admin-1", longName, "", []string{"x"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("over-long name: want ErrInvalidArgument, got %v", err)
	}
}

func TestRBAC_CreateRole_DropsEmptyPermissions(t *testing.T) {
	svc, _ := newRBACFixture(t)
	ctx := context.Background()
	// Empty/whitespace permission strings are dropped during normalization;
	// the remaining real permission keeps the role valid.
	role, err := svc.CreateRole(ctx, "admin-1", "sparse", "", []string{"", "  ", "doc:read"})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if len(role.Permissions) != 1 || role.Permissions[0] != "doc:read" {
		t.Fatalf("empty perms not dropped: %#v", role.Permissions)
	}
}

func TestRBAC_GetUserPermissions_AssignedRole(t *testing.T) {
	svc, repo := newRBACFixture(t)
	ctx := context.Background()
	seedRepoUser(t, repo, "user-5", "u5@test.com", "member")

	if _, err := svc.CreateRole(ctx, "admin-1", "editor", "edits", []string{"doc:write", "doc:read"}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := svc.AssignRole(ctx, "admin-1", "user-5", "editor"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	superset, roleName, perms, err := svc.GetUserPermissions(ctx, "admin-1", "user-5")
	if err != nil {
		t.Fatalf("GetUserPermissions: %v", err)
	}
	if superset {
		t.Fatalf("custom-role user should not be superset")
	}
	if roleName != "editor" {
		t.Fatalf("roleName = %q, want editor", roleName)
	}
	if len(perms) != 2 || perms[0] != "doc:read" || perms[1] != "doc:write" {
		t.Fatalf("perms = %#v, want canonical doc:read/doc:write", perms)
	}
}

func TestRBAC_GetUserPermissions_Errors(t *testing.T) {
	svc, _ := newRBACFixture(t)
	ctx := context.Background()

	// Non-admin actor.
	if _, _, _, err := svc.GetUserPermissions(ctx, "nobody", "admin-1"); err == nil {
		t.Fatal("non-admin GetUserPermissions: expected error")
	}
	// Blank target.
	if _, _, _, err := svc.GetUserPermissions(ctx, "admin-1", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank target: want ErrInvalidArgument, got %v", err)
	}
	// Unknown target.
	if _, _, _, err := svc.GetUserPermissions(ctx, "admin-1", "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown target: want ErrNotFound, got %v", err)
	}
}

func TestRBAC_AssignRole_Errors(t *testing.T) {
	svc, _ := newRBACFixture(t)
	ctx := context.Background()

	// Non-admin actor.
	if err := svc.AssignRole(ctx, "nobody", "admin-1", "x"); err == nil {
		t.Fatal("non-admin AssignRole: expected error")
	}
	// Blank target user.
	if err := svc.AssignRole(ctx, "admin-1", "", "x"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank user: want ErrInvalidArgument, got %v", err)
	}
	// Unknown target user.
	if err := svc.AssignRole(ctx, "admin-1", "ghost", "auditor"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown target: want ErrNotFound, got %v", err)
	}
}

func TestRBAC_DeleteRole_Errors(t *testing.T) {
	svc, _ := newRBACFixture(t)
	ctx := context.Background()

	// Non-admin actor.
	if err := svc.DeleteRole(ctx, "nobody", "x"); err == nil {
		t.Fatal("non-admin DeleteRole: expected error")
	}
	// Blank name.
	if err := svc.DeleteRole(ctx, "admin-1", "   "); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank name: want ErrInvalidArgument, got %v", err)
	}
	// Reserved built-in.
	if err := svc.DeleteRole(ctx, "admin-1", "member"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("reserved name: want ErrInvalidArgument, got %v", err)
	}
}

func TestRBAC_ListRoles_NonAdminDenied(t *testing.T) {
	svc, _ := newRBACFixture(t)
	if _, err := svc.ListRoles(context.Background(), "nobody"); err == nil {
		t.Fatal("non-admin ListRoles: expected error")
	}
}

func TestRBAC_HasPermission_BlankPermission(t *testing.T) {
	svc, repo := newRBACFixture(t)
	ctx := context.Background()
	seedRepoUser(t, repo, "user-6", "u6@test.com", "member")
	if err := svc.HasPermission(ctx, "user-6", "  "); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank permission: want ErrInvalidArgument, got %v", err)
	}
}

func TestRBAC_EffectivePermissions_DanglingAssignment(t *testing.T) {
	svc, repo := newRBACFixture(t)
	ctx := context.Background()
	seedRepoUser(t, repo, "user-7", "u7@test.com", "member")

	// Inject an assignment that points at a non-existent role (fail-closed
	// branch: assignment present but role lookup returns nil).
	repo.mu.Lock()
	repo.roleAssignments["ra-dangling"] = &RoleAssignmentRecord{
		NodeID: "ra-dangling", UserID: "user-7", RoleName: "vanished", CreatedAt: nowMs(),
	}
	repo.mu.Unlock()

	superset, roleName, perms, err := svc.effectivePermissions(ctx, "user-7")
	if err != nil {
		t.Fatalf("effectivePermissions: %v", err)
	}
	if superset || roleName != "vanished" || len(perms) != 0 {
		t.Fatalf("dangling: superset=%v role=%q perms=%#v", superset, roleName, perms)
	}
	if err := svc.HasPermission(ctx, "user-7", "anything"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("dangling HasPermission: want ErrPermissionDenied, got %v", err)
	}
}

func TestRBAC_EffectivePermissions_UnknownUser(t *testing.T) {
	svc, _ := newRBACFixture(t)
	if _, _, _, err := svc.effectivePermissions(context.Background(), "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: want ErrNotFound, got %v", err)
	}
}

func TestRBAC_RepoErrorsPropagate(t *testing.T) {
	svc, repo := newRBACFixture(t)
	ctx := context.Background()
	seedRepoUser(t, repo, "user-8", "u8@test.com", "member")
	// Seed a role + assignment while the repo is healthy, then flip the
	// repo into an error state for the service-layer error-wrap branches.
	if _, err := svc.CreateRole(ctx, "admin-1", "ops", "", []string{"ops:run"}); err != nil {
		t.Fatalf("CreateRole seed: %v", err)
	}

	sentinel := errors.New("repo exploded")
	repo.mu.Lock()
	repo.rbacErr = sentinel
	repo.mu.Unlock()

	if _, err := svc.CreateRole(ctx, "admin-1", "new", "", []string{"x"}); !errors.Is(err, sentinel) {
		t.Fatalf("CreateRole error: want sentinel, got %v", err)
	}
	if _, err := svc.ListRoles(ctx, "admin-1"); !errors.Is(err, sentinel) {
		t.Fatalf("ListRoles error: want sentinel, got %v", err)
	}
	if err := svc.DeleteRole(ctx, "admin-1", "ops"); !errors.Is(err, sentinel) {
		t.Fatalf("DeleteRole error: want sentinel, got %v", err)
	}
	// AssignRole: GetRoleByName fails after the user lookup succeeds.
	if err := svc.AssignRole(ctx, "admin-1", "user-8", "ops"); !errors.Is(err, sentinel) {
		t.Fatalf("AssignRole error: want sentinel, got %v", err)
	}
	// revokeRole path (empty role name) hits DeleteUserRoleAssignment.
	if err := svc.AssignRole(ctx, "admin-1", "user-8", ""); !errors.Is(err, sentinel) {
		t.Fatalf("revokeRole error: want sentinel, got %v", err)
	}
	// effectivePermissions: GetUserRoleAssignment fails.
	if err := svc.HasPermission(ctx, "user-8", "ops:run"); !errors.Is(err, sentinel) {
		t.Fatalf("HasPermission error: want sentinel, got %v", err)
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
