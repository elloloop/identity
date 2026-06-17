package sqlite

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// TestSQLiteRBAC_RoleCRUD covers the role store happy paths plus the
// driver-specific JSON (de)serialisation round-trip.
func TestSQLiteRBAC_RoleCRUD(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := newTestRepo(t, "sqlite-rbac")

	id, err := repo.CreateRole(ctx, &service.RoleRecord{
		Name: "auditor", Description: "read-only", Permissions: []string{"audit:read", "audit:list"},
		CreatedAt: 100, UpdatedAt: 100,
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if id == "" {
		t.Fatal("CreateRole returned empty id")
	}

	got, err := repo.GetRoleByName(ctx, "auditor")
	if err != nil {
		t.Fatalf("GetRoleByName: %v", err)
	}
	if got == nil || got.Name != "auditor" || len(got.Permissions) != 2 {
		t.Fatalf("GetRoleByName round-trip: %#v", got)
	}
	if got.Permissions[0] != "audit:read" || got.Permissions[1] != "audit:list" {
		t.Fatalf("permission ordering not preserved: %#v", got.Permissions)
	}

	roles, err := repo.ListRoles(ctx)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != 1 || roles[0].Name != "auditor" {
		t.Fatalf("ListRoles: %#v", roles)
	}

	if err := repo.DeleteRole(ctx, "auditor"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	gone, err := repo.GetRoleByName(ctx, "auditor")
	if err != nil {
		t.Fatalf("GetRoleByName after delete: %v", err)
	}
	if gone != nil {
		t.Fatalf("expected nil after delete, got %#v", gone)
	}
}

// TestSQLiteRBAC_CreateRole_Duplicate asserts the unique (project_id, name)
// index rejects a duplicate.
func TestSQLiteRBAC_CreateRole_Duplicate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := newTestRepo(t, "sqlite-rbac-dup")

	rec := &service.RoleRecord{Name: "billing", Permissions: []string{"billing:read"}, CreatedAt: 1, UpdatedAt: 1}
	if _, err := repo.CreateRole(ctx, rec); err != nil {
		t.Fatalf("first CreateRole: %v", err)
	}
	if _, err := repo.CreateRole(ctx, &service.RoleRecord{Name: "billing", Permissions: []string{"billing:read"}}); !errors.Is(err, service.ErrAlreadyExists) {
		t.Fatalf("duplicate: want ErrAlreadyExists, got %v", err)
	}
}

// TestSQLiteRBAC_CreateRole_NilRecord guards the nil-record validation.
func TestSQLiteRBAC_CreateRole_NilRecord(t *testing.T) {
	t.Parallel()
	repo := newTestRepo(t, "sqlite-rbac-nil")
	if _, err := repo.CreateRole(context.Background(), nil); err == nil {
		t.Fatal("CreateRole(nil): expected error")
	}
}

// TestSQLiteRBAC_GetRoleByName_NotFoundAndEmpty covers the empty-name guard
// and the no-rows path.
func TestSQLiteRBAC_GetRoleByName_NotFoundAndEmpty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := newTestRepo(t, "sqlite-rbac-nf")

	if got, err := repo.GetRoleByName(ctx, ""); err != nil || got != nil {
		t.Fatalf("empty name: got %#v, err %v", got, err)
	}
	if got, err := repo.GetRoleByName(ctx, "ghost"); err != nil || got != nil {
		t.Fatalf("unknown role: got %#v, err %v", got, err)
	}
}

// TestSQLiteRBAC_Assignment covers set (insert + upsert), get, not-found and
// delete of a per-user role assignment.
func TestSQLiteRBAC_Assignment(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := newTestRepo(t, "sqlite-rbac-assign")

	// The assignment row has composite FKs to users(id) and rbac_roles
	// (project_id, name): seed both before assigning.
	uid, err := repo.CreateUser(ctx, &service.User{Email: "u1@e.com", Name: "U1", Role: "member", Status: "active"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	for _, name := range []string{"auditor", "editor"} {
		if _, err := repo.CreateRole(ctx, &service.RoleRecord{Name: name, Permissions: []string{"x:do"}, CreatedAt: 1, UpdatedAt: 1}); err != nil {
			t.Fatalf("CreateRole %q: %v", name, err)
		}
	}

	// Empty user-id guards.
	if err := repo.SetUserRoleAssignment(ctx, "", "auditor", 1); err == nil {
		t.Fatal("SetUserRoleAssignment(empty user): expected error")
	}
	if got, err := repo.GetUserRoleAssignment(ctx, ""); err != nil || got != nil {
		t.Fatalf("GetUserRoleAssignment(empty): got %#v err %v", got, err)
	}
	if err := repo.DeleteUserRoleAssignment(ctx, ""); err != nil {
		t.Fatalf("DeleteUserRoleAssignment(empty): %v", err)
	}

	// Not found.
	if got, err := repo.GetUserRoleAssignment(ctx, uid); err != nil || got != nil {
		t.Fatalf("unassigned user: got %#v err %v", got, err)
	}

	// Insert.
	if err := repo.SetUserRoleAssignment(ctx, uid, "auditor", 100); err != nil {
		t.Fatalf("SetUserRoleAssignment insert: %v", err)
	}
	got, err := repo.GetUserRoleAssignment(ctx, uid)
	if err != nil || got == nil || got.RoleName != "auditor" || got.CreatedAt != 100 {
		t.Fatalf("after insert: %#v err %v", got, err)
	}

	// Upsert replaces the role + timestamp for the same user.
	if err := repo.SetUserRoleAssignment(ctx, uid, "editor", 200); err != nil {
		t.Fatalf("SetUserRoleAssignment upsert: %v", err)
	}
	got, err = repo.GetUserRoleAssignment(ctx, uid)
	if err != nil || got == nil || got.RoleName != "editor" || got.CreatedAt != 200 {
		t.Fatalf("after upsert: %#v err %v", got, err)
	}

	// Delete.
	if err := repo.DeleteUserRoleAssignment(ctx, uid); err != nil {
		t.Fatalf("DeleteUserRoleAssignment: %v", err)
	}
	if got, err := repo.GetUserRoleAssignment(ctx, uid); err != nil || got != nil {
		t.Fatalf("after delete: got %#v err %v", got, err)
	}
}

// TestSQLiteRBAC_DeleteRole_EmptyAndUnknown covers the empty-name short
// circuit and the no-op delete of a non-existent role.
func TestSQLiteRBAC_DeleteRole_EmptyAndUnknown(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := newTestRepo(t, "sqlite-rbac-del")
	if err := repo.DeleteRole(ctx, ""); err != nil {
		t.Fatalf("DeleteRole(empty): %v", err)
	}
	if err := repo.DeleteRole(ctx, "ghost"); err != nil {
		t.Fatalf("DeleteRole(unknown): %v", err)
	}
}

// TestSQLiteRBAC_PermissionJSON covers the marshal/unmarshal helpers for the
// nil/empty edge cases that the CRUD paths don't hit.
func TestSQLiteRBAC_PermissionJSON(t *testing.T) {
	t.Parallel()
	s, err := marshalPermissions(nil)
	if err != nil || s != "[]" {
		t.Fatalf("marshalPermissions(nil) = %q, %v", s, err)
	}
	out, err := unmarshalPermissions("")
	if err != nil || out != nil {
		t.Fatalf("unmarshalPermissions(\"\") = %#v, %v", out, err)
	}
	if _, err := unmarshalPermissions("not-json"); err == nil {
		t.Fatal("unmarshalPermissions(invalid): expected error")
	}
}
