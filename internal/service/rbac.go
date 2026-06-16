package service

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/elloloop/identity/pkg/audit"
)

// RBAC: project-scoped custom roles and per-user assignments.
//
// This layer is strictly ADDITIVE to the legacy free-text user.role
// field. The legacy admin/owner roles remain a full-access superset and
// are NEVER demoted: HasPermission short-circuits to true for them, so
// existing role=admin users keep full access regardless of any custom
// role/assignment. A custom role grants EXACTLY the permission strings it
// names; a user assigned a custom role is allowed a permission iff it is
// in that role's set, and is otherwise denied with ErrPermissionDenied.
//
// Roles and assignments are persisted via the Repository so all three
// drivers (memory, postgres, sqlite) back them identically and the
// conformance suite holds them to the same uniqueness/ordering/error
// contract.

// maxRoleNameLen / maxPermissionLen bound the role-name and permission
// strings so an unbounded name can't bloat the index or a row.
const (
	maxRoleNameLen   = 128
	maxPermissionLen = 256
)

// normalizeRoleName lower-cases and trims a custom role name so lookups
// are case-insensitive and stable (mirrors the legacy role handling in
// InviteUser, which lower-cases the role string).
func normalizeRoleName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// normalizePermissions trims, de-duplicates and sorts a permission set so
// storage is canonical and HasPermission can rely on membership alone.
// Empty strings are dropped.
func normalizePermissions(perms []string) []string {
	seen := make(map[string]struct{}, len(perms))
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// CreateRole defines a new project-scoped custom role with an explicit
// permission subset. Admin only. The role name must be unique within the
// project; a duplicate returns ErrAlreadyExists.
func (s *AdminService) CreateRole(ctx context.Context, actorID, name, description string, permissions []string) (*RoleRecord, error) {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, err
	}
	name = normalizeRoleName(name)
	if name == "" {
		return nil, fmt.Errorf("%w: role name is required", ErrInvalidArgument)
	}
	if len(name) > maxRoleNameLen {
		return nil, fmt.Errorf("%w: role name too long", ErrInvalidArgument)
	}
	if isAdminRole(name) || name == RoleMember || name == "guest" {
		return nil, fmt.Errorf("%w: %q is a reserved built-in role", ErrInvalidArgument, name)
	}
	perms := normalizePermissions(permissions)
	if len(perms) == 0 {
		return nil, fmt.Errorf("%w: at least one permission is required", ErrInvalidArgument)
	}
	for _, p := range perms {
		if len(p) > maxPermissionLen {
			return nil, fmt.Errorf("%w: permission %q too long", ErrInvalidArgument, p)
		}
	}

	now := nowMs()
	rec := &RoleRecord{
		Name:        name,
		Description: strings.TrimSpace(description),
		Permissions: perms,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	id, err := s.repo(ctx).CreateRole(ctx, rec)
	if err != nil {
		return nil, err
	}
	rec.NodeID = id

	s.audit.Log(ctx, audit.EventRoleCreated,
		audit.WithActor(actorID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"role": name, "permissions": perms}))
	return rec, nil
}

// ListRoles returns every custom role defined in the project, ordered by
// name. Admin only.
func (s *AdminService) ListRoles(ctx context.Context, actorID string) ([]*RoleRecord, error) {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, err
	}
	return s.repo(ctx).ListRoles(ctx)
}

// DeleteRole removes a custom role and every assignment that references
// it. Admin only. Built-in roles cannot be deleted.
func (s *AdminService) DeleteRole(ctx context.Context, actorID, name string) error {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return err
	}
	name = normalizeRoleName(name)
	if name == "" {
		return fmt.Errorf("%w: role name is required", ErrInvalidArgument)
	}
	if isAdminRole(name) || name == RoleMember || name == "guest" {
		return fmt.Errorf("%w: %q is a reserved built-in role", ErrInvalidArgument, name)
	}
	if err := s.repo(ctx).DeleteRole(ctx, name); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.EventRoleDeleted,
		audit.WithActor(actorID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"role": name}))
	return nil
}

// AssignRole binds a user to a custom role (replacing any prior
// assignment). Admin only. The role must exist; an unknown role returns
// ErrNotFound. The empty role name clears the assignment.
func (s *AdminService) AssignRole(ctx context.Context, actorID, targetUserID, roleName string) error {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return err
	}
	if targetUserID == "" {
		return fmt.Errorf("%w: user_id is required", ErrInvalidArgument)
	}
	roleName = normalizeRoleName(roleName)
	if roleName == "" {
		return s.revokeRole(ctx, actorID, targetUserID)
	}

	target, err := s.repo(ctx).GetUser(ctx, targetUserID)
	if err != nil {
		return fmt.Errorf("fetch target user: %w", err)
	}
	if target == nil {
		return fmt.Errorf("%w: user not found", ErrNotFound)
	}
	role, err := s.repo(ctx).GetRoleByName(ctx, roleName)
	if err != nil {
		return err
	}
	if role == nil {
		return fmt.Errorf("%w: role %q does not exist", ErrNotFound, roleName)
	}

	if err := s.repo(ctx).SetUserRoleAssignment(ctx, targetUserID, roleName, nowMs()); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.EventRoleAssigned,
		audit.WithActor(actorID), audit.WithTarget(targetUserID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"role": roleName}))
	return nil
}

// revokeRole clears a user's custom-role assignment.
func (s *AdminService) revokeRole(ctx context.Context, actorID, targetUserID string) error {
	if err := s.repo(ctx).DeleteUserRoleAssignment(ctx, targetUserID); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.EventRoleRevoked,
		audit.WithActor(actorID), audit.WithTarget(targetUserID), audit.WithSuccess(true))
	return nil
}

// GetUserPermissions returns the effective permission view for a user:
// the legacy admin/owner superset flag plus, when the user holds a custom
// role, that role's permission set. Admin only.
func (s *AdminService) GetUserPermissions(ctx context.Context, actorID, targetUserID string) (superset bool, roleName string, permissions []string, err error) {
	if _, e := s.requireAdmin(ctx, actorID); e != nil {
		return false, "", nil, e
	}
	if targetUserID == "" {
		return false, "", nil, fmt.Errorf("%w: user_id is required", ErrInvalidArgument)
	}
	return s.effectivePermissions(ctx, targetUserID)
}

// effectivePermissions resolves a user's effective permissions without an
// admin check — it is the shared engine behind GetUserPermissions and
// HasPermission. The legacy admin/owner role is a full-access superset
// (superset=true), in which case the permission list is irrelevant.
func (s *AdminService) effectivePermissions(ctx context.Context, userID string) (bool, string, []string, error) {
	u, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return false, "", nil, fmt.Errorf("fetch user: %w", err)
	}
	if u == nil {
		return false, "", nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}
	if isAdminRole(strings.ToLower(strings.TrimSpace(u.Role))) {
		return true, strings.ToLower(strings.TrimSpace(u.Role)), nil, nil
	}
	assignment, err := s.repo(ctx).GetUserRoleAssignment(ctx, userID)
	if err != nil {
		return false, "", nil, err
	}
	if assignment == nil {
		return false, "", nil, nil
	}
	role, err := s.repo(ctx).GetRoleByName(ctx, assignment.RoleName)
	if err != nil {
		return false, "", nil, err
	}
	if role == nil {
		// Assignment dangling past a role delete (should not happen —
		// DeleteRole cascades — but fail closed).
		return false, assignment.RoleName, nil, nil
	}
	return false, role.RoleName(), role.Permissions, nil
}

// RoleName returns the role's name; a thin helper so effectivePermissions
// can return the canonical name without leaking the record.
func (r *RoleRecord) RoleName() string { return r.Name }

// HasPermission reports whether the user is allowed to perform the action
// named by permission. The legacy admin/owner role is always allowed
// (full-access superset); otherwise the user must hold a custom role whose
// permission set contains permission. Returns ErrPermissionDenied when not
// allowed so callers can enforce least-privilege ALONGSIDE the existing
// role==admin checks without changing them.
func (s *AdminService) HasPermission(ctx context.Context, userID, permission string) error {
	permission = strings.TrimSpace(permission)
	if permission == "" {
		return fmt.Errorf("%w: permission is required", ErrInvalidArgument)
	}
	superset, _, perms, err := s.effectivePermissions(ctx, userID)
	if err != nil {
		return err
	}
	if superset {
		return nil
	}
	for _, p := range perms {
		if p == permission {
			return nil
		}
	}
	return fmt.Errorf("%w: missing permission %q", ErrPermissionDenied, permission)
}
