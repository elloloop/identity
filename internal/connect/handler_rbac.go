package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// ─── RBAC RPCs ───────────────────────────────────────────────────────────
// Custom scoped roles and per-user assignments. ADDITIVE least-privilege
// layer; admin-only (the JWT must carry role=admin, enforced in the service).

func roleToProto(r *service.RoleRecord) *identitypb.Role {
	if r == nil {
		return nil
	}
	return &identitypb.Role{
		Name:        r.Name,
		Description: r.Description,
		Permissions: r.Permissions,
		CreatedAtMs: r.CreatedAt,
		UpdatedAtMs: r.UpdatedAt,
	}
}

// CreateRole defines a custom role with an explicit permission subset.
func (h *IdentityHandler) CreateRole(
	ctx context.Context,
	req *connect.Request[identitypb.CreateRoleRequest],
) (*connect.Response[identitypb.CreateRoleResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	role, err := h.admin.CreateRole(ctx, callerID, req.Msg.Name, req.Msg.Description, req.Msg.Permissions)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.CreateRoleResponse{Role: roleToProto(role)}), nil
}

// ListRoles returns every custom role defined in the project.
func (h *IdentityHandler) ListRoles(
	ctx context.Context,
	req *connect.Request[identitypb.ListRolesRequest],
) (*connect.Response[identitypb.ListRolesResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	roles, err := h.admin.ListRoles(ctx, callerID)
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*identitypb.Role, 0, len(roles))
	for _, r := range roles {
		out = append(out, roleToProto(r))
	}
	return connect.NewResponse(&identitypb.ListRolesResponse{Roles: out}), nil
}

// DeleteRole removes a custom role and every assignment referencing it.
func (h *IdentityHandler) DeleteRole(
	ctx context.Context,
	req *connect.Request[identitypb.DeleteRoleRequest],
) (*connect.Response[identitypb.DeleteRoleResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	if err := h.admin.DeleteRole(ctx, callerID, req.Msg.Name); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.DeleteRoleResponse{}), nil
}

// AssignRole binds a user to a custom role (or clears it when role_name is empty).
func (h *IdentityHandler) AssignRole(
	ctx context.Context,
	req *connect.Request[identitypb.AssignRoleRequest],
) (*connect.Response[identitypb.AssignRoleResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	if err := h.admin.AssignRole(ctx, callerID, req.Msg.UserId, req.Msg.RoleName); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AssignRoleResponse{}), nil
}

// GetUserPermissions returns the effective permission view for a user.
func (h *IdentityHandler) GetUserPermissions(
	ctx context.Context,
	req *connect.Request[identitypb.GetUserPermissionsRequest],
) (*connect.Response[identitypb.GetUserPermissionsResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	superset, roleName, perms, err := h.admin.GetUserPermissions(ctx, callerID, req.Msg.UserId)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.GetUserPermissionsResponse{
		Superset:    superset,
		RoleName:    roleName,
		Permissions: perms,
	}), nil
}
