package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// AdminGetTenant returns a tenant's own record. Operator-only: the admin
// secret, or a tenant_operator credential of the project.
func (h *IdentityHandler) AdminGetTenant(
	ctx context.Context,
	req *connect.Request[identitypb.AdminGetTenantRequest],
) (*connect.Response[identitypb.AdminGetTenantResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	t, err := h.controlAdmin.AdminGetTenant(ctx, operatorCredentials(req.Header()), req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AdminGetTenantResponse{Tenant: tenantToProto(t)}), nil
}

// AdminListTenants pages through a project's tenants. Operator-only: the
// admin secret, or a tenant_operator credential of the project.
func (h *IdentityHandler) AdminListTenants(
	ctx context.Context,
	req *connect.Request[identitypb.AdminListTenantsRequest],
) (*connect.Response[identitypb.AdminListTenantsResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	page, err := h.controlAdmin.AdminListTenants(ctx, operatorCredentials(req.Header()), req.Msg.ProjectId, req.Msg.Limit, req.Msg.Cursor)
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*identitypb.Tenant, 0, len(page.Tenants))
	for _, t := range page.Tenants {
		out = append(out, tenantToProto(t))
	}
	return connect.NewResponse(&identitypb.AdminListTenantsResponse{Tenants: out, NextCursor: page.NextCursor}), nil
}

// AdminSuspendTenant suspends a claimed tenant. Operator-only: the admin
// secret, or a tenant_operator credential of the project.
func (h *IdentityHandler) AdminSuspendTenant(
	ctx context.Context,
	req *connect.Request[identitypb.AdminSuspendTenantRequest],
) (*connect.Response[identitypb.AdminSuspendTenantResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	t, err := h.controlAdmin.AdminSuspendTenant(ctx, operatorCredentials(req.Header()), req.Msg.ProjectId, req.Msg.TenantId, req.Msg.Reason,
		clientIP(req.Header()), clientUserAgent(req.Header()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AdminSuspendTenantResponse{Tenant: tenantToProto(t)}), nil
}

// AdminRestoreTenant moves a suspended tenant back to claimed. Operator-only:
// the admin secret, or a tenant_operator credential of the project.
func (h *IdentityHandler) AdminRestoreTenant(
	ctx context.Context,
	req *connect.Request[identitypb.AdminRestoreTenantRequest],
) (*connect.Response[identitypb.AdminRestoreTenantResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	t, err := h.controlAdmin.AdminRestoreTenant(ctx, operatorCredentials(req.Header()), req.Msg.ProjectId, req.Msg.TenantId, req.Msg.Reason,
		clientIP(req.Header()), clientUserAgent(req.Header()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AdminRestoreTenantResponse{Tenant: tenantToProto(t)}), nil
}

// AdminRecoverTenantOwnership appoints an owner to a tenant with no owner or
// admin left who both can sign in and holds an active membership.
// Operator-only: the admin secret, or a tenant_operator credential of the
// project.
func (h *IdentityHandler) AdminRecoverTenantOwnership(
	ctx context.Context,
	req *connect.Request[identitypb.AdminRecoverTenantOwnershipRequest],
) (*connect.Response[identitypb.AdminRecoverTenantOwnershipResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	m, err := h.controlAdmin.AdminRecoverTenantOwnership(ctx, operatorCredentials(req.Header()), req.Msg.ProjectId, req.Msg.TenantId, req.Msg.UserId, req.Msg.Reason,
		clientIP(req.Header()), clientUserAgent(req.Header()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AdminRecoverTenantOwnershipResponse{Membership: membershipToProto(m)}), nil
}

// tenantToProto converts a service-layer Tenant to the proto wire message.
func tenantToProto(t *service.Tenant) *identitypb.Tenant {
	if t == nil {
		return nil
	}
	return &identitypb.Tenant{
		Id:            t.ID,
		Name:          t.Name,
		PrimaryDomain: t.PrimaryDomain,
		Status:        t.Status,
		CreatedBy:     t.CreatedBy,
		CreatedAt:     msToTimestamp(t.CreatedAtMs),
		UpdatedAt:     msToTimestamp(t.UpdatedAtMs),
	}
}
