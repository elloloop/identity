package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// CreateTenantInvitation invites an email to join a tenant. Owner/admin only.
// Available only on the postgres control-plane driver; nil service
// (memory) returns Unimplemented.
func (h *IdentityHandler) CreateTenantInvitation(
	ctx context.Context,
	req *connect.Request[identitypb.CreateTenantInvitationRequest],
) (*connect.Response[identitypb.CreateTenantInvitationResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	created, err := h.members.CreateTenantInvitation(ctx, userID, req.Msg.TenantId, req.Msg.Email, req.Msg.Role)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.CreateTenantInvitationResponse{
		Invitation: invitationToProto(created.Invitation),
		RawToken:   created.RawToken,
	}), nil
}

// AcceptTenantInvitation redeems a raw invitation token for the authenticated
// caller, making them a member of the tenant.
func (h *IdentityHandler) AcceptTenantInvitation(
	ctx context.Context,
	req *connect.Request[identitypb.AcceptTenantInvitationRequest],
) (*connect.Response[identitypb.AcceptTenantInvitationResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	m, err := h.members.AcceptTenantInvitation(ctx, userID, req.Msg.Token)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AcceptTenantInvitationResponse{
		Membership: membershipToProto(m),
	}), nil
}

// ListTenantInvitations lists every invitation in a tenant. Owner/admin only.
func (h *IdentityHandler) ListTenantInvitations(
	ctx context.Context,
	req *connect.Request[identitypb.ListTenantInvitationsRequest],
) (*connect.Response[identitypb.ListTenantInvitationsResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	invs, err := h.members.ListTenantInvitations(ctx, userID, req.Msg.TenantId)
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*identitypb.TenantInvitation, 0, len(invs))
	for _, inv := range invs {
		out = append(out, invitationToProto(inv))
	}
	return connect.NewResponse(&identitypb.ListTenantInvitationsResponse{
		Invitations: out,
	}), nil
}

// ListTenantMembers lists every membership in a tenant. Owner/admin only.
func (h *IdentityHandler) ListTenantMembers(
	ctx context.Context,
	req *connect.Request[identitypb.ListTenantMembersRequest],
) (*connect.Response[identitypb.ListTenantMembersResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	mems, err := h.members.ListTenantMembers(ctx, userID, req.Msg.TenantId)
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*identitypb.TenantMembership, 0, len(mems))
	for _, m := range mems {
		out = append(out, membershipToProto(m))
	}
	return connect.NewResponse(&identitypb.ListTenantMembersResponse{
		Members: out,
	}), nil
}

// RemoveTenantMember removes a user's membership from a tenant. Owner/admin
// only, and never the tenant's last owner.
func (h *IdentityHandler) RemoveTenantMember(
	ctx context.Context,
	req *connect.Request[identitypb.RemoveTenantMemberRequest],
) (*connect.Response[identitypb.RemoveTenantMemberResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	if err := h.members.RemoveTenantMember(ctx, userID, req.Msg.TenantId, req.Msg.UserId, clientIP(req.Header()), clientUserAgent(req.Header())); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.RemoveTenantMemberResponse{}), nil
}

// SuspendTenantMember stops a member acting in a tenant, keeping their
// membership. Owner/admin only, never the caller, and never the tenant's
// last active owner.
func (h *IdentityHandler) SuspendTenantMember(
	ctx context.Context,
	req *connect.Request[identitypb.SuspendTenantMemberRequest],
) (*connect.Response[identitypb.SuspendTenantMemberResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	m, err := h.members.SuspendTenantMember(ctx, userID, req.Msg.GetTenantId(), req.Msg.GetUserId(), clientIP(req.Header()), clientUserAgent(req.Header()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.SuspendTenantMemberResponse{Membership: membershipToProto(m)}), nil
}

// RestoreTenantMember lets a suspended member act in a tenant again.
// Owner/admin only.
func (h *IdentityHandler) RestoreTenantMember(
	ctx context.Context,
	req *connect.Request[identitypb.RestoreTenantMemberRequest],
) (*connect.Response[identitypb.RestoreTenantMemberResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	m, err := h.members.RestoreTenantMember(ctx, userID, req.Msg.GetTenantId(), req.Msg.GetUserId(), clientIP(req.Header()), clientUserAgent(req.Header()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.RestoreTenantMemberResponse{Membership: membershipToProto(m)}), nil
}

// TransferTenantOwnership hands the caller's ownership of a tenant to another
// active member, leaving the caller an admin. Owner only.
func (h *IdentityHandler) TransferTenantOwnership(
	ctx context.Context,
	req *connect.Request[identitypb.TransferTenantOwnershipRequest],
) (*connect.Response[identitypb.TransferTenantOwnershipResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	transfer, err := h.members.TransferTenantOwnership(ctx, userID, req.Msg.GetTenantId(), req.Msg.GetUserId(), clientIP(req.Header()), clientUserAgent(req.Header()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.TransferTenantOwnershipResponse{
		Owner:         membershipToProto(transfer.Owner),
		PreviousOwner: membershipToProto(transfer.PreviousOwner),
	}), nil
}

// invitationToProto converts a service-layer TenantInvitation to the proto
// wire message. The token hash is never exposed.
func invitationToProto(inv *service.TenantInvitation) *identitypb.TenantInvitation {
	if inv == nil {
		return nil
	}
	return &identitypb.TenantInvitation{
		Id:         inv.ID,
		TenantId:   inv.TenantID,
		Email:      inv.Email,
		InvitedBy:  inv.InvitedBy,
		Role:       inv.Role,
		Status:     inv.Status,
		ExpiresAt:  msToTimestamp(inv.ExpiresAtMs),
		AcceptedAt: msToTimestamp(inv.AcceptedAtMs),
		CreatedAt:  msToTimestamp(inv.CreatedAtMs),
	}
}

// membershipToProto converts a service-layer TenantMembership to the proto
// wire message.
func membershipToProto(m *service.TenantMembership) *identitypb.TenantMembership {
	if m == nil {
		return nil
	}
	return &identitypb.TenantMembership{
		Id:        m.ID,
		TenantId:  m.TenantID,
		UserId:    m.UserID,
		Source:    m.Source,
		Role:      m.Role,
		Status:    m.Status,
		CreatedAt: msToTimestamp(m.CreatedAtMs),
		UpdatedAt: msToTimestamp(m.UpdatedAtMs),
	}
}

// CreateTenant creates a tenant the authenticated caller owns, when the
// caller's project allows self-service tenants.
func (h *IdentityHandler) CreateTenant(
	ctx context.Context,
	req *connect.Request[identitypb.CreateTenantRequest],
) (*connect.Response[identitypb.CreateTenantResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	created, err := h.members.CreateTenant(ctx, userID, req.Msg.GetName(), clientIP(req.Header()), clientUserAgent(req.Header()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.CreateTenantResponse{
		TenantId:   created.Tenant.ID,
		Name:       created.Tenant.Name,
		Membership: membershipToProto(created.Membership),
	}), nil
}

// ListMyTenants lists the tenants the authenticated caller may act in.
func (h *IdentityHandler) ListMyTenants(
	ctx context.Context,
	req *connect.Request[identitypb.ListMyTenantsRequest],
) (*connect.Response[identitypb.ListMyTenantsResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	tenants, err := h.members.ListMyTenants(ctx, userID)
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*identitypb.UserTenant, 0, len(tenants))
	for _, t := range tenants {
		out = append(out, &identitypb.UserTenant{TenantId: t.TenantID, Name: t.Name, Role: t.Role})
	}
	return connect.NewResponse(&identitypb.ListMyTenantsResponse{Tenants: out}), nil
}

// ListJoinableTenants lists the tenant the authenticated caller's verified
// email's domain lets them join.
func (h *IdentityHandler) ListJoinableTenants(
	ctx context.Context,
	req *connect.Request[identitypb.ListJoinableTenantsRequest],
) (*connect.Response[identitypb.ListJoinableTenantsResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	tenants, err := h.members.ListJoinableTenants(ctx, userID)
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*identitypb.JoinableTenant, 0, len(tenants))
	for _, t := range tenants {
		out = append(out, &identitypb.JoinableTenant{TenantId: t.TenantID, Name: t.Name})
	}
	return connect.NewResponse(&identitypb.ListJoinableTenantsResponse{Tenants: out}), nil
}

// JoinTenantByDomain makes the authenticated caller a member of the tenant
// their verified email's domain lets them join.
func (h *IdentityHandler) JoinTenantByDomain(
	ctx context.Context,
	req *connect.Request[identitypb.JoinTenantByDomainRequest],
) (*connect.Response[identitypb.JoinTenantByDomainResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	m, err := h.members.JoinTenantByDomain(ctx, userID, req.Msg.GetTenantId(), clientIP(req.Header()), clientUserAgent(req.Header()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.JoinTenantByDomainResponse{
		Membership: membershipToProto(m),
	}), nil
}
