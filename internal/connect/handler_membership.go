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

	if err := h.members.RemoveTenantMember(ctx, userID, req.Msg.TenantId, req.Msg.UserId); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.RemoveTenantMemberResponse{}), nil
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
