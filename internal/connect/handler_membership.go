package connect

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// CreateTenantInvitation invites an email to join a tenant, or, with
// account_username, account_domain or display_name, creates or resends the
// set-up link of an account the tenant manages. Owner/admin only.
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
	var created *service.CreatedInvitation
	var err error
	m := req.Msg
	if m.GetAccountUsername() != "" || m.GetAccountDomain() != "" || m.GetDisplayName() != "" {
		if strings.TrimSpace(m.GetNote()) != "" {
			return nil, toConnectError(fmt.Errorf("%w: a note goes only on an ordinary invitation", service.ErrInvalidArgument))
		}
		created, err = h.members.CreateManagedSetupInvitation(ctx, userID, authenticatedSignIn(req.Header()), service.ManagedAccountRequest{
			TenantID: m.GetTenantId(), Username: m.GetAccountUsername(), Domain: m.GetAccountDomain(),
			DisplayName: m.GetDisplayName(), DeliveryEmail: m.GetEmail(), Role: m.GetRole(),
		}, clientIP(req.Header()), clientUserAgent(req.Header()))
	} else {
		created, err = h.members.CreateTenantInvitation(ctx, userID, authenticatedSignIn(req.Header()), m.GetTenantId(), m.GetEmail(), m.GetRole(), m.GetNote())
	}
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.CreateTenantInvitationResponse{
		Invitation:      invitationToProto(created.Invitation),
		RawToken:        created.RawToken,
		EmailSendStatus: emailSendStatusToProto(created.EmailStatus),
	}), nil
}

func emailSendStatusToProto(s service.EmailSendStatus) identitypb.EmailSendStatus {
	switch s {
	case service.EmailSent:
		return identitypb.EmailSendStatus_EMAIL_SEND_STATUS_SENT
	case service.EmailSendFailed:
		return identitypb.EmailSendStatus_EMAIL_SEND_STATUS_FAILED
	case service.EmailNotConfigured:
		return identitypb.EmailSendStatus_EMAIL_SEND_STATUS_NOT_CONFIGURED
	default:
		return identitypb.EmailSendStatus_EMAIL_SEND_STATUS_UNSPECIFIED
	}
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

// RevokeTenantInvitation withdraws a pending invitation of a tenant.
// Owner/admin only.
func (h *IdentityHandler) RevokeTenantInvitation(
	ctx context.Context,
	req *connect.Request[identitypb.RevokeTenantInvitationRequest],
) (*connect.Response[identitypb.RevokeTenantInvitationResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	inv, err := h.members.RevokeTenantInvitation(ctx, userID, authenticatedSignIn(req.Header()), req.Msg.GetTenantId(), req.Msg.GetInvitationId(), clientIP(req.Header()), clientUserAgent(req.Header()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.RevokeTenantInvitationResponse{Invitation: invitationToProto(inv)}), nil
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

	if err := h.members.RemoveTenantMember(ctx, userID, authenticatedSignIn(req.Header()), req.Msg.TenantId, req.Msg.UserId, clientIP(req.Header()), clientUserAgent(req.Header())); err != nil {
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

	m, err := h.members.SuspendTenantMember(ctx, userID, authenticatedSignIn(req.Header()), req.Msg.GetTenantId(), req.Msg.GetUserId(), clientIP(req.Header()), clientUserAgent(req.Header()))
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

	m, err := h.members.RestoreTenantMember(ctx, userID, authenticatedSignIn(req.Header()), req.Msg.GetTenantId(), req.Msg.GetUserId(), clientIP(req.Header()), clientUserAgent(req.Header()))
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

	transfer, err := h.members.TransferTenantOwnership(ctx, userID, authenticatedSignIn(req.Header()), req.Msg.GetTenantId(), req.Msg.GetUserId(), clientIP(req.Header()), clientUserAgent(req.Header()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.TransferTenantOwnershipResponse{
		Owner:         membershipToProto(transfer.Owner),
		PreviousOwner: membershipToProto(transfer.PreviousOwner),
	}), nil
}

// SetTenantMemberRole makes a member an admin, or an admin a member.
// Owner/admin only; never an owner's role.
func (h *IdentityHandler) SetTenantMemberRole(
	ctx context.Context,
	req *connect.Request[identitypb.SetTenantMemberRoleRequest],
) (*connect.Response[identitypb.SetTenantMemberRoleResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	m, err := h.members.SetTenantMemberRole(ctx, userID, authenticatedSignIn(req.Header()), req.Msg.GetTenantId(), req.Msg.GetUserId(), req.Msg.GetRole(), clientIP(req.Header()), clientUserAgent(req.Header()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.SetTenantMemberRoleResponse{Membership: membershipToProto(m)}), nil
}

// invitationToProto converts a service-layer TenantInvitation to the proto
// wire message. The token hash is never exposed.
func invitationToProto(inv *service.TenantInvitation) *identitypb.TenantInvitation {
	if inv == nil {
		return nil
	}
	out := &identitypb.TenantInvitation{
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
	if inv.IsManagedSetup() {
		out.IsManagedSetup = true
		out.Email = inv.DeliveryEmail
		out.AccountAddress = inv.Email
		out.UserId = inv.UserID
	}
	return out
}

// membershipToProto converts a service-layer TenantMembership to the proto
// wire message.
func membershipToProto(m *service.TenantMembership) *identitypb.TenantMembership {
	if m == nil {
		return nil
	}
	return &identitypb.TenantMembership{
		Id:          m.ID,
		TenantId:    m.TenantID,
		UserId:      m.UserID,
		Source:      m.Source,
		Role:        m.Role,
		Status:      m.Status,
		CreatedAt:   msToTimestamp(m.CreatedAtMs),
		UpdatedAt:   msToTimestamp(m.UpdatedAtMs),
		AccountKind: accountKindToProto(m.AccountKind),
	}
}

func accountKindToProto(kind string) identitypb.AccountKind {
	switch kind {
	case service.AccountKindPersonal:
		return identitypb.AccountKind_ACCOUNT_KIND_PERSONAL
	case service.AccountKindManaged:
		return identitypb.AccountKind_ACCOUNT_KIND_MANAGED
	default:
		return identitypb.AccountKind_ACCOUNT_KIND_UNSPECIFIED
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

	tenants, err := h.members.ListMyTenants(ctx, userID, authenticatedSignIn(req.Header()))
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

func (h *IdentityHandler) CheckManagedAddresses(
	context.Context,
	*connect.Request[identitypb.CheckManagedAddressesRequest],
) (*connect.Response[identitypb.CheckManagedAddressesResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
}

func (h *IdentityHandler) ResetManagedAccount(
	context.Context,
	*connect.Request[identitypb.ResetManagedAccountRequest],
) (*connect.Response[identitypb.ResetManagedAccountResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
}
