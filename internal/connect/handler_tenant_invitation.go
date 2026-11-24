package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// GetTenantInvitation describes the invitation a raw token names to whoever
// holds the token; it needs no session. Available only on the postgres
// control-plane driver; nil service (memory) returns Unimplemented.
func (h *IdentityHandler) GetTenantInvitation(
	ctx context.Context,
	req *connect.Request[identitypb.GetTenantInvitationRequest],
) (*connect.Response[identitypb.GetTenantInvitationResponse], error) {
	if h.members == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	view, err := h.members.GetTenantInvitation(ctx, req.Msg.GetToken())
	if err != nil {
		return nil, toConnectError(err)
	}
	resp := connect.NewResponse(&identitypb.GetTenantInvitationResponse{
		TenantId:      view.TenantID,
		TenantName:    view.TenantName,
		InviterName:   view.InviterName,
		InviterEmail:  view.InviterEmail,
		Email:         view.Email,
		Role:          view.Role,
		ExpiresAtMs:   view.ExpiresAtMs,
		Status:        view.Status,
		AccountExists: view.AccountExists,
	})
	resp.Header().Set("Cache-Control", "no-store")
	return resp, nil
}

// SignUpWithTenantInvitation creates the account a pending tenant invitation
// names and signs it in. It is gated as PasswordSignup is (local auth,
// password signup, client assurance).
func (h *IdentityHandler) SignUpWithTenantInvitation(
	ctx context.Context,
	req *connect.Request[identitypb.SignUpWithTenantInvitationRequest],
) (*connect.Response[identitypb.SignUpWithTenantInvitationResponse], error) {
	if h.cfg != nil && !h.cfg.PasswordSignupEnabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, service.ErrSignupDisabled)
	}
	if err := h.requireAssurance(ctx, h.assuranceEnforcePasswordSignup(), req.Header()); err != nil {
		return nil, toConnectError(err)
	}
	result, err := h.auth.SignUpWithTenantInvitation(ctx, req.Msg.GetToken(), req.Msg.GetName(), req.Msg.GetPassword(),
		clientIP(req.Header()), clientUserAgent(req.Header()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.SignUpWithTenantInvitationResponse{
		User:         userToProto(result.User),
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}), nil
}
