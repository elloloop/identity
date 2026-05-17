package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	"github.com/elloloop/identity/internal/service"
)

// OrganizationSignup creates a new tenant + admin user in one
// transaction. Only available in `mode=multi`; returns
// CodeUnimplemented in `mode=single` per docs/IDENTITY.md decision
// log §3.
func (h *IdentityHandler) OrganizationSignup(
	ctx context.Context,
	req *connect.Request[identitypb.OrganizationSignupRequest],
) (*connect.Response[identitypb.OrganizationSignupResponse], error) {
	if h.cfg == nil || !h.cfg.IsMultiMode() || h.orgSignup == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}

	result, err := h.orgSignup.Signup(
		ctx,
		req.Msg.Slug,
		req.Msg.DisplayName,
		req.Msg.AdminEmail,
		req.Msg.AdminPassword,
		req.Msg.AdminName,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.OrganizationSignupResponse{
		Organization: organizationToProto(result.Organization),
		AdminUser:    userToProto(result.User),
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}
	return connect.NewResponse(resp), nil
}

// organizationToProto converts the service-layer Organization to the
// proto wire message.
func organizationToProto(o *service.Organization) *identitypb.Organization {
	if o == nil {
		return nil
	}
	return &identitypb.Organization{
		Id:          o.ID,
		Slug:        o.Slug,
		DisplayName: o.DisplayName,
		OwnerUserId: o.OwnerUserID,
		CreatedAt:   msToTimestamp(o.CreatedAtMs),
		UpdatedAt:   msToTimestamp(o.UpdatedAtMs),
	}
}
