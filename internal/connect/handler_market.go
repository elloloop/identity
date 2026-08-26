package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// SetAccountMarket changes the jurisdiction/market code the authenticated
// caller's account classifies under. The caller is derived from the auth
// header; there is no user_id in the request. The service audits the change
// and re-derives the age band immediately, re-gating the account to
// PENDING_PARENTAL_CONSENT (and revoking its sessions) when the new market's
// thresholds newly classify it as CHILD.
func (h *IdentityHandler) SetAccountMarket(
	ctx context.Context,
	req *connect.Request[identitypb.SetAccountMarketRequest],
) (*connect.Response[identitypb.SetAccountMarketResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	user, err := h.auth.SetAccountMarket(ctx, userID, req.Msg.GetMarket())
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.SetAccountMarketResponse{
		User: userToProto(user),
	}), nil
}
