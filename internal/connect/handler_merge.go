package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// MergeAccounts merges another of the caller's accounts into the caller's.
func (h *IdentityHandler) MergeAccounts(
	ctx context.Context,
	req *connect.Request[identitypb.MergeAccountsRequest],
) (*connect.Response[identitypb.MergeAccountsResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	// The other account's password is checked as a sign-in is, so the client
	// assurance a password sign-in requires is required here too.
	if err := h.requireAssurance(ctx, h.assuranceEnforcePasswordLogin(), req.Header()); err != nil {
		return nil, toConnectError(err)
	}
	user, err := h.auth.MergeAccounts(ctx, callerID, req.Msg.OtherIdentifier, req.Msg.OtherPassword,
		clientIP(req.Header()), clientUserAgent(req.Header()), req.Msg.TakeAddress)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.MergeAccountsResponse{User: userToProto(user)}), nil
}

// MergeUsers merges one account into another. Admin only.
func (h *IdentityHandler) MergeUsers(
	ctx context.Context,
	req *connect.Request[identitypb.MergeUsersRequest],
) (*connect.Response[identitypb.MergeUsersResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	user, err := h.admin.MergeUsers(ctx, callerID, req.Msg.SurvivorUserId, req.Msg.OtherUserId, req.Msg.TakeAddress)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.MergeUsersResponse{User: userToProto(user)}), nil
}
