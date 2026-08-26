package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// ─── Parental account management RPCs ───────────────────────────────────────
//
// The guardian-authorized management surface over a managed child account.
// Every handler here takes the ACTING GUARDIAN from the authenticated session
// (X-Authenticated-User-Id, set by the auth middleware after verifying the
// JWT) and never from the request body — the request messages deliberately
// carry no caller identity field, so a modified client cannot assert who is
// acting. The service applies both mandatory checks at one chokepoint (an
// active guardianOf edge to the child AND a step-up password re-entry) and
// answers a caller without an edge with an account-agnostic PERMISSION_DENIED.

// GetManagedChildProfile returns the managed child's stored profile.
func (h *IdentityHandler) GetManagedChildProfile(
	ctx context.Context,
	req *connect.Request[identitypb.GetManagedChildProfileRequest],
) (*connect.Response[identitypb.GetManagedChildProfileResponse], error) {
	guardianUserID := authenticatedUserID(req.Header())
	if guardianUserID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	child, err := h.auth.GetManagedChildProfile(
		ctx, guardianUserID,
		req.Msg.GetChildUserId(), req.Msg.GetStepUpPassword(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.GetManagedChildProfileResponse{
		Child: userToProto(child),
	}), nil
}

// SetManagedChildPassword sets the child's password directly and cuts the
// child's sessions.
func (h *IdentityHandler) SetManagedChildPassword(
	ctx context.Context,
	req *connect.Request[identitypb.SetManagedChildPasswordRequest],
) (*connect.Response[identitypb.SetManagedChildPasswordResponse], error) {
	guardianUserID := authenticatedUserID(req.Header())
	if guardianUserID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	if err := h.auth.SetManagedChildPassword(
		ctx, guardianUserID,
		req.Msg.GetChildUserId(), req.Msg.GetNewPassword(), req.Msg.GetStepUpPassword(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.SetManagedChildPasswordResponse{}), nil
}

// SetManagedChildUsername changes the child's project-unique handle.
func (h *IdentityHandler) SetManagedChildUsername(
	ctx context.Context,
	req *connect.Request[identitypb.SetManagedChildUsernameRequest],
) (*connect.Response[identitypb.SetManagedChildUsernameResponse], error) {
	guardianUserID := authenticatedUserID(req.Header())
	if guardianUserID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	child, err := h.auth.SetManagedChildUsername(
		ctx, guardianUserID,
		req.Msg.GetChildUserId(), req.Msg.GetUsername(), req.Msg.GetStepUpPassword(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.SetManagedChildUsernameResponse{
		Child: userToProto(child),
	}), nil
}

// RevokeManagedChildSessions invalidates every session and refresh token of
// the child.
func (h *IdentityHandler) RevokeManagedChildSessions(
	ctx context.Context,
	req *connect.Request[identitypb.RevokeManagedChildSessionsRequest],
) (*connect.Response[identitypb.RevokeManagedChildSessionsResponse], error) {
	guardianUserID := authenticatedUserID(req.Header())
	if guardianUserID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	if err := h.auth.RevokeManagedChildSessions(
		ctx, guardianUserID,
		req.Msg.GetChildUserId(), req.Msg.GetStepUpPassword(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.RevokeManagedChildSessionsResponse{}), nil
}

// DeactivateManagedChildAccount suspends the child's account, reversibly.
func (h *IdentityHandler) DeactivateManagedChildAccount(
	ctx context.Context,
	req *connect.Request[identitypb.DeactivateManagedChildAccountRequest],
) (*connect.Response[identitypb.DeactivateManagedChildAccountResponse], error) {
	guardianUserID := authenticatedUserID(req.Header())
	if guardianUserID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	if err := h.auth.DeactivateManagedChildAccount(
		ctx, guardianUserID,
		req.Msg.GetChildUserId(), req.Msg.GetReason(), req.Msg.GetStepUpPassword(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.DeactivateManagedChildAccountResponse{}), nil
}

// ReactivateManagedChildAccount returns a deactivated child account to
// active. It cannot move an account out of PENDING_PARENTAL_CONSENT.
func (h *IdentityHandler) ReactivateManagedChildAccount(
	ctx context.Context,
	req *connect.Request[identitypb.ReactivateManagedChildAccountRequest],
) (*connect.Response[identitypb.ReactivateManagedChildAccountResponse], error) {
	guardianUserID := authenticatedUserID(req.Header())
	if guardianUserID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	if err := h.auth.ReactivateManagedChildAccount(
		ctx, guardianUserID,
		req.Msg.GetChildUserId(), req.Msg.GetStepUpPassword(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.ReactivateManagedChildAccountResponse{}), nil
}

// DeleteManagedChildAccount erases the child account through the same
// hard-delete cascade the admin DeleteUser RPC runs.
func (h *IdentityHandler) DeleteManagedChildAccount(
	ctx context.Context,
	req *connect.Request[identitypb.DeleteManagedChildAccountRequest],
) (*connect.Response[identitypb.DeleteManagedChildAccountResponse], error) {
	guardianUserID := authenticatedUserID(req.Header())
	if guardianUserID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	if err := h.auth.DeleteManagedChildAccount(
		ctx, guardianUserID,
		req.Msg.GetChildUserId(), req.Msg.GetStepUpPassword(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.DeleteManagedChildAccountResponse{}), nil
}
