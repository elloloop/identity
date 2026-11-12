package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// ─── Recovery email RPCs ────────────────────────────────────────────────────
//
// All four require auth: the caller is the verified `sub` the auth
// middleware injects, never a field in the request. They are intentionally
// absent from AuthExemptPaths.

// RequestRecoveryEmail mails a code to the address the caller wants to add.
func (h *IdentityHandler) RequestRecoveryEmail(
	ctx context.Context,
	req *connect.Request[identitypb.RequestRecoveryEmailRequest],
) (*connect.Response[identitypb.RequestRecoveryEmailResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, service.ErrUnauthenticated)
	}
	if err := h.auth.RequestRecoveryEmail(ctx, userID, authenticatedAuthTime(req.Header()), req.Msg.Email); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.RequestRecoveryEmailResponse{}), nil
}

// VerifyRecoveryEmail confirms the code and stores the address on the
// caller's account.
func (h *IdentityHandler) VerifyRecoveryEmail(
	ctx context.Context,
	req *connect.Request[identitypb.VerifyRecoveryEmailRequest],
) (*connect.Response[identitypb.VerifyRecoveryEmailResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, service.ErrUnauthenticated)
	}
	held, err := h.auth.VerifyRecoveryEmail(ctx, userID, authenticatedAuthTime(req.Header()), req.Msg.Email, req.Msg.Code)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.VerifyRecoveryEmailResponse{RecoveryEmails: recoveryEmailsToProto(held)}), nil
}

// ListRecoveryEmails returns the caller's recovery emails.
func (h *IdentityHandler) ListRecoveryEmails(
	ctx context.Context,
	req *connect.Request[identitypb.ListRecoveryEmailsRequest],
) (*connect.Response[identitypb.ListRecoveryEmailsResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, service.ErrUnauthenticated)
	}
	held, err := h.auth.ListRecoveryEmails(ctx, userID)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.ListRecoveryEmailsResponse{RecoveryEmails: recoveryEmailsToProto(held)}), nil
}

// RemoveRecoveryEmail removes one of the caller's recovery emails.
func (h *IdentityHandler) RemoveRecoveryEmail(
	ctx context.Context,
	req *connect.Request[identitypb.RemoveRecoveryEmailRequest],
) (*connect.Response[identitypb.RemoveRecoveryEmailResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, service.ErrUnauthenticated)
	}
	held, err := h.auth.RemoveRecoveryEmail(ctx, userID, authenticatedAuthTime(req.Header()), req.Msg.Email)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.RemoveRecoveryEmailResponse{RecoveryEmails: recoveryEmailsToProto(held)}), nil
}

func recoveryEmailsToProto(held []*service.RecoveryEmail) []*identitypb.RecoveryEmail {
	out := make([]*identitypb.RecoveryEmail, 0, len(held))
	for _, e := range held {
		out = append(out, &identitypb.RecoveryEmail{Email: e.Email, VerifiedAt: e.VerifiedAt})
	}
	return out
}
