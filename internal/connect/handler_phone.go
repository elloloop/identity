package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	"github.com/elloloop/identity/internal/service"
)

// ─── Phone Verification (SMS OTP) RPCs ──────────────────────────────────────
//
// Both RPCs require auth: the caller is identified by the verified `sub`
// the auth middleware injects (authenticatedUserID), NOT by a field in
// the request. They are intentionally absent from AuthExemptPaths.

// RequestPhoneVerification texts a 6-digit code to the supplied number
// for the authenticated caller to confirm.
func (h *IdentityHandler) RequestPhoneVerification(
	ctx context.Context,
	req *connect.Request[identitypb.RequestPhoneVerificationRequest],
) (*connect.Response[identitypb.RequestPhoneVerificationResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, service.ErrUnauthenticated)
	}
	if err := h.auth.RequestPhoneVerification(ctx, userID, req.Msg.PhoneNumber); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.RequestPhoneVerificationResponse{}), nil
}

// VerifyPhoneCode validates the OTP and marks the authenticated caller's
// phone verified, returning the updated user.
func (h *IdentityHandler) VerifyPhoneCode(
	ctx context.Context,
	req *connect.Request[identitypb.VerifyPhoneCodeRequest],
) (*connect.Response[identitypb.VerifyPhoneCodeResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, service.ErrUnauthenticated)
	}
	user, err := h.auth.VerifyPhoneCode(ctx, userID, req.Msg.PhoneNumber, req.Msg.Code)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.VerifyPhoneCodeResponse{
		User: userToProto(user),
	}), nil
}
