package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	"github.com/elloloop/identity/internal/service"
)

// ─── TOTP (2FA) RPCs ────────────────────────────────────────────────────────

// BeginTotpSetup generates a new TOTP secret and recovery codes for the
// authenticated user. The secret is NOT yet active — the user must call
// VerifyTotpSetup with a valid code to confirm enrollment.
func (h *IdentityHandler) BeginTotpSetup(
	ctx context.Context,
	req *connect.Request[identitypb.BeginTotpSetupRequest],
) (*connect.Response[identitypb.BeginTotpSetupResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	secret, qrCodeURI, recoveryCodes, err := h.auth.BeginTotpSetup(ctx, userID)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.BeginTotpSetupResponse{
		Secret:        secret,
		QrCodeUri:     qrCodeURI,
		RecoveryCodes: recoveryCodes,
	}
	return connect.NewResponse(resp), nil
}

// VerifyTotpSetup confirms TOTP enrollment by verifying a code generated
// from the secret provided by BeginTotpSetup.
func (h *IdentityHandler) VerifyTotpSetup(
	ctx context.Context,
	req *connect.Request[identitypb.VerifyTotpSetupRequest],
) (*connect.Response[identitypb.VerifyTotpSetupResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	verified, err := h.auth.VerifyTotpSetup(ctx, userID, req.Msg.Code)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.VerifyTotpSetupResponse{
		Verified: verified,
	}
	return connect.NewResponse(resp), nil
}

// VerifyTotp completes a login challenge that requires TOTP. Accepts either
// a 6-digit TOTP code or a recovery code.
func (h *IdentityHandler) VerifyTotp(
	ctx context.Context,
	req *connect.Request[identitypb.VerifyTotpRequest],
) (*connect.Response[identitypb.VerifyTotpResponse], error) {
	ipAddr := clientIP(req.Header())
	userAgent := clientUserAgent(req.Header())

	result, err := h.auth.VerifyTotp(
		ctx,
		req.Msg.LoginChallengeId,
		req.Msg.Code,
		ipAddr,
		userAgent,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.VerifyTotpResponse{
		User:         userToProto(result.User),
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}
	return connect.NewResponse(resp), nil
}

// DisableTotp removes TOTP enrollment for the authenticated user. Requires
// password confirmation for security.
func (h *IdentityHandler) DisableTotp(
	ctx context.Context,
	req *connect.Request[identitypb.DisableTotpRequest],
) (*connect.Response[identitypb.DisableTotpResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	err := h.auth.DisableTotp(ctx, userID, req.Msg.Password)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.DisableTotpResponse{}), nil
}

// RegenerateRecoveryCodes generates a new set of recovery codes, invalidating
// any existing codes. Requires password confirmation.
func (h *IdentityHandler) RegenerateRecoveryCodes(
	ctx context.Context,
	req *connect.Request[identitypb.RegenerateRecoveryCodesRequest],
) (*connect.Response[identitypb.RegenerateRecoveryCodesResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	codes, err := h.auth.RegenerateRecoveryCodes(ctx, userID, req.Msg.Password)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.RegenerateRecoveryCodesResponse{
		RecoveryCodes: codes,
	}
	return connect.NewResponse(resp), nil
}
