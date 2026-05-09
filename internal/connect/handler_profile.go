package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	"github.com/elloloop/identity/internal/service"
)

// ─── Self-Service Profile RPCs ──────────────────────────────────────────────

// UpdateProfile updates the authenticated user's profile (name, avatar).
func (h *IdentityHandler) UpdateProfile(
	ctx context.Context,
	req *connect.Request[identitypb.UpdateProfileRequest],
) (*connect.Response[identitypb.UpdateProfileResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	user, err := h.profile.UpdateProfile(ctx, userID, req.Msg.Name, req.Msg.AvatarUrl)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.UpdateProfileResponse{
		User: userToProto(user),
	}
	return connect.NewResponse(resp), nil
}

// ─── Password Management RPCs ───────────────────────────────────────────────

// ChangePassword changes the authenticated user's password after verifying
// the current password. The service layer also invalidates all refresh tokens.
func (h *IdentityHandler) ChangePassword(
	ctx context.Context,
	req *connect.Request[identitypb.ChangePasswordRequest],
) (*connect.Response[identitypb.ChangePasswordResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	err := h.profile.ChangePassword(ctx, userID, req.Msg.CurrentPassword, req.Msg.NewPassword)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.ChangePasswordResponse{}), nil
}

// RequestPasswordReset sends a password reset link to the user's recovery email.
// Always returns success to prevent email enumeration.
func (h *IdentityHandler) RequestPasswordReset(
	ctx context.Context,
	req *connect.Request[identitypb.RequestPasswordResetRequest],
) (*connect.Response[identitypb.RequestPasswordResetResponse], error) {
	// RequestPasswordReset is intentionally enumeration-safe: even if
	// the service layer reports an error (unknown email, transport
	// failure, etc.), we always return success so the response cannot
	// be used to confirm whether an account exists.
	_ = h.auth.RequestPasswordReset(ctx, req.Msg.Email)
	return connect.NewResponse(&identitypb.RequestPasswordResetResponse{}), nil
}

// ─── Passkey Management RPCs (authenticated) ────────────────────────────────
//
// Passkey registration/deletion are self-service operations. The existing
// service layer has these on ProfileService (ListMyPasskeys, DeletePasskey)
// while registration ceremony methods (BeginPasskeyRegistration,
// CompletePasskeyRegistration) live on AuthService.

// BeginPasskeyRegistration generates PublicKeyCredentialCreationOptions for
// navigator.credentials.create().
func (h *IdentityHandler) BeginPasskeyRegistration(
	ctx context.Context,
	req *connect.Request[identitypb.BeginPasskeyRegistrationRequest],
) (*connect.Response[identitypb.BeginPasskeyRegistrationResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	optionsJSON, challengeID, err := h.auth.BeginPasskeyRegistration(
		ctx, userID, req.Msg.DeviceName,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.BeginPasskeyRegistrationResponse{
		OptionsJson: optionsJSON,
		ChallengeId: challengeID,
	}
	return connect.NewResponse(resp), nil
}

// CompletePasskeyRegistration verifies the attestation and stores the new
// passkey credential.
func (h *IdentityHandler) CompletePasskeyRegistration(
	ctx context.Context,
	req *connect.Request[identitypb.CompletePasskeyRegistrationRequest],
) (*connect.Response[identitypb.CompletePasskeyRegistrationResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	credential, err := h.auth.CompletePasskeyRegistration(
		ctx, userID, req.Msg.ChallengeId, req.Msg.CredentialJson, req.Msg.DeviceName,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.CompletePasskeyRegistrationResponse{
		Credential: passkeyToProto(credential),
	}
	return connect.NewResponse(resp), nil
}

// ListPasskeys lists the authenticated user's registered passkey credentials.
// Delegates to ProfileService.ListMyPasskeys.
func (h *IdentityHandler) ListPasskeys(
	ctx context.Context,
	req *connect.Request[identitypb.ListPasskeysRequest],
) (*connect.Response[identitypb.ListPasskeysResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	credentials, err := h.profile.ListMyPasskeys(ctx, userID)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.ListPasskeysResponse{
		Credentials: passkeysToProto(credentials),
	}
	return connect.NewResponse(resp), nil
}

// DeletePasskey deletes a registered passkey credential.
// Delegates to ProfileService.DeletePasskey.
func (h *IdentityHandler) DeletePasskey(
	ctx context.Context,
	req *connect.Request[identitypb.DeletePasskeyRequest],
) (*connect.Response[identitypb.DeletePasskeyResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	err := h.profile.DeletePasskey(ctx, userID, req.Msg.CredentialId)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.DeletePasskeyResponse{}), nil
}

// ─── Session Management RPCs ────────────────────────────────────────────────
//
// Session listing and revocation are self-service operations on ProfileService.

// ListMySessions lists the authenticated user's active sessions.
func (h *IdentityHandler) ListMySessions(
	ctx context.Context,
	req *connect.Request[identitypb.ListMySessionsRequest],
) (*connect.Response[identitypb.ListMySessionsResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	sessions, err := h.profile.ListMySessions(ctx, userID)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.ListMySessionsResponse{
		Sessions: sessionsToProto(sessions),
	}
	return connect.NewResponse(resp), nil
}

// RevokeSession revokes a single session by its ID.
func (h *IdentityHandler) RevokeSession(
	ctx context.Context,
	req *connect.Request[identitypb.RevokeSessionRequest],
) (*connect.Response[identitypb.RevokeSessionResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	err := h.profile.RevokeSession(ctx, userID, req.Msg.SessionId)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.RevokeSessionResponse{}), nil
}

// RevokeAllSessions revokes all sessions for the authenticated user.
// Requires password confirmation.
func (h *IdentityHandler) RevokeAllSessions(
	ctx context.Context,
	req *connect.Request[identitypb.RevokeAllSessionsRequest],
) (*connect.Response[identitypb.RevokeAllSessionsResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	revokedCount, err := h.profile.RevokeAllSessions(ctx, userID, req.Msg.Password)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.RevokeAllSessionsResponse{
		RevokedCount: intToProtoInt32(revokedCount),
	}
	return connect.NewResponse(resp), nil
}

// SignOutEverywhere revokes all sessions for the authenticated user.
// This is a distinct RPC from RevokeAllSessions per the proto definition
// but delegates to the same service method.
func (h *IdentityHandler) SignOutEverywhere(
	ctx context.Context,
	req *connect.Request[identitypb.SignOutEverywhereRequest],
) (*connect.Response[identitypb.SignOutEverywhereResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	revokedCount, err := h.profile.RevokeAllSessions(ctx, userID, req.Msg.Password)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.SignOutEverywhereResponse{
		RevokedCount: intToProtoInt32(revokedCount),
	}
	return connect.NewResponse(resp), nil
}

// ConfirmPasswordReset consumes a password-reset token and sets a new password.
func (h *IdentityHandler) ConfirmPasswordReset(
	ctx context.Context,
	req *connect.Request[identitypb.ConfirmPasswordResetRequest],
) (*connect.Response[identitypb.ConfirmPasswordResetResponse], error) {
	if err := h.auth.ConfirmPasswordReset(ctx, req.Msg.Token, req.Msg.NewPassword); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.ConfirmPasswordResetResponse{}), nil
}

// SendEmailVerification sends a verification email to the authenticated user.
func (h *IdentityHandler) SendEmailVerification(
	ctx context.Context,
	req *connect.Request[identitypb.SendEmailVerificationRequest],
) (*connect.Response[identitypb.SendEmailVerificationResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	if err := h.auth.SendEmailVerification(ctx, userID); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.SendEmailVerificationResponse{}), nil
}

// VerifyEmail consumes an email-verification token and marks the email verified.
func (h *IdentityHandler) VerifyEmail(
	ctx context.Context,
	req *connect.Request[identitypb.VerifyEmailRequest],
) (*connect.Response[identitypb.VerifyEmailResponse], error) {
	user, err := h.auth.VerifyEmail(ctx, req.Msg.Token)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.VerifyEmailResponse{
		User: userToProto(user),
	}), nil
}

// ─── Email Change RPCs ──────────────────────────────────────────────────

// RequestEmailChange begins the primary-email rotation flow. The caller
// must already be authenticated (auth middleware enforces this) AND
// supply their current password as a re-authentication step. The new
// address is sent a verification link; the old address is sent a
// security notice. The change takes effect only after ConfirmEmailChange.
func (h *IdentityHandler) RequestEmailChange(
	ctx context.Context,
	req *connect.Request[identitypb.RequestEmailChangeRequest],
) (*connect.Response[identitypb.RequestEmailChangeResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	if err := h.auth.RequestEmailChange(ctx, userID, req.Msg.NewEmail, req.Msg.CurrentPassword); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.RequestEmailChangeResponse{}), nil
}

// ConfirmEmailChange consumes a pending email-change token (sent to the
// new address). This RPC is exempt from the auth middleware so a user
// clicking the link from their inbox doesn't need to be currently
// signed in. On success, the user's email is updated and ALL of their
// refresh tokens are revoked, forcing re-authentication everywhere.
func (h *IdentityHandler) ConfirmEmailChange(
	ctx context.Context,
	req *connect.Request[identitypb.ConfirmEmailChangeRequest],
) (*connect.Response[identitypb.ConfirmEmailChangeResponse], error) {
	user, err := h.auth.ConfirmEmailChange(ctx, req.Msg.Token)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.ConfirmEmailChangeResponse{
		User: userToProto(user),
	}), nil
}
