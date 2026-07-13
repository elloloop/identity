package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
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

// ─── Self-Service Account Deletion RPCs ─────────────────────────────────────

// DeleteMyAccount schedules grace-period deletion of the authenticated caller's
// OWN account (GDPR Art 17). The caller is derived from the auth header; there
// is no user_id in the request.
func (h *IdentityHandler) DeleteMyAccount(
	ctx context.Context,
	req *connect.Request[identitypb.DeleteMyAccountRequest],
) (*connect.Response[identitypb.DeleteMyAccountResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	scheduledAt, err := h.profile.DeleteMyAccount(ctx, userID, req.Msg.Reason)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.DeleteMyAccountResponse{
		DeletionScheduledAtMs: scheduledAt,
	}), nil
}

// CancelAccountDeletion calls off a pending self-service deletion for the
// authenticated caller, restoring the account. Idempotent when nothing is
// pending.
func (h *IdentityHandler) CancelAccountDeletion(
	ctx context.Context,
	req *connect.Request[identitypb.CancelAccountDeletionRequest],
) (*connect.Response[identitypb.CancelAccountDeletionResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	status, err := h.profile.CancelAccountDeletion(ctx, userID)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.CancelAccountDeletionResponse{
		Status: userStatusToProto(status),
	}), nil
}

// ─── Self-Service Data Export RPC ───────────────────────────────────────────

// ExportMyData returns a structured, machine-readable copy of the personal
// data the identity service holds about the authenticated caller (GDPR Art 15
// access + Art 20 portability). The caller is derived from the auth header;
// there is no user_id in the request. The payload carries no secret material.
func (h *IdentityHandler) ExportMyData(
	ctx context.Context,
	req *connect.Request[identitypb.ExportMyDataRequest],
) (*connect.Response[identitypb.ExportMyDataResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	export, err := h.profile.ExportMyData(ctx, userID)
	if err != nil {
		return nil, toConnectError(err)
	}

	linked := make([]*identitypb.LinkedIdentity, 0, len(export.LinkedIdentities))
	for _, l := range export.LinkedIdentities {
		linked = append(linked, linkedIdentityToProto(l))
	}

	resp := &identitypb.ExportMyDataResponse{
		FormatVersion:    intToProtoInt32(export.FormatVersion),
		ExportedAtMs:     export.ExportedAtMs,
		User:             userToProto(export.User),
		Sessions:         sessionsToProto(export.Sessions),
		Passkeys:         passkeysToProto(export.Passkeys),
		LinkedIdentities: linked,
		TotpEnabled:      export.TotpEnabled,
		AuditEvents:      auditEventsToProto(export.AuditEvents),
	}
	return connect.NewResponse(resp), nil
}

// ─── Password Management RPCs ───────────────────────────────────────────────

// ChangePassword changes the authenticated user's password after verifying
// the current password. The service layer also revokes all of the user's
// sessions (deletes their refresh tokens), forcing re-authentication
// everywhere — including the caller, who must sign in again with the new
// password.
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

// RequestPasswordReset sends a password reset link to the user's primary
// verified email (the address on file for the account).
// Always returns success to prevent email enumeration.
func (h *IdentityHandler) RequestPasswordReset(
	ctx context.Context,
	req *connect.Request[identitypb.RequestPasswordResetRequest],
) (*connect.Response[identitypb.RequestPasswordResetResponse], error) {
	// The CAPTCHA gate runs before the enumeration-safe stub. A failed or
	// missing CAPTCHA is not an account-existence oracle — it is the same
	// rejection for any email — so returning the error here is safe.
	if err := h.checkCaptcha(ctx, h.captchaEnforcePasswordReset(), req.Msg.CaptchaToken, clientIP(req.Header())); err != nil {
		return nil, toConnectError(err)
	}
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

// ─── Linked-Identity RPCs (self-service connected accounts) ──────────────────

// linkedIdentityToProto converts a persisted OAuth identity link to its
// wire representation. The provider subject and email are non-secret
// account-management metadata the user is entitled to see.
func linkedIdentityToProto(oi *service.OAuthIdentity) *identitypb.LinkedIdentity {
	return &identitypb.LinkedIdentity{
		Provider:        oi.Provider,
		ProviderUserId:  oi.ProviderUserID,
		EmailAtLinkTime: oi.EmailAtLinkTime,
		LinkedAt:        oi.CreatedAt,
	}
}

// ListLinkedIdentities returns the authenticated user's connected providers.
func (h *IdentityHandler) ListLinkedIdentities(
	ctx context.Context,
	req *connect.Request[identitypb.ListLinkedIdentitiesRequest],
) (*connect.Response[identitypb.ListLinkedIdentitiesResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	links, err := h.profile.ListLinkedIdentities(ctx, userID)
	if err != nil {
		return nil, toConnectError(err)
	}

	out := make([]*identitypb.LinkedIdentity, 0, len(links))
	for _, l := range links {
		out = append(out, linkedIdentityToProto(l))
	}
	return connect.NewResponse(&identitypb.ListLinkedIdentitiesResponse{Identities: out}), nil
}

// LinkIdentity attaches a freshly-verified OAuth identity to the caller. The
// server performs the provider code exchange itself; the client is never
// trusted to assert the identity.
func (h *IdentityHandler) LinkIdentity(
	ctx context.Context,
	req *connect.Request[identitypb.LinkIdentityRequest],
) (*connect.Response[identitypb.LinkIdentityResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	oi, err := h.auth.LinkIdentity(
		ctx,
		userID,
		req.Msg.Code,
		req.Msg.Provider,
		req.Msg.RedirectUri,
		req.Msg.CodeVerifier,
		req.Msg.State,
		req.Msg.StateToken,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.LinkIdentityResponse{
		Identity: linkedIdentityToProto(oi),
	}), nil
}

// UnlinkIdentity disconnects a provider identity from the caller, refusing to
// remove the user's last remaining sign-in credential.
func (h *IdentityHandler) UnlinkIdentity(
	ctx context.Context,
	req *connect.Request[identitypb.UnlinkIdentityRequest],
) (*connect.Response[identitypb.UnlinkIdentityResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	err := h.profile.UnlinkIdentity(ctx, userID, req.Msg.Provider, req.Msg.ProviderUserId)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.UnlinkIdentityResponse{}), nil
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
