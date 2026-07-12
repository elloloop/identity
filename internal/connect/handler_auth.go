package connect

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// ─── Authentication RPCs ────────────────────────────────────────────────────

// BeginOAuthLogin returns the provider authorization URL plus the
// server-minted state artifacts needed to complete the callback safely.
func (h *IdentityHandler) BeginOAuthLogin(
	ctx context.Context,
	req *connect.Request[identitypb.BeginOAuthLoginRequest],
) (*connect.Response[identitypb.BeginOAuthLoginResponse], error) {
	result, err := h.auth.BeginOAuthLogin(
		ctx,
		req.Msg.Provider,
		req.Msg.RedirectUri,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.BeginOAuthLoginResponse{
		AuthorizationUrl: result.AuthorizationURL,
		State:            result.State,
		StateToken:       result.StateToken,
		CodeVerifier:     result.CodeVerifier,
		ExpiresIn:        result.ExpiresIn,
	}
	return connect.NewResponse(resp), nil
}

// OAuthLogin exchanges an OAuth authorization code for backend-issued tokens.
//
// The service layer is responsible for the actual provider-side code
// exchange and identity verification. The handler simply forwards the
// authorization code, the user-selected provider, and the redirect URI.
func (h *IdentityHandler) OAuthLogin(
	ctx context.Context,
	req *connect.Request[identitypb.OAuthLoginRequest],
) (*connect.Response[identitypb.OAuthLoginResponse], error) {
	ipAddr := clientIP(req.Header())
	userAgent := clientUserAgent(req.Header())

	result, err := h.auth.OAuthLogin(ctx, service.OAuthLoginParams{
		Code:             req.Msg.Code,
		Provider:         req.Msg.Provider,
		RedirectURI:      req.Msg.RedirectUri,
		CodeVerifier:     req.Msg.CodeVerifier,
		State:            req.Msg.State,
		StateToken:       req.Msg.StateToken,
		AppleUserPayload: req.Msg.AppleUserPayload,
		IPAddr:           ipAddr,
		UserAgent:        userAgent,
	})
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.OAuthLoginResponse{
		User:         userToProto(result.User),
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}
	return connect.NewResponse(resp), nil
}

// NativeOAuthLogin verifies a native mobile-SDK ID token (Google idToken /
// Apple identityToken) server-side and issues backend tokens scoped to the
// product's project — no browser, no PKCE. The service layer performs the
// token verification, product→project resolution, account linking, and token
// issuance; the handler forwards the request fields and the caller's IP / UA.
func (h *IdentityHandler) NativeOAuthLogin(
	ctx context.Context,
	req *connect.Request[identitypb.NativeOAuthLoginRequest],
) (*connect.Response[identitypb.NativeOAuthLoginResponse], error) {
	ipAddr := clientIP(req.Header())
	userAgent := clientUserAgent(req.Header())

	result, err := h.auth.NativeOAuthLogin(ctx, service.NativeOAuthLoginParams{
		Provider:  req.Msg.Provider,
		IDToken:   req.Msg.IdToken,
		Product:   req.Msg.Product,
		Nonce:     req.Msg.Nonce,
		IPAddr:    ipAddr,
		UserAgent: userAgent,
	})
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.NativeOAuthLoginResponse{
		User:         userToProto(result.User),
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}
	return connect.NewResponse(resp), nil
}

// RedeemOAuthCode exchanges the single-use one-time code from the
// hosted OAuth callback redirect for a backend-issued token pair. The
// code is consumed atomically; a replay or expired code surfaces as
// CodeUnauthenticated.
func (h *IdentityHandler) RedeemOAuthCode(
	ctx context.Context,
	req *connect.Request[identitypb.RedeemOAuthCodeRequest],
) (*connect.Response[identitypb.RedeemOAuthCodeResponse], error) {
	ipAddr := clientIP(req.Header())
	userAgent := clientUserAgent(req.Header())

	result, err := h.auth.RedeemOAuthCode(ctx, req.Msg.Code, ipAddr, userAgent)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.RedeemOAuthCodeResponse{
		User:         userToProto(result.User),
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}
	return connect.NewResponse(resp), nil
}

// PasswordSignup creates a new user account with email and password.
func (h *IdentityHandler) PasswordSignup(
	ctx context.Context,
	req *connect.Request[identitypb.PasswordSignupRequest],
) (*connect.Response[identitypb.PasswordSignupResponse], error) {
	if h.cfg != nil && !h.cfg.PasswordSignupEnabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, service.ErrSignupDisabled)
	}
	if err := h.checkCaptcha(ctx, h.captchaEnforcePasswordSignup(), req.Msg.CaptchaToken, clientIP(req.Header())); err != nil {
		return nil, toConnectError(err)
	}
	result, err := h.auth.PasswordSignup(
		ctx,
		req.Msg.Email,
		req.Msg.Password,
		"", // name — not in proto; service derives from email
		req.Msg.RecoveryEmail,
		req.Msg.DateOfBirthMs,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.PasswordSignupResponse{
		User:         userToProto(result.User),
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}
	return connect.NewResponse(resp), nil
}

// PasswordLogin authenticates a user with email and password. If TOTP is
// enabled, returns totp_required=true and a login_challenge_id for the
// client to pass to VerifyTotp.
func (h *IdentityHandler) PasswordLogin(
	ctx context.Context,
	req *connect.Request[identitypb.PasswordLoginRequest],
) (*connect.Response[identitypb.PasswordLoginResponse], error) {
	ipAddr := clientIP(req.Header())
	userAgent := clientUserAgent(req.Header())

	if err := h.checkCaptcha(ctx, h.captchaEnforcePasswordLogin(), req.Msg.CaptchaToken, ipAddr); err != nil {
		return nil, toConnectError(err)
	}

	result, err := h.auth.PasswordLogin(
		ctx,
		req.Msg.Email,
		req.Msg.Password,
		ipAddr,
		userAgent,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.PasswordLoginResponse{
		User:             userToProto(result.User),
		AccessToken:      result.AccessToken,
		RefreshToken:     result.RefreshToken,
		ExpiresIn:        result.ExpiresIn,
		TotpRequired:     result.TotpRequired,
		LoginChallengeId: result.LoginChallengeID,
	}
	return connect.NewResponse(resp), nil
}

// ─── Passwordless Email Login RPCs ──────────────────────────────────────────

// RequestEmailLoginCode emails a 6-digit OTP. The response is identical
// whether or not the email has an account (anti-enumeration); the service
// always returns nil for a well-formed request.
func (h *IdentityHandler) RequestEmailLoginCode(
	ctx context.Context,
	req *connect.Request[identitypb.RequestEmailLoginCodeRequest],
) (*connect.Response[identitypb.RequestEmailLoginCodeResponse], error) {
	if err := h.checkCaptcha(ctx, h.captchaEnforceEmailLoginCode(), req.Msg.CaptchaToken, clientIP(req.Header())); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.auth.RequestEmailLoginCode(ctx, req.Msg.Email); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.RequestEmailLoginCodeResponse{}), nil
}

// VerifyEmailLoginCode validates the OTP, resolves-or-creates the user by
// email, and issues a token pair.
func (h *IdentityHandler) VerifyEmailLoginCode(
	ctx context.Context,
	req *connect.Request[identitypb.VerifyEmailLoginCodeRequest],
) (*connect.Response[identitypb.VerifyEmailLoginCodeResponse], error) {
	ipAddr := clientIP(req.Header())
	userAgent := clientUserAgent(req.Header())

	result, err := h.auth.VerifyEmailLoginCode(ctx, req.Msg.Email, req.Msg.Code, ipAddr, userAgent)
	if err != nil {
		return nil, toConnectError(err)
	}
	resp := &identitypb.VerifyEmailLoginCodeResponse{
		User:         userToProto(result.User),
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}
	return connect.NewResponse(resp), nil
}

// RequestMagicLink emails a single-use sign-in link. A disallowed
// return_to is rejected with InvalidArgument; everything else returns the
// same anti-enumeration success.
func (h *IdentityHandler) RequestMagicLink(
	ctx context.Context,
	req *connect.Request[identitypb.RequestMagicLinkRequest],
) (*connect.Response[identitypb.RequestMagicLinkResponse], error) {
	if err := h.checkCaptcha(ctx, h.captchaEnforceMagicLink(), req.Msg.CaptchaToken, clientIP(req.Header())); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.auth.RequestMagicLink(ctx, req.Msg.Email, req.Msg.ReturnTo); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.RequestMagicLinkResponse{}), nil
}

// RedeemMagicLink consumes the single-use token, resolves-or-creates the
// user by the bound email, and issues a token pair plus the validated
// return_to.
func (h *IdentityHandler) RedeemMagicLink(
	ctx context.Context,
	req *connect.Request[identitypb.RedeemMagicLinkRequest],
) (*connect.Response[identitypb.RedeemMagicLinkResponse], error) {
	ipAddr := clientIP(req.Header())
	userAgent := clientUserAgent(req.Header())

	result, err := h.auth.RedeemMagicLink(ctx, req.Msg.Token, ipAddr, userAgent)
	if err != nil {
		return nil, toConnectError(err)
	}
	resp := &identitypb.RedeemMagicLinkResponse{
		User:         userToProto(result.User),
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
		ReturnTo:     result.ReturnTo,
	}
	return connect.NewResponse(resp), nil
}

// ─── Passkey Authentication RPCs ────────────────────────────────────────────

// BeginPasskeyLogin generates PublicKeyCredentialRequestOptions for
// navigator.credentials.get().
func (h *IdentityHandler) BeginPasskeyLogin(
	ctx context.Context,
	req *connect.Request[identitypb.BeginPasskeyLoginRequest],
) (*connect.Response[identitypb.BeginPasskeyLoginResponse], error) {
	optionsJSON, challengeID, err := h.auth.BeginPasskeyLogin(ctx, req.Msg.Email)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.BeginPasskeyLoginResponse{
		OptionsJson: optionsJSON,
		ChallengeId: challengeID,
	}
	return connect.NewResponse(resp), nil
}

// CompletePasskeyLogin verifies the passkey assertion and issues tokens.
func (h *IdentityHandler) CompletePasskeyLogin(
	ctx context.Context,
	req *connect.Request[identitypb.CompletePasskeyLoginRequest],
) (*connect.Response[identitypb.CompletePasskeyLoginResponse], error) {
	ipAddr := clientIP(req.Header())
	userAgent := clientUserAgent(req.Header())

	result, err := h.auth.CompletePasskeyLogin(
		ctx,
		req.Msg.ChallengeId,
		req.Msg.CredentialJson,
		ipAddr,
		userAgent,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.CompletePasskeyLoginResponse{
		User:         userToProto(result.User),
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}
	return connect.NewResponse(resp), nil
}

// ─── Passkey-first Signup RPCs (unauthenticated) ─────────────────────────────

// BeginPasskeySignup generates PublicKeyCredentialCreationOptions for creating
// a brand-new account from a passkey. Unauthenticated: no session required.
func (h *IdentityHandler) BeginPasskeySignup(
	ctx context.Context,
	req *connect.Request[identitypb.BeginPasskeySignupRequest],
) (*connect.Response[identitypb.BeginPasskeySignupResponse], error) {
	if err := h.checkCaptcha(ctx, h.captchaEnforcePasskeySignup(), req.Msg.CaptchaToken, clientIP(req.Header())); err != nil {
		return nil, toConnectError(err)
	}
	optionsJSON, challengeID, err := h.auth.BeginPasskeySignup(ctx, req.Msg.Email, req.Msg.DeviceName)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.BeginPasskeySignupResponse{
		OptionsJson: optionsJSON,
		ChallengeId: challengeID,
	}
	return connect.NewResponse(resp), nil
}

// CompletePasskeySignup verifies the attestation, creates the account (or
// returns an enumeration-safe decoy when the email already exists) and issues
// tokens. Unauthenticated: no session required.
func (h *IdentityHandler) CompletePasskeySignup(
	ctx context.Context,
	req *connect.Request[identitypb.CompletePasskeySignupRequest],
) (*connect.Response[identitypb.CompletePasskeySignupResponse], error) {
	ipAddr := clientIP(req.Header())
	userAgent := clientUserAgent(req.Header())

	result, err := h.auth.CompletePasskeySignup(
		ctx,
		req.Msg.ChallengeId,
		req.Msg.CredentialJson,
		req.Msg.Email,
		req.Msg.OtpCode,
		req.Msg.DeviceName,
		ipAddr,
		userAgent,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.CompletePasskeySignupResponse{
		User:         userToProto(result.User),
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}
	return connect.NewResponse(resp), nil
}

// ─── QR Login RPCs ──────────────────────────────────────────────────────────

// InitiateQrLogin creates a new QR login session for a new device.
func (h *IdentityHandler) InitiateQrLogin(
	ctx context.Context,
	req *connect.Request[identitypb.InitiateQrLoginRequest],
) (*connect.Response[identitypb.InitiateQrLoginResponse], error) {
	ipAddr := clientIP(req.Header())

	result, err := h.auth.InitiateQrLogin(
		ctx,
		req.Msg.DeviceInfo,
		req.Msg.UserAgent,
		ipAddr,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.InitiateQrLoginResponse{
		SessionId:  result.SessionID,
		QrUrl:      result.QRURL,
		ExpiresIn:  result.ExpiresIn,
		PollSecret: result.PollSecret,
	}
	return connect.NewResponse(resp), nil
}

// GetQrLoginSession retrieves the details of a QR login session for display
// on the authenticated device.
func (h *IdentityHandler) GetQrLoginSession(
	ctx context.Context,
	req *connect.Request[identitypb.GetQrLoginSessionRequest],
) (*connect.Response[identitypb.GetQrLoginSessionResponse], error) {
	session, err := h.auth.GetQrLoginSession(ctx, req.Msg.SessionId)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.GetQrLoginSessionResponse{
		Status:        qrLoginStatusToProto(session.Status),
		NewDeviceInfo: session.NewDeviceInfo,
		NewDeviceIp:   session.NewDeviceIP,
	}
	if !session.ExpiresAt.IsZero() {
		resp.ExpiresAt = timestamppb.New(session.ExpiresAt)
	}
	return connect.NewResponse(resp), nil
}

// ApproveQrLogin approves or rejects a QR login session from the authenticated device.
func (h *IdentityHandler) ApproveQrLogin(
	ctx context.Context,
	req *connect.Request[identitypb.ApproveQrLoginRequest],
) (*connect.Response[identitypb.ApproveQrLoginResponse], error) {
	userID := authenticatedUserID(req.Header())
	userAgent := clientUserAgent(req.Header())

	status, err := h.auth.ApproveQrLogin(ctx, req.Msg.SessionId, req.Msg.Approve, userID, userAgent)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.ApproveQrLoginResponse{
		Status: qrLoginStatusToProto(status),
	}
	return connect.NewResponse(resp), nil
}

// PollQrLogin polls for QR login session completion from the new device.
func (h *IdentityHandler) PollQrLogin(
	ctx context.Context,
	req *connect.Request[identitypb.PollQrLoginRequest],
) (*connect.Response[identitypb.PollQrLoginResponse], error) {
	ipAddr := clientIP(req.Header())
	userAgent := clientUserAgent(req.Header())

	result, err := h.auth.PollQrLogin(
		ctx, req.Msg.SessionId, req.Msg.PollSecret, ipAddr, userAgent,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.PollQrLoginResponse{
		Status: qrLoginStatusToProto(result.Status),
	}
	// Only populate tokens when status is approved.
	if result.User != nil {
		resp.User = userToProto(result.User)
		resp.AccessToken = result.AccessToken
		resp.RefreshToken = result.RefreshToken
		resp.ExpiresIn = result.ExpiresIn
	}
	return connect.NewResponse(resp), nil
}

// ─── Session / Token RPCs ───────────────────────────────────────────────────

// GetCurrentUser returns the currently authenticated user's profile.
func (h *IdentityHandler) GetCurrentUser(
	ctx context.Context,
	req *connect.Request[identitypb.GetCurrentUserRequest],
) (*connect.Response[identitypb.GetCurrentUserResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	user, err := h.auth.GetCurrentUser(ctx, userID)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.GetCurrentUserResponse{
		User: userToProto(user),
	}
	return connect.NewResponse(resp), nil
}

// RefreshToken rotates the refresh token and issues a new access token.
func (h *IdentityHandler) RefreshToken(
	ctx context.Context,
	req *connect.Request[identitypb.RefreshTokenRequest],
) (*connect.Response[identitypb.RefreshTokenResponse], error) {
	ipAddr := clientIP(req.Header())
	userAgent := clientUserAgent(req.Header())

	user, accessToken, refreshToken, err := h.auth.RefreshToken(
		ctx, req.Msg.RefreshToken, ipAddr, userAgent,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.RefreshTokenResponse{
		User:         userToProto(user),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	return connect.NewResponse(resp), nil
}

// Logout invalidates the given refresh token.
func (h *IdentityHandler) Logout(
	ctx context.Context,
	req *connect.Request[identitypb.LogoutRequest],
) (*connect.Response[identitypb.LogoutResponse], error) {
	err := h.auth.Logout(ctx, req.Msg.RefreshToken)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.LogoutResponse{}), nil
}

// AcceptInvitation completes account setup for an invited user.
func (h *IdentityHandler) AcceptInvitation(
	ctx context.Context,
	req *connect.Request[identitypb.AcceptInvitationRequest],
) (*connect.Response[identitypb.AcceptInvitationResponse], error) {
	ipAddr := clientIP(req.Header())
	userAgent := clientUserAgent(req.Header())

	result, err := h.auth.AcceptInvitation(
		ctx,
		req.Msg.InvitationToken,
		req.Msg.Password,
		req.Msg.Name,
		ipAddr,
		userAgent,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.AcceptInvitationResponse{
		User:         userToProto(result.User),
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}
	return connect.NewResponse(resp), nil
}

// ensure IdentityHandler is not used incorrectly — keep this type assertion
// compile-time-checked once the generated interface exists.
// var _ identityconnect.IdentityServiceHandler = (*IdentityHandler)(nil)
