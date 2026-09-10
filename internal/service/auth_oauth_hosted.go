package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/oauth"
)

// oauthOneTimeCodeTTL bounds how long the hosted-callback one-time code
// is valid for. The SPA redeems it on the very next page load after the
// 302 to return_to, so a tight window suffices and limits the replay
// surface. Not config-knobbed: 60s is short enough to be safe and long
// enough for a slow client, and a deployer-tunable here would invite
// someone to widen it into a security hole.
const oauthOneTimeCodeTTL = 60 * time.Second

// Handover code methods name the flow that minted a code. Redeem enforces
// that flow's login policy and records that flow's audit event, so a code
// from the hosted magic-link page completes as a passwordless login and a
// code from the hosted OAuth callback as an OAuth login — never the other
// way round.
const (
	HandoverMethodOAuth     = "oauth"
	HandoverMethodMagicLink = "magic_link"
)

// HostedOAuthBeginResult is the output of BeginHostedOAuth: the provider
// authorization URL the browser should be 302-redirected to. The state
// + PKCE verifier + return_to are all sealed inside the signed hosted
// state token carried in the URL's `state` parameter, so the callback
// needs nothing else from the browser.
type HostedOAuthBeginResult struct {
	AuthorizationURL string
}

// BeginHostedOAuth mints state + PKCE for the hosted flow and returns
// the provider authorization URL. redirectURI is the identity-owned
// callback (e.g. https://identity.example.com/oauth/callback/google);
// returnTo is the already-allowlist-validated app URL the callback will
// redirect back to. It reuses the same provider Authorizer the headless
// BeginOAuthLogin uses — there is no forked authorization path.
func (s *AuthService) BeginHostedOAuth(
	ctx context.Context,
	provider, redirectURI, returnTo, csrfToken, projectKey string,
) (*HostedOAuthBeginResult, error) {
	if !s.oauthResolver.available(ctx) {
		return nil, ErrOAuthDisabled
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return nil, fmt.Errorf("%w: provider is required", ErrInvalidArgument)
	}
	if strings.TrimSpace(redirectURI) == "" {
		return nil, fmt.Errorf("%w: redirect uri is required", ErrInvalidArgument)
	}
	if strings.TrimSpace(returnTo) == "" {
		return nil, fmt.Errorf("%w: return_to is required", ErrInvalidArgument)
	}
	if strings.TrimSpace(csrfToken) == "" {
		return nil, fmt.Errorf("%w: csrf_token is required", ErrInvalidArgument)
	}

	exchanger, ok := s.oauthResolver.exchangerFor(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("%w: unknown oauth provider %q", ErrInvalidArgument, provider)
	}
	authorizer, ok := exchanger.(oauth.Authorizer)
	if !ok {
		return nil, fmt.Errorf("%w: oauth provider %q cannot start authorization", ErrInvalidArgument, provider)
	}

	state, err := oauth.GenerateState()
	if err != nil {
		return nil, fmt.Errorf("generating oauth state: %w", err)
	}
	codeVerifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("generating oauth code verifier: %w", err)
	}

	scope := ProjectScopeFromContext(ctx)
	if scope == nil {
		return nil, fmt.Errorf("%w: missing project scope", ErrUnauthenticated)
	}

	stateToken, err := oauth.IssueHostedStateToken(
		ctx,
		s.signer,
		provider,
		redirectURI,
		returnTo,
		state,
		codeVerifier,
		csrfToken,
		scope.ProjectID,
		oauthStateTokenExpiry,
		s.nowFunc().UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}

	// A hub-routed request additionally carries the plaintext project key
	// in front of the signed token, so the callback middleware can scope
	// the request before verification; the signed project_id claim is what
	// actually binds the flow to the project.
	stateToken = oauth.JoinProjectKeyState(projectKey, stateToken)

	// The signed hosted state token IS the OAuth `state` parameter, so
	// the single callback URL can recover provider + verifier + return_to
	// tamper-proof without any server-side per-request storage.
	authorizationURL, err := authorizer.AuthorizationURL(
		ctx,
		redirectURI,
		stateToken,
		oauth.CodeChallengeS256(codeVerifier),
	)
	if err != nil {
		_, mappedErr := s.mapOAuthError(err)
		return nil, mappedErr
	}

	return &HostedOAuthBeginResult{AuthorizationURL: authorizationURL}, nil
}

// HostedOAuthCallbackResult is the output of CompleteHostedOAuth: the
// validated return_to, the freshly-minted handover code, and RedirectURL —
// return_to with the code appended as ?code=, the exact URL the callback
// redirects the browser to.
type HostedOAuthCallbackResult struct {
	ReturnTo    string
	Code        string
	CSRFToken   string
	RedirectURL string
}

// CompleteHostedOAuth runs the hosted callback: it verifies the signed
// hosted state token (recovering provider + PKCE verifier + return_to),
// runs the same OAuthLogin exchange the headless flow uses, then mints a
// single-use one-time code bound to the authenticated user. The caller
// (the HTTP handler) 302-redirects to result.ReturnTo?code=result.Code.
//
// stateToken is the OAuth `state` value the provider echoed back;
// providerFromPath is the provider segment from the callback path, used
// only to cross-check the token's provider claim.
func (s *AuthService) CompleteHostedOAuth(
	ctx context.Context,
	providerFromPath, code, stateToken, appleUserPayload, ipAddr, userAgent string,
	csrfTokens []string,
) (*HostedOAuthCallbackResult, error) {
	_, stateToken = oauth.SplitProjectKeyState(stateToken)

	claims, err := oauth.VerifyHostedStateToken(stateToken, s.signer, s.nowFunc().UTC())
	if err != nil {
		s.logger.Info("hosted_oauth_state_validation_failed", zap.Error(err))
		return nil, fmt.Errorf("%w: invalid oauth state", ErrUnauthenticated)
	}
	matchedCSRFToken := 0
	for _, token := range csrfTokens {
		matchedCSRFToken |= subtle.ConstantTimeCompare([]byte(claims.CSRFToken), []byte(token))
	}
	if matchedCSRFToken != 1 {
		s.logger.Info("hosted_oauth_csrf_mismatch")
		return nil, fmt.Errorf("%w: csrf mismatch", ErrUnauthenticated)
	}
	if want := strings.ToLower(strings.TrimSpace(providerFromPath)); want != "" && claims.Provider != want {
		s.logger.Info("hosted_oauth_provider_mismatch",
			zap.String("path_provider", want), zap.String("token_provider", claims.Provider))
		return nil, fmt.Errorf("%w: provider mismatch", ErrUnauthenticated)
	}

	// The token's project_id claim must name the project the request
	// resolved to: a state minted for project A cannot complete a login in
	// project B, whatever prefix or host the callback arrived with.
	scope := ProjectScopeFromContext(ctx)
	if scope == nil || claims.ProjectID != scope.ProjectID {
		s.logger.Info("hosted_oauth_project_mismatch", zap.String("expected", claims.ProjectID))
		return nil, fmt.Errorf("%w: project mismatch", ErrUnauthenticated)
	}

	// Reuse the headless exchange end to end: same state-token-free path
	// (we already verified the hosted token), passing the recovered
	// verifier so PKCE completes. OAuthLogin upserts the user and mints
	// the identity token pair internally; we discard those tokens and
	// hand back a one-time code instead — the SPA re-mints via redeem.
	result, err := s.OAuthLogin(ctx, OAuthLoginParams{
		Code:             code,
		Provider:         claims.Provider,
		RedirectURI:      claims.RedirectURI,
		CodeVerifier:     claims.CodeVerifier,
		State:            "", // state already verified against the hosted token
		StateToken:       "", // no headless state token in the hosted flow
		AppleUserPayload: appleUserPayload,
		IPAddr:           ipAddr,
		UserAgent:        userAgent,
	})
	if err != nil {
		return nil, err
	}

	otc, err := s.mintHandoverCode(ctx, result.User.ID, HandoverMethodOAuth)
	if err != nil {
		return nil, err
	}

	return &HostedOAuthCallbackResult{
		ReturnTo:    claims.ReturnTo,
		Code:        otc,
		CSRFToken:   claims.CSRFToken,
		RedirectURL: handoverRedirectURL(claims.ReturnTo, otc),
	}, nil
}

// mintHandoverCode generates an opaque code, stores its hash bound to userID
// and to the flow that minted it (method) with a short TTL, and returns the
// plaintext. Only the hash is persisted; the plaintext lives solely in the
// redirect the hosted callback or page issues.
func (s *AuthService) mintHandoverCode(ctx context.Context, userID, method string) (string, error) {
	now := s.nowMs()
	raw := randomToken(32)
	_, err := s.repo(ctx).CreateOAuthOneTimeCode(ctx, &OAuthOneTimeCodeRecord{
		CodeHash:    sha256Hex(raw),
		UserID:      userID,
		LoginMethod: method,
		ExpiresAt:   now + oauthOneTimeCodeTTL.Milliseconds(),
		CreatedAt:   now,
	})
	if err != nil {
		return "", fmt.Errorf("creating handover code: %w", err)
	}
	return raw, nil
}

// handoverRedirectURL appends the handover code to the allowlisted return_to
// as ?code=, preserving any query the app already put there. return_to was
// parsed when the allowlist admitted it, so the parse cannot fail here; the
// concatenation fallback keeps the user on the app origin regardless.
func handoverRedirectURL(returnTo, code string) string {
	u, err := url.Parse(returnTo)
	if err != nil {
		sep := "?"
		if strings.Contains(returnTo, "?") {
			sep = "&"
		}
		return returnTo + sep + "code=" + url.QueryEscape(code)
	}
	q := u.Query()
	q.Set("code", code)
	u.RawQuery = q.Encode()
	return u.String()
}

// handoverAvailable reports whether any flow that mints handover codes is
// configured: OAuth for the hosted callback, or the return allowlist for the
// hosted magic-link page. With neither, no code can exist and redeem fails
// fast with ErrOAuthDisabled instead of answering "invalid code" for every
// probe.
func (s *AuthService) handoverAvailable(ctx context.Context) bool {
	return s.oauthResolver.available(ctx) || s.returnAllow.Enabled()
}

// handoverProfile maps the flow that minted a handover code to the login
// policy method its redeem must satisfy and the audit event it records. An
// unknown method fails closed — the code is refused rather than redeemed
// under a guessed policy.
func handoverProfile(method string) (policyMethod string, event audit.EventType, ok bool) {
	switch method {
	case HandoverMethodOAuth:
		return LoginMethodOAuth, audit.EventOAuthLogin, true
	case HandoverMethodMagicLink:
		return LoginMethodEmailOTP, audit.EventLoginSuccess, true
	}
	return "", "", false
}

// RedeemOAuthCode exchanges a single-use handover code for a fresh token
// pair. The hosted OAuth callback and the hosted magic-link page both mint
// one; the RPC keeps its original name because the wire contract did not
// change. The repository's ConsumeOAuthOneTimeCode is the serialization
// point: it atomically consumes the code (single winner across replicas)
// and returns the bound user, after which the login completes under the
// minting flow's login policy and tokens are minted via the same
// issueTokens path every other login uses. A replay, an expired code, or
// an unknown code all return ErrOAuthCodeInvalid.
func (s *AuthService) RedeemOAuthCode(ctx context.Context, code, ipAddr, userAgent string) (*LoginResult, error) {
	if !s.handoverAvailable(ctx) {
		return nil, ErrOAuthDisabled
	}
	if strings.TrimSpace(code) == "" {
		return nil, ErrOAuthCodeInvalid
	}

	rec, err := s.repo(ctx).ConsumeOAuthOneTimeCode(ctx, sha256Hex(code), s.nowMs())
	if err != nil {
		if errors.Is(err, ErrOAuthCodeInvalid) {
			return nil, ErrOAuthCodeInvalid
		}
		return nil, fmt.Errorf("consuming handover code: %w", err)
	}
	policyMethod, event, ok := handoverProfile(rec.LoginMethod)
	if !ok {
		s.logger.Warn("handover_code_unknown_method", zap.String("method", rec.LoginMethod))
		return nil, ErrOAuthCodeInvalid
	}

	user, err := s.repo(ctx).GetUser(ctx, rec.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrOAuthCodeInvalid
	}

	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return nil, err
	}

	// The code was minted only after the minting flow proved the user — a
	// verified provider login, or control of the inbox — so consult the
	// tenant's LoginPolicy for THAT method before issuing tokens, matching
	// the headless path of the same flow.
	decision, err := s.enforceLoginPolicy(ctx, user.Email, policyMethod)
	if err != nil {
		return nil, err
	}
	if user.TotpRequired || decision.RequireSecondFactor {
		return s.requireSecondFactor(ctx, user, decision.RequireSecondFactor)
	}

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}

	s.updateLastLogin(ctx, user.ID)
	s.logger.Info("handover_code_redeemed",
		zap.String("user_id", user.ID), zap.String("method", rec.LoginMethod))
	s.audit.Log(
		ctx, event,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": rec.LoginMethod, "via": "hosted_handover"}),
	)

	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}
