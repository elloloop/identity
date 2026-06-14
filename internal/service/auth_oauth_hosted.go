package service

import (
	"context"
	"errors"
	"fmt"
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
	provider, redirectURI, returnTo string,
) (*HostedOAuthBeginResult, error) {
	if s.oauthRegistry == nil || s.oauthRegistry.Len() == 0 {
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

	exchanger, ok := s.oauthRegistry.Get(provider)
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
	stateToken, err := oauth.IssueHostedStateToken(
		ctx,
		s.signer,
		provider,
		redirectURI,
		returnTo,
		state,
		codeVerifier,
		oauthStateTokenExpiry,
		s.nowFunc().UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}

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
// validated return_to plus the freshly-minted one-time code the callback
// appends as ?code=<otc>.
type HostedOAuthCallbackResult struct {
	ReturnTo string
	Code     string
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
	providerFromPath, code, stateToken, ipAddr, userAgent string,
) (*HostedOAuthCallbackResult, error) {
	claims, err := oauth.VerifyHostedStateToken(stateToken, s.signer, s.nowFunc().UTC())
	if err != nil {
		s.logger.Info("hosted_oauth_state_validation_failed", zap.Error(err))
		return nil, fmt.Errorf("%w: invalid oauth state", ErrUnauthenticated)
	}
	if want := strings.ToLower(strings.TrimSpace(providerFromPath)); want != "" && claims.Provider != want {
		s.logger.Info("hosted_oauth_provider_mismatch",
			zap.String("path_provider", want), zap.String("token_provider", claims.Provider))
		return nil, fmt.Errorf("%w: provider mismatch", ErrUnauthenticated)
	}

	// Reuse the headless exchange end to end: same state-token-free path
	// (we already verified the hosted token), passing the recovered
	// verifier so PKCE completes. OAuthLogin upserts the user and mints
	// the identity token pair internally; we discard those tokens and
	// hand back a one-time code instead — the SPA re-mints via redeem.
	result, err := s.OAuthLogin(
		ctx,
		code,
		claims.Provider,
		claims.RedirectURI,
		claims.CodeVerifier,
		"", // state already verified against the hosted token
		"", // no headless state token in the hosted flow
		ipAddr,
		userAgent,
	)
	if err != nil {
		return nil, err
	}

	otc, err := s.mintOAuthOneTimeCode(ctx, result.User.ID)
	if err != nil {
		return nil, err
	}

	return &HostedOAuthCallbackResult{ReturnTo: claims.ReturnTo, Code: otc}, nil
}

// mintOAuthOneTimeCode generates an opaque code, stores its hash bound
// to userID with a short TTL, and returns the plaintext. Only the hash
// is persisted; the plaintext lives solely in the callback redirect.
func (s *AuthService) mintOAuthOneTimeCode(ctx context.Context, userID string) (string, error) {
	now := s.nowMs()
	raw := randomToken(32)
	_, err := s.repo(ctx).CreateOAuthOneTimeCode(ctx, &OAuthOneTimeCodeRecord{
		CodeHash:  sha256Hex(raw),
		UserID:    userID,
		ExpiresAt: now + oauthOneTimeCodeTTL.Milliseconds(),
		CreatedAt: now,
	})
	if err != nil {
		return "", fmt.Errorf("creating oauth one-time code: %w", err)
	}
	return raw, nil
}

// RedeemOAuthCode exchanges the single-use hosted-flow code for a fresh
// token pair. The repository's ConsumeOAuthOneTimeCode is the
// serialization point: it atomically consumes the code (single winner
// across replicas) and returns the bound user, after which tokens are
// minted via the same issueTokens path every other login uses. A
// replay, an expired code, or an unknown code all return
// ErrOAuthCodeInvalid.
func (s *AuthService) RedeemOAuthCode(ctx context.Context, code, ipAddr, userAgent string) (*LoginResult, error) {
	if s.oauthRegistry == nil || s.oauthRegistry.Len() == 0 {
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
		return nil, fmt.Errorf("consuming oauth one-time code: %w", err)
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

	// The hosted code was minted only after a verified provider login, so
	// this is an oauth authentication; consult the tenant's LoginPolicy
	// before issuing tokens, matching the headless OAuthLogin path.
	if err := s.enforceLoginPolicy(ctx, user.Email, LoginMethodOAuth); err != nil {
		return nil, err
	}

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}

	s.updateLastLogin(ctx, user.ID)
	s.logger.Info("oauth_code_redeemed", zap.String("user_id", user.ID))
	s.audit.Log(
		ctx, audit.EventOAuthLogin,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "hosted_redeem"}),
	)

	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}
