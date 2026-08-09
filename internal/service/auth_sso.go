package service

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// ssoSessionTokenBytes is the entropy of the opaque cookie value. It is the
// only thing standing between a guess and a browser's SSO session, so it
// matches the refresh-token width rather than the shorter one-time code's.
const ssoSessionTokenBytes = 32

// SSOSessionView is what a sign-in surface may learn about the browser's SSO
// session: who it belongs to, and whether this deployment wants a visible tap
// before minting. Nothing else — no session id, no token, no timestamps —
// because the view crosses an origin boundary to the hub.
//
// It answers "whose card do I draw", NOT "may this person enter". Authorization
// is decided at mint time by ContinueSSOSession, which re-runs the account,
// access, and policy gates; a surface that renders a card is not promising the
// continue will succeed.
type SSOSessionView struct {
	Email        string
	ContinueMode string
}

// EstablishSSOSession records that this browser completed an authentication
// and returns the opaque value to put in the cookie. Only the hash is stored.
//
// loginMethod is the method that actually authenticated the user; it is
// replayed against the tenant's login policy on every later fast path, so a
// cookie can never launder a weak login into a stronger one.
//
// It returns an empty string (and no error) when SSO is disabled, so callers
// can wire it unconditionally: a deployment that has not opted in simply never
// gets a cookie value to set.
func (s *AuthService) EstablishSSOSession(
	ctx context.Context,
	userID, loginMethod, ipAddr, userAgent string,
) (string, error) {
	if !s.cfg.SSOEnabled || userID == "" {
		return "", nil
	}
	now := s.nowMs()
	raw := randomToken(ssoSessionTokenBytes)
	_, err := s.repo(ctx).CreateSSOSession(ctx, &SSOSessionRecord{
		TokenHash:    sha256Hex(raw),
		UserID:       userID,
		LoginMethod:  loginMethod,
		IPAddress:    ipAddr,
		UserAgent:    truncate(userAgent, 512),
		CreatedAtMs:  now,
		LastUsedAtMs: now,
		ExpiresAtMs:  now + int64(s.cfg.SSOSessionTTLSeconds)*1000,
	})
	if err != nil {
		return "", fmt.Errorf("creating sso session: %w", err)
	}
	s.audit.Log(
		ctx, audit.EventSSOSessionStarted,
		audit.WithActor(userID), audit.WithTarget(userID),
		audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"login_method": loginMethod}),
	)
	return raw, nil
}

// IntrospectSSOSession resolves a cookie value to the account it belongs to,
// for a sign-in surface that renders its own "Continue as <email>" card.
//
// It is deliberately a thin read: an inactive or unknown cookie, a deleted
// account, and a disabled deployment all return ErrSSOSessionInvalid, so the
// endpoint reveals nothing beyond "there is a session here, and it is this
// person's". The repository is project-scoped, so a session established in one
// project is simply not found in another — that is what stops a consumer SSO
// session from lighting up an admin project's sign-in page.
func (s *AuthService) IntrospectSSOSession(ctx context.Context, rawCookie string) (*SSOSessionView, error) {
	rec, err := s.activeSSOSession(ctx, rawCookie)
	if err != nil {
		return nil, err
	}
	user, err := s.repo(ctx).GetUser(ctx, rec.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrSSOSessionInvalid
	}
	return &SSOSessionView{Email: user.Email, ContinueMode: s.cfg.SSOContinueMode}, nil
}

// ContinueSSOSession is the fast path: it turns a valid SSO cookie into the
// same single-use code a completed provider round trip produces, WITHOUT
// contacting the provider.
//
// It ends exactly where CompleteHostedOAuth ends, and that is the point.
// Nothing here mints a token pair; the caller 302s to returnTo?code=… and the
// product redeems it through the unchanged RedeemOAuthCode, so per-product
// pairs, rotation lineage, and the product age gate are inherited from the
// normal path rather than re-implemented on a second one.
//
// Skipping the provider must not skip anything else, so every gate a cold
// sign-in runs between "we know who you are" and "here is a code" runs here
// too: account status (lockout, deactivation, IDV), the project's access mode,
// and the tenant's login policy replayed against the session's original login
// method. Having authenticated is not authorization to enter a product.
//
// returnTo must already have been checked against the return allowlist by the
// caller, exactly as /oauth/start checks it before a provider round trip.
func (s *AuthService) ContinueSSOSession(
	ctx context.Context,
	rawCookie, returnTo, ipAddr, userAgent string,
) (*HostedOAuthCallbackResult, error) {
	if strings.TrimSpace(returnTo) == "" {
		return nil, fmt.Errorf("%w: return_to is required", ErrInvalidArgument)
	}

	rec, err := s.activeSSOSession(ctx, rawCookie)
	if err != nil {
		return nil, err
	}

	user, err := s.repo(ctx).GetUser(ctx, rec.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrSSOSessionInvalid
	}

	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return nil, err
	}
	if err := s.enforceProjectAccessLogin(ctx, canonicalize(user.Email)); err != nil {
		return nil, err
	}

	// Replayed against the ORIGINAL method, not a synthetic "sso" one: an
	// authentication that the tenant's policy would refuse today, or that it
	// treats as single-factor, must not become acceptable merely because it
	// happened once before.
	decision, err := s.enforceLoginPolicy(ctx, user.Email, rec.LoginMethod)
	if err != nil {
		return nil, err
	}
	if user.TotpRequired || decision.RequireSecondFactor {
		return nil, ErrSSOSecondFactorRequired
	}

	otc, err := s.mintOAuthOneTimeCode(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	// Roll the window only after the mint succeeded — a refused continue must
	// not extend the session's life. Best-effort: the user already has their
	// code, and a failed touch only means the session lapses on its original
	// schedule.
	now := s.nowMs()
	if err := s.repo(ctx).TouchSSOSession(
		ctx, rec.TokenHash, now, now+int64(s.cfg.SSOSessionTTLSeconds)*1000,
	); err != nil {
		s.logger.Warn("sso_session_touch_failed", zap.String("user_id", user.ID), zap.Error(err))
	}

	s.logger.Info("sso_session_continued", zap.String("user_id", user.ID))
	s.audit.Log(
		ctx, audit.EventSSOSessionContinued,
		audit.WithActor(user.ID), audit.WithTarget(user.ID),
		audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"login_method": rec.LoginMethod}),
	)

	return &HostedOAuthCallbackResult{ReturnTo: returnTo, Code: otc}, nil
}

// EndSSOSession revokes the single session a cookie names. It backs the
// product-initiated hub sign-out, and is a no-op for an absent or already-dead
// cookie so a sign-out link is always safe to follow.
func (s *AuthService) EndSSOSession(ctx context.Context, rawCookie string) error {
	if !s.cfg.SSOEnabled || strings.TrimSpace(rawCookie) == "" {
		return nil
	}
	return s.repo(ctx).RevokeSSOSession(ctx, sha256Hex(rawCookie), s.nowMs())
}

// activeSSOSession resolves a raw cookie value to a usable session row.
// Disabled deployments, absent cookies, unknown hashes, expired rows, revoked
// rows, and rows belonging to another project all collapse to
// ErrSSOSessionInvalid: the caller's behaviour is identical for all of them,
// and distinguishing them to the client would turn the endpoint into an oracle
// for which cookie values exist.
func (s *AuthService) activeSSOSession(ctx context.Context, rawCookie string) (*SSOSessionRecord, error) {
	if !s.cfg.SSOEnabled {
		return nil, ErrSSOSessionInvalid
	}
	if strings.TrimSpace(rawCookie) == "" {
		return nil, ErrSSOSessionInvalid
	}
	rec, err := s.repo(ctx).FindSSOSessionByHash(ctx, sha256Hex(rawCookie))
	if err != nil {
		return nil, err
	}
	if !rec.Active(s.nowMs()) {
		return nil, ErrSSOSessionInvalid
	}
	return rec, nil
}
