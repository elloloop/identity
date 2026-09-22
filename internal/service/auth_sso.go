package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
)

var (
	// ErrSSODisabled is returned when a cross-product SSO path runs while
	// GATEWAY_SSO_ENABLED is false. The HTTP layer registers no /sso routes
	// in that posture, so this only fires on a route registered anyway.
	ErrSSODisabled = errors.New("sso is not enabled for this deployment")
	// ErrSSOSessionInvalid is returned when a continue-as cookie names no
	// live SSO session — unknown, expired, revoked, or minted under a
	// different project. All failure modes look identical so the endpoint
	// cannot be probed for which sessions exist.
	ErrSSOSessionInvalid = errors.New("sso session is invalid or expired")
)

// SSOContinueResult is the output of ContinueWithSSO: the validated
// return_to plus the freshly-minted single-use code the handler appends as
// ?code=<otc>, exactly like the hosted OAuth callback.
type SSOContinueResult struct {
	ReturnTo string
	Code     string
}

// ssoEnabled reports whether cross-product SSO is configured on.
func (s *AuthService) ssoEnabled() bool {
	return s.cfg != nil && s.cfg.SSOEnabled
}

// mintSSOSession generates an opaque token, stores its hash bound to userID
// under the request's project with the ORIGINAL login method recorded, and
// returns the plaintext. Only the hash is persisted; the plaintext lives
// solely in the browser's __Host- cookie.
func (s *AuthService) mintSSOSession(ctx context.Context, userID, method string) (string, error) {
	scope := ProjectScopeFromContext(ctx)
	if scope == nil {
		return "", fmt.Errorf("%w: missing project scope", ErrUnauthenticated)
	}
	ttl := s.cfg.SSOSessionTTLSeconds
	if ttl <= 0 {
		// Validate refuses to boot an enabled deployment with a non-positive
		// TTL; this only guards a directly-constructed Config.
		ttl = config.DefaultSSOSessionTTLSeconds
	}
	now := s.nowMs()
	raw := randomToken(32)
	_, err := s.repo(ctx).CreateSSOSession(ctx, &SSOSessionRecord{
		TokenHash:   sha256Hex(raw),
		UserID:      userID,
		ProjectID:   scope.ProjectID,
		LoginMethod: method,
		ExpiresAt:   now + int64(ttl)*1000,
		CreatedAt:   now,
	})
	if err != nil {
		return "", fmt.Errorf("creating sso session: %w", err)
	}
	return raw, nil
}

// ContinueWithSSO is the cross-product continue-as fast path: it validates
// the SSO session the auth origin's cookie carries, re-runs EVERY
// authorization gate an interactive login would, and ends at the same
// single-use one-time code the hosted OAuth callback mints — so the
// product redeems it into its OWN fresh token pair and refresh rotation /
// replay semantics are inherited, never re-implemented.
//
// The gates, in order, each re-run on every continue-as:
//   - project binding: the session's ProjectID must equal the request's
//     resolved project — a session never lights up another project's
//     sign-in;
//   - return_to allowlist (fail-closed, same list as the hosted flow);
//   - project access mode (enforceProjectAccessLogin);
//   - account status (checkAccountStatus);
//   - the ORIGINAL login policy (enforceLoginPolicy with the method the
//     session was established with — not a synthetic "sso" method), and a
//     second-factor requirement is refused outright: a cookie must never
//     launder a login that now needs more proof than it gave;
//   - the product age gate (enforceProductAgeGate).
//
// A failure any user action can resolve by re-authenticating (unknown /
// expired / wrong-project session, second factor now required) collapses
// to ErrSSOSessionInvalid; gate denials keep their existing sentinels so
// logs and audits stay precise.
func (s *AuthService) ContinueWithSSO(ctx context.Context, rawToken, returnTo, ipAddr, userAgent string) (*SSOContinueResult, error) {
	if !s.ssoEnabled() {
		return nil, ErrSSODisabled
	}
	scope := ProjectScopeFromContext(ctx)
	if scope == nil {
		return nil, fmt.Errorf("%w: missing project scope", ErrUnauthenticated)
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, ErrSSOSessionInvalid
	}

	rec, err := s.repo(ctx).GetSSOSessionByHash(ctx, sha256Hex(rawToken))
	if err != nil {
		return nil, fmt.Errorf("querying sso session: %w", err)
	}
	if rec == nil || rec.ExpiresAt <= s.nowMs() {
		return nil, ErrSSOSessionInvalid
	}
	// Never bridge projects: whatever host or key the request arrived
	// with, a session minted under project A cannot mint a code in
	// project B (mirrors the hosted-state project binding).
	if rec.ProjectID != scope.ProjectID {
		s.logger.Info("sso_project_mismatch", zap.String("expected", rec.ProjectID))
		return nil, ErrSSOSessionInvalid
	}

	if !s.returnAllow.Allows(returnTo) {
		// Fail closed, and do not echo the value back (attacker-controlled).
		s.logger.Info("sso_return_to_rejected")
		return nil, fmt.Errorf("%w: return_to is not allowed", ErrInvalidArgument)
	}

	user, err := s.repo(ctx).GetUser(ctx, rec.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrSSOSessionInvalid
	}

	if err := s.enforceProjectAccessLogin(ctx, canonicalize(user.Email)); err != nil {
		return nil, err
	}
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return nil, err
	}

	decision, err := s.enforceLoginPolicy(ctx, user.Email, rec.LoginMethod)
	if err != nil {
		return nil, err
	}
	if user.TotpRequired || decision.RequireSecondFactor {
		s.logger.Info("sso_continue_second_factor_required", zap.String("user_id", user.ID))
		return nil, fmt.Errorf("%w: a second factor is required; sign in again", ErrSSOSessionInvalid)
	}

	// Derive the band from the stored DOB before the gate, mirroring the
	// stamp issueTokensWithSessionStart performs at mint time.
	s.stampAgeBand(user)
	if err := s.enforceProductAgeGate(ctx, user); err != nil {
		return nil, err
	}

	otc, err := s.mintOAuthOneTimeCode(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	s.logger.Info("sso_continue", zap.String("user_id", user.ID))
	s.audit.Log(
		ctx, audit.EventOAuthLogin,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "sso_continue"}),
	)

	return &SSOContinueResult{ReturnTo: returnTo, Code: otc}, nil
}
