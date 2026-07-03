package service

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/passwords"
)

// withPasswordMinLength returns a claimed-tenant governance bundle for
// acme.com whose policy tightens the minimum password length. AllowedMethods
// is left permissive (password) so the password path is reachable.
func withPasswordMinLength(minLen int) *LoginGovernance {
	g := claimedPasswordOnlyGovernance()
	p := g.Policies.(*fakePolicyStore).byTenant["proj-1|tenant-acme"]
	p.PasswordMinLength = minLen
	return g
}

// withSessionTimeouts returns a claimed-tenant governance bundle whose
// policy sets idle and absolute session timeouts (in seconds).
func withSessionTimeouts(idleSec, absoluteSec int64) *LoginGovernance {
	g := claimedPasswordOnlyGovernance()
	p := g.Policies.(*fakePolicyStore).byTenant["proj-1|tenant-acme"]
	p.SessionIdleTimeoutSeconds = idleSec
	p.SessionAbsoluteTimeoutSeconds = absoluteSec
	return g
}

// A tenant with password_min_length=12 rejects an 11-char password for that
// tenant only; an ungoverned user keeps the global 8-char baseline.
func TestValidatePasswordStrengthForEmail_TenantMinLength(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withPasswordMinLength(12))
	ctx := withProject("proj-1")

	// 11 valid-class chars: meets the global 8 floor but not the tenant 12.
	const elevenChar = "Aa1!aaaaaaa" // 11 runes, all classes present
	require.Len(t, []rune(elevenChar), 11)

	err := svc.validatePasswordStrengthForEmail(ctx, "alice@acme.com", elevenChar)
	require.Error(t, err, "11-char password must be rejected for a min-12 tenant")
	require.True(t, errors.Is(err, ErrWeakPassword))

	// A 12-char password satisfies the tightened policy.
	require.NoError(t, svc.validatePasswordStrengthForEmail(ctx, "alice@acme.com", "Aa1!aaaaaaaa"))

	// The same 11-char password is fine for a user outside the tenant —
	// the tightening applies to acme.com members only.
	require.NoError(t, svc.validatePasswordStrengthForEmail(ctx, "bob@other.example", elevenChar))
}

// Unset password policy fields preserve the global behavior.
func TestValidatePasswordStrengthForEmail_UnsetFallsBackToGlobal(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance()) // no password fields set
	ctx := withProject("proj-1")

	// An 8-char all-class password meets the global baseline.
	require.NoError(t, svc.validatePasswordStrengthForEmail(ctx, "alice@acme.com", "Aa1!aaaa"))
	// A 7-char password fails the global baseline regardless of tenant.
	require.Error(t, svc.validatePasswordStrengthForEmail(ctx, "alice@acme.com", "Aa1!aaa"))
}

// enforceSessionTimeout invalidates an idle session past its idle window.
func TestEnforceSessionTimeout_Idle(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withSessionTimeouts(60, 0)) // 60s idle, no absolute
	ctx := withProject("proj-1")

	now := int64(1_000_000_000)
	created := now - 30*msPerSecond // young
	idleOK := now - 30*msPerSecond  // used 30s ago, under 60s
	require.NoError(t, svc.enforceSessionTimeout(ctx, "alice@acme.com", now, created, idleOK))

	idleStale := now - 61*msPerSecond // used 61s ago, over 60s
	err := svc.enforceSessionTimeout(ctx, "alice@acme.com", now, created, idleStale)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrSessionExpired))
}

// enforceSessionTimeout invalidates a session past its absolute lifetime
// even when recently used.
func TestEnforceSessionTimeout_Absolute(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withSessionTimeouts(0, 3600)) // 1h absolute, no idle
	ctx := withProject("proj-1")

	now := int64(10_000_000_000)
	recentlyUsed := now - 1*msPerSecond

	created := now - 3599*msPerSecond // under 1h
	require.NoError(t, svc.enforceSessionTimeout(ctx, "alice@acme.com", now, created, recentlyUsed))

	old := now - 3601*msPerSecond // over 1h
	err := svc.enforceSessionTimeout(ctx, "alice@acme.com", now, old, recentlyUsed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrSessionExpired))
}

// Unset timeouts and ungoverned users impose no session timeout.
func TestEnforceSessionTimeout_FailSafe(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	ctx := withProject("proj-1")

	// No governance at all.
	require.NoError(t, svc.enforceSessionTimeout(ctx, "alice@acme.com", 1<<40, 0, 0))

	// Governance present but timeouts unset.
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())
	require.NoError(t, svc.enforceSessionTimeout(ctx, "alice@acme.com", 1<<40, 1, 1))

	// Timeouts set, but the user is outside any governed tenant.
	svc.WithLoginGovernance(withSessionTimeouts(1, 1))
	require.NoError(t, svc.enforceSessionTimeout(ctx, "stranger@nowhere.example", 1<<40, 1, 1))
}

// RefreshToken rejects an idle session past the tenant's idle timeout and
// deletes the dead refresh row, on the real hot path.
func TestRefreshToken_TenantIdleTimeout(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withSessionTimeouts(60, 0)) // 60s idle

	now := time.Unix(2_000_000, 0)
	svc.nowFunc = func() time.Time { return now }
	ctx := withProject("proj-1")

	user := seedUser(repo, "alice@acme.com", "", "active")
	rawToken := "raw-idle-token" // #nosec G101 -- a test fixture, not a real credential.
	_, err := repo.CreateRefreshToken(ctx, &RefreshTokenRecord{
		TokenHash:  hashRefreshToken(rawToken),
		UserID:     user.ID,
		ExpiresAt:  now.Add(time.Hour).UnixMilli(), // not yet absolutely expired
		CreatedAt:  now.Add(-30 * time.Minute).UnixMilli(),
		LastUsedAt: now.Add(-61 * time.Second).UnixMilli(), // idle past 60s
	})
	require.NoError(t, err)

	_, _, _, err = svc.RefreshToken(ctx, rawToken, "", "")
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrSessionExpired))

	// The dead session's refresh row is gone.
	stored, findErr := repo.FindRefreshTokenByHashIncludingConsumed(ctx, hashRefreshToken(rawToken))
	require.NoError(t, findErr)
	require.Nil(t, stored)
}

// Under mode=session, a session-timeout breach must revoke the matching access
// session — not just delete the refresh row — so the still-valid access token
// stops working immediately. Regression for #304, where the sid Session row
// outlived the refresh token under GATEWAY_REVOCATION_MODE=session.
func TestRefreshToken_SessionMode_IdleTimeoutRevokesAccessSession(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	svc.cfg.RevocationMode = config.RevocationModeSession
	svc.WithLoginGovernance(withSessionTimeouts(60, 0)) // 60s idle

	start := time.Unix(4_000_000, 0)
	cur := start
	svc.nowFunc = func() time.Time { return cur }
	ctx := withProject("proj-1")

	user := seedUser(repo, "alice@acme.com", "", "active")

	// Initial login mints an access session (sid) + refresh token.
	access, raw, err := svc.issueTokens(ctx, user, "", "")
	require.NoError(t, err)
	claims, err := jwt.VerifyAccessToken(access, svc.signer, "", "", false)
	require.NoError(t, err)
	require.NotEmpty(t, claims.SID)

	// The access session is active before the breach.
	sess, err := repo.GetSessionBySid(ctx, claims.SID)
	require.NoError(t, err)
	require.NotNil(t, sess)
	require.Zero(t, sess.RevokedAtMs)

	// Advance past the idle window and refresh: the timeout fires.
	cur = start.Add(61 * time.Second)
	_, _, _, err = svc.RefreshToken(ctx, raw, "", "")
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrSessionExpired))

	// The refresh row is gone AND the access session is revoked, so a
	// session-store check on the still-live access token now rejects it.
	stored, findErr := repo.FindRefreshTokenByHashIncludingConsumed(ctx, hashRefreshToken(raw))
	require.NoError(t, findErr)
	require.Nil(t, stored)

	revoked, err := repo.GetSessionBySid(ctx, claims.SID)
	require.NoError(t, err)
	require.NotNil(t, revoked)
	require.NotZero(t, revoked.RevokedAtMs, "access session must be revoked on a mode=session timeout breach")
}

// In the default mode=ttl, a timeout breach deletes the refresh row and never
// touches the session store (there is no session), so behavior is unchanged.
func TestRefreshToken_TTLMode_IdleTimeoutLeavesSessionStoreUntouched(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	// Default config is mode=ttl.
	svc.WithLoginGovernance(withSessionTimeouts(60, 0))

	start := time.Unix(4_500_000, 0)
	cur := start
	svc.nowFunc = func() time.Time { return cur }
	ctx := withProject("proj-1")

	user := seedUser(repo, "alice@acme.com", "", "active")
	access, raw, err := svc.issueTokens(ctx, user, "", "")
	require.NoError(t, err)

	// mode=ttl mints no session and no sid claim.
	claims, err := jwt.VerifyAccessToken(access, svc.signer, "", "", false)
	require.NoError(t, err)
	require.Empty(t, claims.SID)

	cur = start.Add(61 * time.Second)
	_, _, _, err = svc.RefreshToken(ctx, raw, "", "")
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrSessionExpired))

	// The refresh row is gone; no session rows were ever created.
	stored, findErr := repo.FindRefreshTokenByHashIncludingConsumed(ctx, hashRefreshToken(raw))
	require.NoError(t, findErr)
	require.Nil(t, stored)

	repo.mu.Lock()
	n := len(repo.sessions)
	repo.mu.Unlock()
	require.Zero(t, n, "mode=ttl must not create or touch session rows")
}

// RefreshToken succeeds for a fresh session under the tenant's timeouts.
func TestRefreshToken_TenantTimeout_FreshSessionPasses(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withSessionTimeouts(3600, 86400))

	now := time.Unix(3_000_000, 0)
	svc.nowFunc = func() time.Time { return now }
	ctx := withProject("proj-1")

	user := seedUser(repo, "alice@acme.com", "", "active")
	rawToken := "raw-fresh-token"
	_, err := repo.CreateRefreshToken(ctx, &RefreshTokenRecord{
		TokenHash:  hashRefreshToken(rawToken),
		UserID:     user.ID,
		ExpiresAt:  now.Add(time.Hour).UnixMilli(),
		CreatedAt:  now.Add(-time.Minute).UnixMilli(),
		LastUsedAt: now.Add(-time.Second).UnixMilli(),
	})
	require.NoError(t, err)

	gotUser, access, refresh, err := svc.RefreshToken(ctx, rawToken, "", "")
	require.NoError(t, err)
	require.Equal(t, user.ID, gotUser.ID)
	require.NotEmpty(t, access)
	require.NotEmpty(t, refresh)
}

// The absolute timeout is anchored at the original login and survives
// repeated refreshes: a session that keeps refreshing within its idle window
// must still die once the absolute window passes. This is the regression for
// the bug where issueTokens re-stamped CreatedAt on every rotation, so the
// absolute cap was measured from the latest refresh and never fired.
func TestRefreshToken_AbsoluteTimeoutAnchoredAcrossRefreshes(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	// idle 1h, absolute 2h — refreshing every 30m never goes idle, so only
	// the absolute cap can end the session.
	svc.WithLoginGovernance(withSessionTimeouts(3600, 7200))

	start := time.Unix(5_000_000, 0)
	cur := start
	svc.nowFunc = func() time.Time { return cur }
	ctx := withProject("proj-1")

	user := seedUser(repo, "alice@acme.com", "", "active")

	// Initial login anchors the session's absolute lifetime at `start`.
	_, raw, err := svc.issueTokens(ctx, user, "", "")
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	// Refresh at +30m, +60m, +90m, +120m. Each stays within the 1h idle
	// window AND within (or exactly at) the 2h absolute cap, so all succeed
	// and rotate the token — yet the absolute anchor stays pinned to `start`.
	for _, mins := range []int{30, 60, 90, 120} {
		cur = start.Add(time.Duration(mins) * time.Minute)
		_, _, raw, err = svc.RefreshToken(ctx, raw, "", "")
		require.NoErrorf(t, err, "refresh at +%dm should be within the absolute window", mins)
		require.NotEmpty(t, raw)
	}

	// +150m: still well within the idle window (only 30m since the last
	// refresh) but past the 2h absolute cap. With the bug, CreatedAt would
	// have been re-stamped to +120m and this would wrongly succeed.
	cur = start.Add(150 * time.Minute)
	_, _, _, err = svc.RefreshToken(ctx, raw, "", "")
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrSessionExpired), "absolute cap must fire once the session is older than 2h")
}

// passwordStrengthPolicy maps the LoginPolicy fields onto the passwords
// StrengthPolicy and falls back to the zero policy when ungoverned.
func TestPasswordStrengthPolicy(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	ctx := withProject("proj-1")

	g := withPasswordMinLength(16)
	svc.WithLoginGovernance(g)

	got := g.passwordStrengthPolicy(ctx, "proj-1", svc.logger, "alice@acme.com")
	require.Equal(t, passwords.StrengthPolicy{MinLength: 16}, got)

	// Ungoverned → zero policy (global default).
	require.Equal(t, passwords.StrengthPolicy{}, g.passwordStrengthPolicy(ctx, "proj-1", svc.logger, "x@nowhere.example"))
}
