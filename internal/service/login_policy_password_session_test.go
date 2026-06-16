package service

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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
	rawToken := "raw-idle-token"
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

// passwordStrengthPolicyFor maps the LoginPolicy fields onto the passwords
// StrengthPolicy and falls back to the zero policy when ungoverned.
func TestPasswordStrengthPolicyFor(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	ctx := withProject("proj-1")

	g := withPasswordMinLength(16)
	g.Policies.(*fakePolicyStore).byTenant["proj-1|tenant-acme"].PasswordRequireClasses = true
	svc.WithLoginGovernance(g)

	got := svc.passwordStrengthPolicyFor(ctx, "alice@acme.com")
	require.Equal(t, passwords.StrengthPolicy{MinLength: 16, RequireClasses: true}, got)

	// Ungoverned → zero policy (global default).
	require.Equal(t, passwords.StrengthPolicy{}, svc.passwordStrengthPolicyFor(ctx, "x@nowhere.example"))
}
