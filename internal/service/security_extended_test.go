package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/jwt"
)

// TestSecExt_RefreshTokenReplay_RevokesAllSessions covers two security
// invariants for refresh-token theft:
//  1. The reused (already-rotated) token must be rejected on second use.
//  2. When replay is detected, ALL active refresh tokens for that user
//     should be invalidated (industry-standard "refresh token reuse
//     detection" — see OAuth 2.1 §4.13).
//
// (1) is asserted; (2) is asserted and CURRENTLY FAILS because
// AuthService.RefreshToken does not implement reuse-detection cleanup
// — DeleteRefreshTokensForUser exists on the repo interface but is never
// called from the refresh path. This test stays failing to surface that
// hardening gap.
func TestSecExt_RefreshTokenReplay_RevokesAllSessions(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	// Sign up — first session.
	r1, err := svc.PasswordSignup(context.Background(), "alice@example.com", strongPW, "", "")
	require.NoError(t, err)
	stolenRefresh := r1.RefreshToken

	// Issue a SECOND parallel session for the same user (e.g. login from
	// a second device).
	r2, err := svc.PasswordLogin(context.Background(), "alice@example.com", strongPW, "", "")
	require.NoError(t, err)
	otherRefresh := r2.RefreshToken
	require.NotEqual(t, stolenRefresh, otherRefresh)

	// Attacker uses the stolen refresh token first — succeeds (rotates).
	_, _, _, err = svc.RefreshToken(context.Background(), stolenRefresh, "", "")
	require.NoError(t, err)

	// (1) Replay of the now-rotated token: MUST fail.
	_, _, _, err = svc.RefreshToken(context.Background(), stolenRefresh, "", "")
	require.Error(t, err, "rotated refresh token MUST not be reusable")
	assert.True(t, errors.Is(err, ErrUnauthenticated))

	// (2) On replay, all sessions for this user should be invalidated —
	// the legitimate user's other refresh token must also be revoked.
	_, _, _, err = svc.RefreshToken(context.Background(), otherRefresh, "", "")
	if err == nil {
		t.Fatalf("BUG: refresh-token replay was detected but the user's other " +
			"active refresh token was NOT invalidated; AuthService.RefreshToken " +
			"does not call DeleteRefreshTokensForUser on replay (OAuth 2.1 §4.13 violation)")
	}
}

// TestSecExt_LoginTiming_NoUserEnumeration asserts that a non-existent
// email vs. an existing email with the wrong password take comparable
// time, so an attacker cannot enumerate valid emails by timing.
//
// Allowance: the existing-user path runs bcrypt.CompareHashAndPassword
// (≈250ms at cost 12) while the missing-user path returns immediately.
// If the missing-user path is much faster, that's a timing leak.
//
// Many implementations close this gap by always running a "fake bcrypt"
// for missing users. This test pins the gap if present.
func TestSecExt_LoginTiming_NoUserEnumeration(t *testing.T) {
	// Not parallel: this test measures wall-clock time.
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	pwHash := hashPW(t, strongPW)
	seedUser(repo, "exists@example.com", pwHash, "active")

	const iters = 5
	measure := func(email, pw string) time.Duration {
		var total time.Duration
		for i := 0; i < iters; i++ {
			start := time.Now()
			_, _ = svc.PasswordLogin(context.Background(), email, pw, "", "")
			total += time.Since(start)
		}
		return total / iters
	}

	// Warm-up.
	_, _ = svc.PasswordLogin(context.Background(), "exists@example.com", "WrongP@ss1!", "", "")
	_, _ = svc.PasswordLogin(context.Background(), "missing@example.com", strongPW, "", "")

	avgWrongPW := measure("exists@example.com", "WrongP@ss1!")
	avgMissing := measure("missing@example.com", strongPW)

	t.Logf("Login avg wrong-pw=%v missing-user=%v", avgWrongPW, avgMissing)

	// If existing-user path is more than ~5x slower than missing-user path,
	// timing leaks the existence of the email. We allow some slack because
	// CI noise is real, but a 5x ratio is well within enumeration range.
	if avgWrongPW > 5*avgMissing && avgMissing > 0 {
		t.Errorf("BUG: PasswordLogin is %.1fx slower for existing user (wrong pw) "+
			"than for missing user — email enumeration via timing is feasible. "+
			"Mitigation: run a dummy bcrypt comparison for missing users.",
			float64(avgWrongPW)/float64(avgMissing))
	}
}

// TestSecExt_CrossTenant_TokenRejection asserts that a JWT minted under
// tenant A is not accepted to authorize ops on tenant B.
//
// The current implementation embeds the configured tenant in the JWT
// "tenant" claim, but the verifier (jwt.VerifyAccessToken) does not
// enforce that the claim matches the verifying service's configured
// tenant. The downstream AuthService.GetCurrentUser also does not check.
// This test FAILS until tenant claim enforcement is added — leaving it
// failing surfaces the cross-tenant authorization gap.
func TestSecExt_CrossTenant_TokenRejection(t *testing.T) {
	t.Parallel()
	repoA := newFakeRepo()
	svcA := newTestAuthService(t, repoA)
	svcA.tenantID = "tenant-a"
	svcA.cfg.DefaultTenantID = "tenant-a"

	// Sign up Alice in tenant A.
	rA, err := svcA.PasswordSignup(context.Background(), "alice@example.com", strongPW, "", "")
	require.NoError(t, err)
	tokenA := rA.AccessToken

	// Service B uses the SAME key ring (shared signing keys, e.g. shared
	// JWKS in a multi-tenant deployment) but is configured for tenant-b.
	repoB := newFakeRepo()
	svcB := newTestAuthService(t, repoB)
	svcB.tenantID = "tenant-b"
	svcB.cfg.DefaultTenantID = "tenant-b"
	svcB.keyRing = svcA.keyRing // shared trust

	// The token's claim says tenant-a; service B is tenant-b.
	claims, err := jwt.VerifyAccessToken(tokenA, svcB.keyRing)
	require.NoError(t, err, "token signature is valid (shared keys)")
	require.Equal(t, "tenant-a", claims.Tenant)

	// At this point a tenant-aware service should reject the token.
	// The current verification path returns the token's claim verbatim
	// without comparing against svcB.tenantID — which is the bug.
	if claims.Tenant == svcB.tenantID {
		t.Fatalf("test setup wrong: tenants should differ")
	}
	t.Errorf("BUG: cross-tenant token accepted — JWT verification does not " +
		"check the tenant claim against the verifying service's configured " +
		"tenant. A token issued for tenant %q is accepted as-is by a service "+
		"configured for tenant %q.", claims.Tenant, svcB.tenantID)
}

// TestSecExt_AccountLockout_NFailuresLockWithinWindow asserts that after
// N=cfg.LoginMaxFailedAttempts failed attempts the account is locked.
func TestSecExt_AccountLockout_NFailuresLockWithinWindow(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "lockout@example.com", pwHash, "active")

	maxAttempts := svc.cfg.LoginMaxFailedAttempts
	require.Greater(t, maxAttempts, 0)

	for i := 0; i < maxAttempts; i++ {
		_, err := svc.PasswordLogin(context.Background(), "lockout@example.com", "BadP@ss1!", "", "")
		require.Error(t, err)
	}

	// (N+1)th attempt with correct password must be locked.
	_, err := svc.PasswordLogin(context.Background(), "lockout@example.com", strongPW, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAccountLocked),
		"after %d failed attempts the account MUST be locked", maxAttempts)
}

// TestSecExt_PasswordResetTokenReplay_NotApplicable documents that the
// codebase has no public "consume password reset token" path —
// AdminService.ResetUserPassword only generates a reset token; there is
// no service method that consumes it. So replay-rejection cannot be
// asserted at this layer. This test is a placeholder that records the
// gap (a reset token should be single-use when the consume endpoint is
// added).
func TestSecExt_PasswordResetTokenReplay_NotApplicable(t *testing.T) {
	t.Parallel()
	t.Skip("no public password-reset consume endpoint exists in AuthService; " +
		"AdminService.ResetUserPassword only generates the token. Replay-rejection " +
		"must be asserted when the consume endpoint is implemented.")
}

// TestSecExt_InvitationTokenReplay asserts that an accepted invitation
// token cannot be reused.
func TestSecExt_InvitationTokenReplay(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	u := seedUser(repo, "invitee@example.com", "", "invited")

	rawToken := "invitation-token-replay-test"
	tokenHash := hashInvitationToken(rawToken)
	seedInvitation(repo, &InvitationRecord{
		TokenHash: tokenHash,
		Email:     "invitee@example.com",
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})

	// First use — succeeds.
	r, err := svc.AcceptInvitation(context.Background(), rawToken, strongPW, "Name", "", "")
	require.NoError(t, err)
	require.NotNil(t, r)

	// Second use — must be rejected.
	_, err = svc.AcceptInvitation(context.Background(), rawToken, strongPW, "Name", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvitationUsed),
		"replayed invitation token MUST be rejected")
}

// TestSecExt_ConcurrentLogin_NoInconsistentState asserts that two
// goroutines logging in for the same user concurrently do not corrupt
// state. Both should succeed OR one should fail cleanly with a
// well-defined error — there must be no panic, no data race, and the
// repository should remain consistent (each successful login produces
// exactly one refresh token).
func TestSecExt_ConcurrentLogin_NoInconsistentState(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "concurrent@example.com", pwHash, "active")

	const N = 8
	var wg sync.WaitGroup
	results := make([]struct {
		ok  bool
		err error
	}, N)

	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			r, err := svc.PasswordLogin(context.Background(), "concurrent@example.com", strongPW, "", "")
			results[i].err = err
			results[i].ok = err == nil && r != nil && r.RefreshToken != ""
		}()
	}
	wg.Wait()

	successes := 0
	for _, r := range results {
		if r.ok {
			successes++
		} else if r.err != nil {
			// Any error must be one of the well-defined sentinels.
			if !(errors.Is(r.err, ErrUnauthenticated) ||
				errors.Is(r.err, ErrAccountLocked) ||
				errors.Is(r.err, ErrAccountNotActive)) {
				t.Errorf("unexpected error type from concurrent login: %v", r.err)
			}
		}
	}
	t.Logf("concurrent logins: %d/%d successes", successes, N)
	assert.Greater(t, successes, 0, "at least one concurrent login should succeed")

	// Refresh token count should equal successes (no duplicates, no losses).
	repo.mu.Lock()
	rtCount := len(repo.refreshTokens)
	repo.mu.Unlock()
	assert.Equal(t, successes, rtCount,
		"each successful login should produce exactly one refresh token")
}
