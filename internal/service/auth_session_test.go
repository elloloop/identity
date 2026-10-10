package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/jwt"
)

// ── mode=ttl (default) ─────────────────────────────────────────────────

func TestModeTTL_IssueTokens_DoesNotMintSession(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	// Default test config is mode=ttl (empty), so no session mints.

	result, err := svc.PasswordSignup(context.Background(), "ttl@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	require.NotEmpty(t, result.AccessToken)

	claims, err := jwt.VerifyAccessToken(result.AccessToken, svc.signer, "", "", false)
	require.NoError(t, err)
	assert.Empty(t, claims.SID, "ttl mode must not put a sid on the access token")

	repo.mu.Lock()
	n := len(repo.sessions)
	repo.mu.Unlock()
	assert.Equal(t, 0, n, "ttl mode must not create any Session rows")
}

func TestModeTTL_DeleteRefreshTokensForUser_LeavesAccessTokenAlive(t *testing.T) {
	// Documents the mode=ttl contract: in-flight access tokens stay
	// valid until natural JWT expiry even after refresh tokens are
	// revoked. The startup assertion is what stops a deployer from
	// raising the TTL without switching modes.
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "ttl-revoke@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)

	user, err := repo.FindUserByEmail(context.Background(), "ttl-revoke@example.com")
	require.NoError(t, err)
	require.NotNil(t, user)

	require.NoError(t, repo.DeleteRefreshTokensForUser(context.Background(), user.ID))

	// Access token: still verifiable against the same key ring.
	_, err = jwt.VerifyAccessToken(result.AccessToken, svc.signer, "", "", false)
	assert.NoError(t, err, "in-flight access token must verify in mode=ttl after refresh revocation")
}

// ── RefreshToken account-status re-check ───────────────────────────────

func TestRefreshToken_DeactivatedUser_Rejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "deact@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)

	user, err := repo.FindUserByEmail(context.Background(), "deact@example.com")
	require.NoError(t, err)
	require.NoError(t, repo.UpdateUser(context.Background(), user.ID, map[string]any{"status": "deactivated"}))

	_, access, refresh, err := svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountNotActive)
	assert.Empty(t, access, "no access token must be minted for a deactivated user")
	assert.Empty(t, refresh, "no refresh token must be minted for a deactivated user")
}

func TestRefreshToken_LockedUser_Rejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "locked@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)

	user, err := repo.FindUserByEmail(context.Background(), "locked@example.com")
	require.NoError(t, err)
	require.NoError(t, repo.UpdateUser(context.Background(), user.ID, map[string]any{
		"locked_until": svc.nowMs() + 60_000,
	}))

	_, access, _, err := svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountLocked)
	assert.Empty(t, access, "no access token must be minted for a locked user")
}

// ── mode=session opt-in ────────────────────────────────────────────────

func newSessionModeService(t *testing.T, repo *fakeRepo) *AuthService {
	t.Helper()
	svc := newTestAuthService(t, repo)
	svc.cfg.RevocationMode = config.RevocationModeSession
	return svc
}

func TestModeSession_IssueTokens_MintsSessionAndEmbedsSID(t *testing.T) {
	repo := newFakeRepo()
	svc := newSessionModeService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "sess@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)

	claims, err := jwt.VerifyAccessToken(result.AccessToken, svc.signer, "", "", false)
	require.NoError(t, err)
	require.NotEmpty(t, claims.SID, "session mode must put a sid on the access token")

	rec, err := repo.GetSessionBySid(context.Background(), claims.SID)
	require.NoError(t, err)
	require.NotNil(t, rec, "session row must exist for the embedded sid")
	assert.Equal(t, claims.Sub, rec.UserID)
	assert.Zero(t, rec.RevokedAtMs, "fresh session must not be revoked")
}

func TestModeSession_RefreshRotatesSID(t *testing.T) {
	repo := newFakeRepo()
	svc := newSessionModeService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "sess-rot@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)

	originalClaims, err := jwt.VerifyAccessToken(result.AccessToken, svc.signer, "", "", false)
	require.NoError(t, err)

	_, newAccess, _, err := svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.NoError(t, err)

	newClaims, err := jwt.VerifyAccessToken(newAccess, svc.signer, "", "", false)
	require.NoError(t, err)
	assert.NotEqual(t, originalClaims.SID, newClaims.SID, "refresh must mint a fresh sid")

	// Both sessions exist; both are active until RevokeSession or expiry.
	old, err := repo.GetSessionBySid(context.Background(), originalClaims.SID)
	require.NoError(t, err)
	require.NotNil(t, old)
	assert.Zero(t, old.RevokedAtMs)
}

func TestModeSession_RefreshReplayRevokesAllSessions(t *testing.T) {
	// In mode=session, a refresh-token replay must also revoke the
	// access tokens. The conformance suite already covers the
	// DeleteRefreshTokensForUser path; this test confirms the
	// session-revocation hook fires from the replay branch.
	repo := newFakeRepo()
	svc := newSessionModeService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "sess-replay@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)

	// First refresh consumes the original token.
	_, _, _, err = svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.NoError(t, err)

	// Replay: the same refresh token must trigger the replay branch.
	_, _, _, err = svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))

	// All sessions for the user must be revoked.
	user, err := repo.FindUserByEmail(context.Background(), "sess-replay@example.com")
	require.NoError(t, err)
	require.NotNil(t, user)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	for _, s := range repo.sessions {
		if s.UserID != user.ID {
			continue
		}
		assert.NotZero(t, s.RevokedAtMs, "session %s for replay user must be revoked", s.SID)
	}
}

// Logout must kill the access session too: an explicitly logged-out user must
// not keep a working access token until its natural (uncapped in mode=session)
// expiry.
func TestModeSession_Logout_RevokesAccessSession(t *testing.T) {
	repo := newFakeRepo()
	svc := newSessionModeService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "sess-logout@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)

	claims, err := jwt.VerifyAccessToken(result.AccessToken, svc.signer, "", "", false)
	require.NoError(t, err)
	require.NotEmpty(t, claims.SID)

	require.NoError(t, svc.Logout(context.Background(), result.RefreshToken))

	rec, err := repo.GetSessionBySid(context.Background(), claims.SID)
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.NotZero(t, rec.RevokedAtMs, "logout must revoke the matching access session in mode=session")
}

func TestModeTTL_Logout_LeavesSessionStoreUntouched(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "ttl-logout@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	require.NoError(t, svc.Logout(context.Background(), result.RefreshToken))

	repo.mu.Lock()
	n := len(repo.sessions)
	repo.mu.Unlock()
	assert.Zero(t, n, "ttl mode must not create or touch session rows on logout")
}

// The natural-expiry cleanup must kill the access session too — a deployer may
// set the JWT expiry longer than the refresh TTL in mode=session, so the
// access session must die with the refresh token.
func TestModeSession_ExpiredRefreshToken_RevokesAccessSession(t *testing.T) {
	repo := newFakeRepo()
	svc := newSessionModeService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "sess-exp@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	claims, err := jwt.VerifyAccessToken(result.AccessToken, svc.signer, "", "", false)
	require.NoError(t, err)

	// Age the refresh row past its natural expiry.
	repo.mu.Lock()
	for _, rt := range repo.refreshTokens {
		rt.ExpiresAt = 1
	}
	repo.mu.Unlock()

	_, _, _, err = svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTokenExpired))

	rec, err := repo.GetSessionBySid(context.Background(), claims.SID)
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.NotZero(t, rec.RevokedAtMs, "expired-refresh cleanup must revoke the matching access session")
}

// A refresh row written before the sid link existed carries an empty sid, so
// the scoped revoke is impossible; the helper must fail closed by falling back
// to the user-scoped revoke — without touching other users' sessions.
func TestModeSession_LegacyRowWithoutSID_FallsBackToUserScopedRevoke(t *testing.T) {
	repo := newFakeRepo()
	svc := newSessionModeService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "sess-legacy@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	user, err := repo.FindUserByEmail(context.Background(), "sess-legacy@example.com")
	require.NoError(t, err)
	require.NotNil(t, user)

	// A bystander's session must survive the user-scoped fallback.
	_, err = repo.CreateSession(context.Background(), &SessionRecord{
		SID: "bystander-sid", UserID: "bystander-user", CreatedAtMs: 1,
	})
	require.NoError(t, err)

	// Simulate a pre-migration row: strip the sid link and age it past expiry.
	repo.mu.Lock()
	for _, rt := range repo.refreshTokens {
		if rt.UserID == user.ID {
			rt.SID = ""
			rt.ExpiresAt = 1
		}
	}
	repo.mu.Unlock()

	_, _, _, err = svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTokenExpired))

	repo.mu.Lock()
	defer repo.mu.Unlock()
	for _, s := range repo.sessions {
		switch s.UserID {
		case user.ID:
			assert.NotZero(t, s.RevokedAtMs, "a legacy-row breach must revoke the user's sessions (fail closed)")
		case "bystander-user":
			assert.Zero(t, s.RevokedAtMs, "another user's session must be untouched")
		}
	}
}

func TestModeSession_PasswordReset_RevokesSessions(t *testing.T) {
	// Credential change must force re-auth; in mode=session that
	// includes the access tokens.
	repo := newFakeRepo()
	svc := newSessionModeService(t, repo)

	_, err := svc.PasswordSignup(context.Background(), "sess-reset@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)

	user, err := repo.FindUserByEmail(context.Background(), "sess-reset@example.com")
	require.NoError(t, err)

	// Issue the reset and confirm.
	require.NoError(t, svc.RequestPasswordReset(context.Background(), "sess-reset@example.com", EmailLinkParams{}))

	// Find the issued reset token (test repo only).
	repo.mu.Lock()
	var rawHash string
	for _, t := range repo.passwordResets {
		rawHash = t.TokenHash
	}
	repo.mu.Unlock()
	require.NotEmpty(t, rawHash, "no password reset token issued")

	// ConfirmPasswordReset takes the raw token. The reset email contains
	// the raw token; tests stub by injecting a known token directly.
	repo.mu.Lock()
	freshToken := "test-raw-reset"
	newHash := hashRefreshToken(freshToken)
	for nodeID, t := range repo.passwordResets {
		newTok := *t
		newTok.TokenHash = newHash
		repo.passwordResets[nodeID] = &newTok
	}
	repo.mu.Unlock()

	require.NoError(t, svc.ConfirmPasswordReset(context.Background(), freshToken, strongPW+"-2!Aa"))

	repo.mu.Lock()
	defer repo.mu.Unlock()
	for _, s := range repo.sessions {
		if s.UserID != user.ID {
			continue
		}
		assert.NotZero(t, s.RevokedAtMs, "session %s must be revoked after password reset", s.SID)
	}
}

func TestConfig_Validate_TTLCapEnforced(t *testing.T) {
	cfg := testConfig()
	cfg.JWTExpirySeconds = 1800 // 30 minutes
	cfg.RevocationMode = config.RevocationModeTTL
	err := cfg.Validate()
	require.Error(t, err, "Validate must reject 30-minute access tokens in mode=ttl")
	assert.Contains(t, err.Error(), "GATEWAY_JWT_EXPIRY_SECONDS")
}

func TestConfig_Validate_TTLCapAtBoundary(t *testing.T) {
	cfg := testConfig()
	cfg.JWTExpirySeconds = 900
	cfg.RevocationMode = config.RevocationModeTTL
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_SessionModeAllowsLongerTTL(t *testing.T) {
	cfg := testConfig()
	cfg.JWTExpirySeconds = 3600 // 1 hour
	cfg.RevocationMode = config.RevocationModeSession
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_UnknownMode(t *testing.T) {
	cfg := testConfig()
	cfg.RevocationMode = "bogus"
	require.Error(t, cfg.Validate())
}

// TestModeSession_IssueTokens_CreateSessionError covers the error
// path on the session-mint side: a transient CreateSession failure
// fails the whole token-issue path so we never hand the client an
// access token whose sid has no backing row.
func TestModeSession_IssueTokens_CreateSessionError(t *testing.T) {
	repo := newErrorRepo()
	svc := newTestAuthServiceErr(t, repo)
	svc.cfg.RevocationMode = config.RevocationModeSession
	repo.failCreateSession = true

	_, err := svc.PasswordSignup(context.Background(), "create-fail@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.Error(t, err)
}

// TestModeSession_RevokeFailureIsBestEffort: a RevokeSessionsForUser
// error is logged but does not propagate; the caller has already
// invalidated refresh tokens so the worst case is the access-token
// validity stretches to the cache TTL (not a complete bypass).
// Drives the failure path of revokeUserSessionsIfModeSession.
func TestModeSession_RevokeFailureIsBestEffort(t *testing.T) {
	repo := newErrorRepo()
	svc := newTestAuthServiceErr(t, repo)
	svc.cfg.RevocationMode = config.RevocationModeSession

	// Seed a user and a session.
	_, err := svc.PasswordSignup(context.Background(), "revoke-fail@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	user, err := repo.FindUserByEmail(context.Background(), "revoke-fail@example.com")
	require.NoError(t, err)
	require.NotNil(t, user)

	repo.failRevokeSessionsForUser = true
	// Calling the helper directly (it's lower-case but reachable inside
	// the package). A logged failure must not panic or propagate.
	svc.revokeUserSessionsIfModeSession(context.Background(), user.ID, "test")
}

// ── mode=session: a refresh refused over the account's state ──────────

// openSession issues a mode=session token pair for user and returns the
// refresh token and the sid its access token carries.
func openSession(t *testing.T, svc *AuthService, user *User) (string, string) {
	t.Helper()
	access, refresh, err := svc.issueTokens(context.Background(), user, "", "")
	require.NoError(t, err)
	claims, err := jwt.VerifyAccessToken(access, svc.signer, "", "", false)
	require.NoError(t, err)
	require.NotEmpty(t, claims.SID)
	return refresh, claims.SID
}

func sessionRevoked(t *testing.T, repo Repository, sid string) bool {
	t.Helper()
	rec, err := repo.GetSessionBySid(context.Background(), sid)
	require.NoError(t, err)
	require.NotNil(t, rec)
	return rec.RevokedAtMs != 0
}

// An account whose address became unverified is refused its refresh, and the
// access token issued alongside that refresh token stops working with it. The
// refresh token itself survives: it rotates into a new session once the
// address is proven.
func TestModeSession_RefreshRefusedForUnverifiedAddress_RevokesAccessSession(t *testing.T) {
	repo := newFakeRepo()
	svc := newSessionModeService(t, repo)
	ctx := context.Background()
	user := seedUser(repo, "unproven-later@example.com", "", StatusActive)
	user.EmailVerified = true
	refresh, sid := openSession(t, svc, user)

	svc.cfg.AuthRequireVerifiedEmail = true
	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"email_verified": false, "email_verified_at": int64(0)}))
	_, _, _, err := svc.RefreshToken(ctx, refresh, "", "")
	require.ErrorIs(t, err, ErrEmailVerificationRequired)
	assert.True(t, sessionRevoked(t, repo, sid), "the refused account's access session must end")

	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"email_verified": true, "email_verified_at": int64(1)}))
	_, access, _, err := svc.RefreshToken(ctx, refresh, "", "")
	require.NoError(t, err)
	claims, err := jwt.VerifyAccessToken(access, svc.signer, "", "", false)
	require.NoError(t, err)
	assert.False(t, sessionRevoked(t, repo, claims.SID), "the rotated session is live")
}

// An account that is no longer active is refused its refresh, and its access
// session ends with it.
func TestModeSession_RefreshRefusedForInactiveAccount_RevokesAccessSession(t *testing.T) {
	for _, status := range []string{"deactivated", "suspended", StatusInvited} {
		t.Run(status, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newSessionModeService(t, repo)
			ctx := context.Background()
			user := seedUser(repo, "inactive@example.com", "", StatusActive)
			refresh, sid := openSession(t, svc, user)

			require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"status": status}))
			_, _, _, err := svc.RefreshToken(ctx, refresh, "", "")
			require.Error(t, err)
			assert.True(t, sessionRevoked(t, repo, sid), "the refused account's access session must end")
		})
	}
}

// A refresh refused for a reason that says nothing against the account leaves
// its access session alone: a lockout (which anyone guessing at the password
// can trigger) and a failure of the store.
func TestModeSession_RefreshRefusedNotForAccountState_KeepsAccessSession(t *testing.T) {
	t.Run("locked", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newSessionModeService(t, repo)
		ctx := context.Background()
		user := seedUser(repo, "locked-out@example.com", "", StatusActive)
		refresh, sid := openSession(t, svc, user)

		require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"locked_until": svc.nowMs() + 60_000}))
		_, _, _, err := svc.RefreshToken(ctx, refresh, "", "")
		require.ErrorIs(t, err, ErrAccountLocked)
		assert.False(t, sessionRevoked(t, repo, sid))
	})
	t.Run("store failure", func(t *testing.T) {
		repo := newErrorRepo()
		svc := newTestAuthServiceErr(t, repo)
		svc.cfg.RevocationMode = config.RevocationModeSession
		user := seedUser(repo.fakeRepo, "transient@example.com", "", StatusActive)
		refresh, sid := openSession(t, svc, user)

		repo.failConsumeRefreshToken = true
		_, _, _, err := svc.RefreshToken(context.Background(), refresh, "", "")
		require.Error(t, err)
		assert.False(t, sessionRevoked(t, repo, sid))
	})
}

// A lockout can be triggered by anyone guessing at the password, so a refresh
// refused over one must not cost the account anything: the client's retry is
// refused the same way rather than taken for a replay, none of the account's
// sessions or refresh tokens are revoked, and every one rotates normally once
// the lockout ends.
func TestModeSession_RefreshRefusedForLockout_KeepsTokenForRetry(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	svc.cfg.RevocationMode = config.RevocationModeSession
	ctx := context.Background()
	now := time.Now()
	svc.nowFunc = func() time.Time { return now }
	user := seedUser(repo, "guessed-at@example.com", "", StatusActive)
	refresh, sid := openSession(t, svc, user)
	otherRefresh, otherSid := openSession(t, svc, user)

	lockout := time.Minute
	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"locked_until": now.Add(lockout).UnixMilli()}))
	for range 3 {
		_, _, _, err := svc.RefreshToken(ctx, refresh, "", "")
		require.ErrorIs(t, err, ErrAccountLocked)
	}
	assert.Zero(t, writer.countByEventTypeAndDetail("login_failure", "reason", "refresh_token_replay"))
	assert.False(t, sessionRevoked(t, repo, sid))
	assert.False(t, sessionRevoked(t, repo, otherSid))

	now = now.Add(lockout + time.Second)
	for _, r := range []string{refresh, otherRefresh} {
		_, access, _, err := svc.RefreshToken(ctx, r, "", "")
		require.NoError(t, err)
		claims, err := jwt.VerifyAccessToken(access, svc.signer, "", "", false)
		require.NoError(t, err)
		assert.False(t, sessionRevoked(t, repo, claims.SID), "the rotated session is live")
	}
}
