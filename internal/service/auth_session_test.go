package service

import (
	"context"
	"errors"
	"testing"

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

	result, err := svc.PasswordSignup(context.Background(), "ttl@example.com", strongPW, "", "")
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

	result, err := svc.PasswordSignup(context.Background(), "ttl-revoke@example.com", strongPW, "", "")
	require.NoError(t, err)

	user, err := repo.FindUserByEmail(context.Background(), "ttl-revoke@example.com")
	require.NoError(t, err)
	require.NotNil(t, user)

	require.NoError(t, repo.DeleteRefreshTokensForUser(context.Background(), user.ID))

	// Access token: still verifiable against the same key ring.
	_, err = jwt.VerifyAccessToken(result.AccessToken, svc.signer, "", "", false)
	assert.NoError(t, err, "in-flight access token must verify in mode=ttl after refresh revocation")
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

	result, err := svc.PasswordSignup(context.Background(), "sess@example.com", strongPW, "", "")
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

	result, err := svc.PasswordSignup(context.Background(), "sess-rot@example.com", strongPW, "", "")
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

	result, err := svc.PasswordSignup(context.Background(), "sess-replay@example.com", strongPW, "", "")
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

func TestModeSession_PasswordReset_RevokesSessions(t *testing.T) {
	// Credential change must force re-auth; in mode=session that
	// includes the access tokens.
	repo := newFakeRepo()
	svc := newSessionModeService(t, repo)

	_, err := svc.PasswordSignup(context.Background(), "sess-reset@example.com", strongPW, "", "")
	require.NoError(t, err)

	user, err := repo.FindUserByEmail(context.Background(), "sess-reset@example.com")
	require.NoError(t, err)

	// Issue the reset and confirm.
	require.NoError(t, svc.RequestPasswordReset(context.Background(), "sess-reset@example.com"))

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
