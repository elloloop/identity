package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// TestSignOutEverywhere_RevokesSSOAndAccessSessions pins what the name of the
// RPC promises: after it, nothing the user was signed in with still works.
//
// Three stores have to be reached, and each was a separate way for the promise
// to be false — the refresh tokens (always revoked), the mode=session access
// sessions (revoked as of ADR-0014; previously an issued access token kept
// working to its natural expiry), and the browser's SSO sessions (which would
// otherwise silently mint a NEW session on the very next product visit, from
// the cookie the user just asked to be signed out of).
func TestSignOutEverywhere_RevokesSSOAndAccessSessions(t *testing.T) {
	const userID = "user-1"
	const password = "Str0ng!Pass"

	db := newFakeDB()
	pwHash, err := passwords.Hash(password)
	require.NoError(t, err)
	db.addUserWithPassword(userID, "alice@test.com", "Alice", "member", "active", pwHash)
	db.addRefreshToken("sess-1", userID, nowMs()+3600*1000)
	db.addRefreshToken("sess-2", userID, nowMs()+3600*1000)

	repo := newFakeRepo()
	ctx := context.Background()

	// Two browsers signed in, plus an access session for one of them.
	for _, hash := range []string{"sso-hash-a", "sso-hash-b"} {
		_, err := repo.CreateSSOSession(ctx, &SSOSessionRecord{
			TokenHash: hash, UserID: userID, LoginMethod: LoginMethodOAuth,
			CreatedAtMs: nowMs(), LastUsedAtMs: nowMs(), ExpiresAtMs: nowMs() + 3600*1000,
		})
		require.NoError(t, err)
	}
	_, err = repo.CreateSession(ctx, &SessionRecord{SID: "sid-1", UserID: userID, CreatedAtMs: nowMs()})
	require.NoError(t, err)

	// Another user's session must be left alone throughout.
	_, err = repo.CreateSSOSession(ctx, &SSOSessionRecord{
		TokenHash: "sso-hash-other", UserID: "user-2", LoginMethod: LoginMethodOAuth,
		CreatedAtMs: nowMs(), LastUsedAtMs: nowMs(), ExpiresAtMs: nowMs() + 3600*1000,
	})
	require.NoError(t, err)

	svc := NewProfileService(repo, db, "test-tenant",
		audit.NewLogger(&recordingAuditWriter{}, "test-tenant", nil), zap.NewNop())

	count, err := svc.RevokeAllSessions(ctx, userID, password)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "the count reported is the device sessions the user recognises")

	for _, hash := range []string{"sso-hash-a", "sso-hash-b"} {
		got, err := repo.FindSSOSessionByHash(ctx, hash)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.NotZero(t, got.RevokedAtMs, "SSO session %s survived sign-out-everywhere", hash)
		assert.False(t, got.Active(nowMs()), "revoked SSO session %s must not be usable", hash)
	}

	accessSession, err := repo.GetSessionBySid(ctx, "sid-1")
	require.NoError(t, err)
	require.NotNil(t, accessSession)
	assert.NotZero(t, accessSession.RevokedAtMs,
		"the mode=session access session must be revoked, or the access token outlives the sign-out")

	other, err := repo.FindSSOSessionByHash(ctx, "sso-hash-other")
	require.NoError(t, err)
	require.NotNil(t, other)
	assert.Zero(t, other.RevokedAtMs, "another user's SSO session must be untouched")
}

// A credential change forces re-auth everywhere, which must include the
// browser SSO sessions — otherwise changing a compromised password leaves the
// attacker's browser able to keep minting product sessions.
func TestChangePassword_RevokesSSOSessions(t *testing.T) {
	const userID = "user-1"
	const oldPassword = "Str0ng!Pass"

	db := newFakeDB()
	pwHash, err := passwords.Hash(oldPassword)
	require.NoError(t, err)
	db.addUserWithPassword(userID, "alice@test.com", "Alice", "member", "active", pwHash)

	repo := newFakeRepo()
	ctx := context.Background()
	_, err = repo.CreateSSOSession(ctx, &SSOSessionRecord{
		TokenHash: "sso-hash", UserID: userID, LoginMethod: LoginMethodPassword,
		CreatedAtMs: nowMs(), LastUsedAtMs: nowMs(), ExpiresAtMs: nowMs() + 3600*1000,
	})
	require.NoError(t, err)

	svc := NewProfileService(repo, db, "test-tenant",
		audit.NewLogger(&recordingAuditWriter{}, "test-tenant", nil), zap.NewNop())

	require.NoError(t, svc.ChangePassword(ctx, userID, oldPassword, "N3w!Str0ngPass"))

	got, err := repo.FindSSOSessionByHash(ctx, "sso-hash")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.NotZero(t, got.RevokedAtMs, "a password change must end the browser's SSO session")
}
