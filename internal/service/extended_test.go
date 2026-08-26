// Extended tests targeting low-coverage branches in internal/service.
//
// These tests focus on error paths, edge cases, and code paths not covered
// by the original happy-path tests. They use the existing fakeRepo / fakeDB
// helpers from testutil_test.go and fakedb_test.go.
package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp"
	otptotp "github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/graph"

	"github.com/elloloop/identity/pkg/passwords"
	"github.com/elloloop/identity/pkg/secretcrypto"
)

// ── PasswordSignup edge cases ──────────────────────────────────────────

func TestPasswordSignup_EmptyPasswordFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.PasswordSignup(context.Background(), "alice@example.com", "", "", "", 0, "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestPasswordSignup_DefaultDisplayNameFromEmail(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "rosa@example.com", strongPW, "", "rec@example.com", 0, "")
	require.NoError(t, err)
	assert.Equal(t, "rosa", result.User.Name)
}

// ── PasswordLogin edge cases ───────────────────────────────────────────

func TestPasswordLogin_LocalDisabled(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.AuthAllowLocal = false

	_, err := svc.PasswordLogin(context.Background(), "x@example.com", "anything", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrLocalAuthDisabled))
}

func TestPasswordLogin_InvalidEmailFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.PasswordLogin(context.Background(), "not-an-email@", strongPW, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestPasswordLogin_BareIdentifierTreatedAsUsername(t *testing.T) {
	// An identifier without '@' is a managed-child USERNAME candidate. An
	// unknown one — or a syntactically impossible one — gets the same uniform
	// invalid-credentials refusal as an unknown email, never a format error:
	// the response must not vary with whether an account exists.
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	for _, identifier := range []string{"nosuchuser", "!!bad!!"} {
		_, err := svc.PasswordLogin(context.Background(), identifier, strongPW, "", "")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrUnauthenticated), "identifier %q: %v", identifier, err)
	}
}

func TestPasswordLogin_EmptyPasswordFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.PasswordLogin(context.Background(), "x@example.com", "", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestPasswordLogin_LockedExpiredAllowsLogin(t *testing.T) {
	// LockedUntil in the past should NOT block login.
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	u := seedUser(repo, "expired-lock@example.com", pwHash, "active")
	repo.mu.Lock()
	u.LockedUntil = time.Now().Add(-time.Hour).UnixMilli()
	repo.users[u.ID].LockedUntil = u.LockedUntil
	repo.mu.Unlock()

	result, err := svc.PasswordLogin(context.Background(), "expired-lock@example.com", strongPW, "", "")
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestPasswordLogin_ResetsFailedCount(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	u := seedUser(repo, "reset-fail@example.com", pwHash, "active")

	// Set some failed attempts.
	repo.mu.Lock()
	repo.users[u.ID].FailedLoginCount = 2
	repo.mu.Unlock()

	_, err := svc.PasswordLogin(context.Background(), "reset-fail@example.com", strongPW, "", "")
	require.NoError(t, err)

	// Counter should reset.
	repo.mu.Lock()
	count := repo.users[u.ID].FailedLoginCount
	repo.mu.Unlock()
	assert.Equal(t, 0, count)
}

// ── OAuthLogin edge cases ─────────────────────────────────────────────

func TestOAuthLogin_EmptyCodeFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: "", Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "", UserAgent: ""})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestOAuthLogin_DefaultsDisplayNameFromEmail(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	code := fakeOAuthCode("carol@example.com", "", "", "google")
	result, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: code, Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "", UserAgent: ""})
	require.NoError(t, err)
	assert.Equal(t, "carol", result.User.Name)
}

func TestOAuthLogin_DeactivatedAccountFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	seedUser(repo, "deac-oauth@example.com", "", "deactivated")

	code := fakeOAuthCode("deac-oauth@example.com", "X", "", "google")
	_, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: code, Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "", UserAgent: ""})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAccountNotActive))
}

func TestOAuthLogin_ExistingUserNoNameChangeNoUpdate(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	seedUser(repo, "noupd@example.com", "", "active")

	// Same display name and no avatar -- no patch should happen, but call must succeed.
	code := fakeOAuthCode("noupd@example.com", "noupd", "", "google")
	_, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: code, Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "", UserAgent: ""})
	require.NoError(t, err)
}

// ── AcceptInvitation edge cases ────────────────────────────────────────

func TestAcceptInvitation_MissingTokenFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.AcceptInvitation(context.Background(), "", strongPW, "", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestAcceptInvitation_MissingPasswordFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.AcceptInvitation(context.Background(), "tok", "", "", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestAcceptInvitation_WeakPasswordFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.AcceptInvitation(context.Background(), "tok", "weak", "", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrWeakPassword))
}

func TestAcceptInvitation_UnknownTokenFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.AcceptInvitation(context.Background(), "no-such-token", strongPW, "", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestAcceptInvitation_UserMissingFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	rawToken := "orphan-token"
	tokenHash := hashInvitationToken(rawToken)
	seedInvitation(repo, &InvitationRecord{
		TokenHash: tokenHash,
		Email:     "ghost@example.com",
		UserID:    "nonexistent-id",
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})

	_, err := svc.AcceptInvitation(context.Background(), rawToken, strongPW, "", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

func TestAcceptInvitation_FoundByEmailWhenUserIDMissing(t *testing.T) {
	// Invitation has no UserID, but email lookup should find the user.
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	seedUser(repo, "by-email@example.com", "", "invited")

	rawToken := "by-email-token"
	tokenHash := hashInvitationToken(rawToken)
	seedInvitation(repo, &InvitationRecord{
		TokenHash: tokenHash,
		Email:     "by-email@example.com",
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})

	result, err := svc.AcceptInvitation(context.Background(), rawToken, strongPW, "Updated Name", "", "")
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", result.User.Name)
	assert.Equal(t, "active", result.User.Status)
}

// ── RefreshToken edge cases ────────────────────────────────────────────

func TestRefreshToken_MissingTokenFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, _, _, err := svc.RefreshToken(context.Background(), "", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestRefreshToken_UserDeletedFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "deleted@example.com", strongPW, "", "", 0, "")
	require.NoError(t, err)

	// Delete the user node directly while the refresh token still exists.
	repo.mu.Lock()
	delete(repo.users, result.User.ID)
	repo.mu.Unlock()

	_, _, _, err = svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

// ── GetCurrentUser ─────────────────────────────────────────────────────

func TestGetCurrentUser_EmptyIDFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.GetCurrentUser(context.Background(), "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

// ── Logout edge case ───────────────────────────────────────────────────

func TestLogout_UnknownTokenIsNoop(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	err := svc.Logout(context.Background(), "no-such-token")
	require.NoError(t, err)
}

// ── BeginPasskeyRegistration edge cases ────────────────────────────────

func TestBeginPasskeyRegistration_UserNotFound(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, _, err := svc.BeginPasskeyRegistration(context.Background(), "no-such-user", "Key")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

func TestBeginPasskeyRegistration_WithExistingCreds(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "pkreg@example.com", "", "active")

	repo.mu.Lock()
	id := nextNodeID()
	repo.passkeyCreds[id] = &PasskeyCredRecord{
		NodeID:       id,
		CredentialID: "existing-cred-1",
		UserID:       u.ID,
	}
	repo.mu.Unlock()

	optionsJSON, challengeID, err := svc.BeginPasskeyRegistration(context.Background(), u.ID, "Key")
	require.NoError(t, err)
	assert.NotEmpty(t, optionsJSON)
	assert.NotEmpty(t, challengeID)
}

// ── CompletePasskeyRegistration ────────────────────────────────────────

func TestCompletePasskeyRegistration_MissingArgs(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, _, err := svc.CompletePasskeyRegistration(context.Background(), "user-1", "", "", "Device", false, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestCompletePasskeyRegistration_ChallengeNotFound(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, _, err := svc.CompletePasskeyRegistration(context.Background(), "user-1", "no-such-challenge", "{}", "Device", false, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

func TestCompletePasskeyRegistration_WrongChallengeType(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	repo.mu.Lock()
	id := nextNodeID()
	repo.passkeyChallenges[id] = &PasskeyChallengeRecord{
		NodeID:        id,
		Challenge:     "challenge-bytes",
		UserID:        "user-1",
		ChallengeType: "authentication",
		ExpiresAt:     time.Now().Add(time.Hour).UnixMilli(),
	}
	repo.mu.Unlock()

	_, _, err := svc.CompletePasskeyRegistration(context.Background(), "user-1", id, "{}", "Device", false, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestCompletePasskeyRegistration_WrongUser(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	repo.mu.Lock()
	id := nextNodeID()
	repo.passkeyChallenges[id] = &PasskeyChallengeRecord{
		NodeID:        id,
		Challenge:     "challenge-bytes",
		UserID:        "user-1",
		ChallengeType: "registration",
		ExpiresAt:     time.Now().Add(time.Hour).UnixMilli(),
	}
	repo.mu.Unlock()

	_, _, err := svc.CompletePasskeyRegistration(context.Background(), "user-2", id, "{}", "Device", false, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPermissionDenied))
}

func TestCompletePasskeyRegistration_ExpiredChallenge(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	repo.mu.Lock()
	id := nextNodeID()
	repo.passkeyChallenges[id] = &PasskeyChallengeRecord{
		NodeID:        id,
		Challenge:     "challenge-bytes",
		UserID:        "user-1",
		ChallengeType: "registration",
		ExpiresAt:     time.Now().Add(-time.Hour).UnixMilli(),
	}
	repo.mu.Unlock()

	_, _, err := svc.CompletePasskeyRegistration(context.Background(), "user-1", id, "{}", "Device", false, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTokenExpired))
}

func TestCompletePasskeyRegistration_VerifyFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	repo.mu.Lock()
	id := nextNodeID()
	repo.passkeyChallenges[id] = &PasskeyChallengeRecord{
		NodeID:        id,
		Challenge:     "valid-challenge",
		UserID:        "user-1",
		ChallengeType: "registration",
		ExpiresAt:     time.Now().Add(time.Hour).UnixMilli(),
	}
	repo.mu.Unlock()

	// Bogus credential JSON — verification will fail.
	_, _, err := svc.CompletePasskeyRegistration(context.Background(), "user-1", id, `{"id":"x"}`, "Device", false, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

// ── CompletePasskeyLogin ───────────────────────────────────────────────

func TestCompletePasskeyLogin_MissingArgs(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.CompletePasskeyLogin(context.Background(), "", "", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestCompletePasskeyLogin_ChallengeNotFound(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.CompletePasskeyLogin(context.Background(), "no-such", "{}", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestCompletePasskeyLogin_WrongChallengeType(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	repo.mu.Lock()
	id := nextNodeID()
	repo.passkeyChallenges[id] = &PasskeyChallengeRecord{
		NodeID:        id,
		Challenge:     "x",
		ChallengeType: "registration",
		ExpiresAt:     time.Now().Add(time.Hour).UnixMilli(),
	}
	repo.mu.Unlock()

	_, err := svc.CompletePasskeyLogin(context.Background(), id, "{}", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestCompletePasskeyLogin_ExpiredChallenge(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	repo.mu.Lock()
	id := nextNodeID()
	repo.passkeyChallenges[id] = &PasskeyChallengeRecord{
		NodeID:        id,
		Challenge:     "x",
		ChallengeType: "authentication",
		ExpiresAt:     time.Now().Add(-time.Hour).UnixMilli(),
	}
	repo.mu.Unlock()

	_, err := svc.CompletePasskeyLogin(context.Background(), id, "{}", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestCompletePasskeyLogin_BadCredentialJSON(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	repo.mu.Lock()
	id := nextNodeID()
	repo.passkeyChallenges[id] = &PasskeyChallengeRecord{
		NodeID:        id,
		Challenge:     "x",
		ChallengeType: "authentication",
		ExpiresAt:     time.Now().Add(time.Hour).UnixMilli(),
	}
	repo.mu.Unlock()

	_, err := svc.CompletePasskeyLogin(context.Background(), id, "not-json", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

// ── BeginPasskeyLogin email branches ───────────────────────────────────

func TestBeginPasskeyLogin_EmailWithCreds(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "withpk@example.com", "", "active")

	repo.mu.Lock()
	id := nextNodeID()
	repo.passkeyCreds[id] = &PasskeyCredRecord{
		NodeID: id, UserID: u.ID, CredentialID: "abc",
	}
	repo.mu.Unlock()

	options, challengeID, err := svc.BeginPasskeyLogin(context.Background(), "withpk@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, options)
	assert.NotEmpty(t, challengeID)
}

func TestBeginPasskeyLogin_UnknownEmailDoesNotEnumerate(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	options, challengeID, err := svc.BeginPasskeyLogin(context.Background(), "ghost@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, options)
	assert.NotEmpty(t, challengeID)
}

// ── BeginTotpSetup edge cases ──────────────────────────────────────────

func TestBeginTotpSetup_UserNotFound(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, _, _, err := svc.BeginTotpSetup(context.Background(), "no-such")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

func TestBeginTotpSetup_CleansUnverifiedCred(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "totp-clean@example.com", "", "active")

	// Add an unverified credential.
	repo.mu.Lock()
	id := nextNodeID()
	repo.totpCreds[id] = &TotpCredRecord{
		NodeID: id, UserID: u.ID, Verified: false,
	}
	repo.mu.Unlock()

	_, _, _, err := svc.BeginTotpSetup(context.Background(), u.ID)
	require.NoError(t, err)

	// The unverified credential should be replaced.
	repo.mu.Lock()
	_, exists := repo.totpCreds[id]
	repo.mu.Unlock()
	assert.False(t, exists, "old unverified cred should be deleted")
}

func TestBeginTotpSetup_UserWithoutEmailUsesID(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "", "", "active")

	_, qrURI, _, err := svc.BeginTotpSetup(context.Background(), u.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, qrURI)
}

// ── VerifyTotpSetup edge cases ─────────────────────────────────────────

func TestVerifyTotpSetup_EmptyCode(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	ok, err := svc.VerifyTotpSetup(context.Background(), "user-1", "")
	require.Error(t, err)
	assert.False(t, ok)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestVerifyTotpSetup_NoSetupInProgress(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	ok, err := svc.VerifyTotpSetup(context.Background(), "no-cred-user", "123456")
	require.Error(t, err)
	assert.False(t, ok)
	assert.True(t, errors.Is(err, ErrNotFound))
}

func TestVerifyTotpSetup_DecryptFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "decrypt-fail@example.com", "", "active")

	repo.mu.Lock()
	id := nextNodeID()
	repo.totpCreds[id] = &TotpCredRecord{
		NodeID: id, UserID: u.ID, SecretEncrypted: "garbage",
	}
	repo.mu.Unlock()

	ok, err := svc.VerifyTotpSetup(context.Background(), u.ID, "123456")
	require.Error(t, err)
	assert.False(t, ok)
}

func TestVerifyTotpSetup_HappyPath(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "verify-ok@example.com", "", "active")

	secret := "JBSWY3DPEHPK3PXP" // #nosec G101 -- deterministic TOTP test vector.
	encrypted, err := secretcrypto.Encrypt(secret, testTotpKey())
	require.NoError(t, err)

	repo.mu.Lock()
	id := nextNodeID()
	repo.totpCreds[id] = &TotpCredRecord{
		NodeID: id, UserID: u.ID, SecretEncrypted: encrypted,
	}
	repo.mu.Unlock()

	// Generate a current TOTP code from the secret.
	code, err := totpGenerateCode(secret)
	require.NoError(t, err)

	ok, err := svc.VerifyTotpSetup(context.Background(), u.ID, code)
	require.NoError(t, err)
	assert.True(t, ok)

	// Verified flag and totp_required should both be true now.
	repo.mu.Lock()
	cred := repo.totpCreds[id]
	user := repo.users[u.ID]
	repo.mu.Unlock()
	assert.True(t, cred.Verified)
	assert.True(t, user.TotpRequired)
}

// ── VerifyTotp edge cases ──────────────────────────────────────────────

func TestVerifyTotp_MissingChallengeID(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.VerifyTotp(context.Background(), "", "123456", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestVerifyTotp_MissingCode(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.VerifyTotp(context.Background(), "challenge", "", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestVerifyTotp_InvalidChallenge(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.VerifyTotp(context.Background(), "no-such", "123456", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestVerifyTotp_ExpiredChallenge(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	cid := "stale-challenge"
	repo.mu.Lock()
	nid := nextNodeID()
	repo.loginChallenges[nid] = &LoginChallengeRecord{
		NodeID: nid, ChallengeID: cid, UserID: "u",
		ExpiresAt: time.Now().Add(-time.Hour).UnixMilli(),
	}
	repo.mu.Unlock()

	_, err := svc.VerifyTotp(context.Background(), cid, "123456", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestVerifyTotp_NoTotpEnabled(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "no-totp@example.com", "", "active")

	cid := "challenge-no-totp"
	repo.mu.Lock()
	nid := nextNodeID()
	repo.loginChallenges[nid] = &LoginChallengeRecord{
		NodeID: nid, ChallengeID: cid, UserID: u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	}
	repo.mu.Unlock()

	_, err := svc.VerifyTotp(context.Background(), cid, "123456", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

func TestVerifyTotp_InvalidCode(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "wrong-totp@example.com", "", "active")

	encrypted, err := secretcrypto.Encrypt("JBSWY3DPEHPK3PXP", testTotpKey())
	require.NoError(t, err)
	repo.mu.Lock()
	credID := nextNodeID()
	repo.totpCreds[credID] = &TotpCredRecord{
		NodeID: credID, UserID: u.ID, SecretEncrypted: encrypted, Verified: true,
	}
	cid := "wrong-challenge"
	nid := nextNodeID()
	repo.loginChallenges[nid] = &LoginChallengeRecord{
		NodeID: nid, ChallengeID: cid, UserID: u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	}
	repo.mu.Unlock()

	_, err = svc.VerifyTotp(context.Background(), cid, "000000", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidTotpCode))
}

func TestVerifyTotp_TotpHappyPath(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "totpok@example.com", "", "active")

	secret := "JBSWY3DPEHPK3PXP" // #nosec G101 -- deterministic TOTP test vector.
	encrypted, err := secretcrypto.Encrypt(secret, testTotpKey())
	require.NoError(t, err)
	repo.mu.Lock()
	credID := nextNodeID()
	repo.totpCreds[credID] = &TotpCredRecord{
		NodeID: credID, UserID: u.ID, SecretEncrypted: encrypted, Verified: true,
	}
	cid := "totpok-challenge"
	nid := nextNodeID()
	repo.loginChallenges[nid] = &LoginChallengeRecord{
		NodeID: nid, ChallengeID: cid, UserID: u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	}
	repo.mu.Unlock()

	code, err := totpGenerateCode(secret)
	require.NoError(t, err)

	result, err := svc.VerifyTotp(context.Background(), cid, code, "1.2.3.4", "Agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.AccessToken)
}

// ── DisableTotp edge cases ─────────────────────────────────────────────

func TestDisableTotp_EmptyPassword(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	err := svc.DisableTotp(context.Background(), "u", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestDisableTotp_UserNotFound(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	err := svc.DisableTotp(context.Background(), "no-user", "any")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

func TestDisableTotp_NoPasswordSet(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "nopw@example.com", "", "active")

	err := svc.DisableTotp(context.Background(), u.ID, "anything")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

// ── RegenerateRecoveryCodes edge cases ─────────────────────────────────

func TestRegenerateRecoveryCodes_EmptyPassword(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.RegenerateRecoveryCodes(context.Background(), "u", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestRegenerateRecoveryCodes_UserNotFound(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.RegenerateRecoveryCodes(context.Background(), "no-user", "x")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

func TestRegenerateRecoveryCodes_NoPasswordSet(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "rc-nopw@example.com", "", "active")

	_, err := svc.RegenerateRecoveryCodes(context.Background(), u.ID, "x")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

// ── QR login extended ──────────────────────────────────────────────────

func TestInitiateQrLogin_LongUserAgentTruncated(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	ua := make([]byte, 1000)
	for i := range ua {
		ua[i] = 'A'
	}
	init, err := svc.InitiateQrLogin(context.Background(), "Phone", string(ua), "")
	require.NoError(t, err)
	assert.NotEmpty(t, init.SessionID)
}

func TestGetQrLoginSession_EmptyID(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.GetQrLoginSession(context.Background(), "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestGetQrLoginSession_NotFound(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.GetQrLoginSession(context.Background(), "ghost")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

func TestGetQrLoginSession_ExpiresPending(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	init, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.NoError(t, err)
	svc.nowFunc = func() time.Time { return time.Now().Add(time.Hour) }

	info, err := svc.GetQrLoginSession(context.Background(), init.SessionID)
	require.NoError(t, err)
	assert.Equal(t, "expired", info.Status)
}

func TestApproveQrLogin_EmptyID(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.ApproveQrLogin(context.Background(), "", true, "u", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestApproveQrLogin_NotFound(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.ApproveQrLogin(context.Background(), "ghost", true, "u", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

func TestApproveQrLogin_ExpiredPending(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	init, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.NoError(t, err)
	svc.nowFunc = func() time.Time { return time.Now().Add(time.Hour) }

	_, err = svc.ApproveQrLogin(context.Background(), init.SessionID, true, "u", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrQrLoginExpired))
}

func TestApproveQrLogin_AlreadyConsumed(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "qr-approved@example.com", "", "active")

	init, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.NoError(t, err)
	_, err = svc.ApproveQrLogin(context.Background(), init.SessionID, true, u.ID, "")
	require.NoError(t, err)

	// Approving twice should fail with ErrQrLoginNotPending.
	_, err = svc.ApproveQrLogin(context.Background(), init.SessionID, true, u.ID, "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrQrLoginNotPending))
}

func TestPollQrLogin_EmptyID(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.PollQrLogin(context.Background(), "", "anysecret", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestPollQrLogin_PendingReturnsPending(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	init, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.NoError(t, err)

	res, err := svc.PollQrLogin(context.Background(), init.SessionID, init.PollSecret, "", "")
	require.NoError(t, err)
	assert.Equal(t, "pending", res.Status)
}

func TestPollQrLogin_ApprovedWithoutUserFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	init, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.NoError(t, err)

	// Manipulate the session: status approved with empty user_id.
	repo.mu.Lock()
	for _, sess := range repo.qrSessions {
		if sess.SessionID == init.SessionID {
			sess.Status = "approved"
			sess.UserID = ""
		}
	}
	repo.mu.Unlock()

	_, err = svc.PollQrLogin(context.Background(), init.SessionID, init.PollSecret, "", "")
	require.Error(t, err)
}

func TestPollQrLogin_ApprovedUserDeleted(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "qr-deleted@example.com", "", "active")

	init, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.NoError(t, err)
	_, err = svc.ApproveQrLogin(context.Background(), init.SessionID, true, u.ID, "")
	require.NoError(t, err)

	repo.mu.Lock()
	delete(repo.users, u.ID)
	repo.mu.Unlock()

	_, err = svc.PollQrLogin(context.Background(), init.SessionID, init.PollSecret, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

// ── AdminService extended ──────────────────────────────────────────────

func TestAdminService_RequireAdmin_ActorMissing(t *testing.T) {
	db := newFakeDB()
	svc := newTestAdminService(db)

	_, err := svc.InviteUser(context.Background(), "ghost-actor", "x@example.com", "X", "member", "", 0, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "actor user not found")
}

func TestAdminService_InviteUser_InvalidRole(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newTestAdminService(db)

	_, err := svc.InviteUser(context.Background(), "admin-1", "x@test.com", "", "owner", "", 0, false)
	require.Error(t, err)
}

func TestAdminService_InviteUser_DefaultsRoleToMember(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newTestAdminService(db)

	res, err := svc.InviteUser(context.Background(), "admin-1", "rolemiss@test.com", "", "", "", 0, false)
	require.NoError(t, err)
	assert.Equal(t, "member", res.User.Role)
}

func TestAdminService_DeactivateUser_EmptyTarget(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newTestAdminService(db)

	err := svc.DeactivateUser(context.Background(), "admin-1", "", "")
	require.Error(t, err)
}

func TestAdminService_DeactivateUser_NotFound(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newTestAdminService(db)

	err := svc.DeactivateUser(context.Background(), "admin-1", "ghost", "")
	require.Error(t, err)
}

func TestAdminService_ReactivateUser_EmptyTarget(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newTestAdminService(db)

	err := svc.ReactivateUser(context.Background(), "admin-1", "")
	require.Error(t, err)
}

func TestAdminService_ReactivateUser_NotFound(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newTestAdminService(db)

	err := svc.ReactivateUser(context.Background(), "admin-1", "ghost")
	require.Error(t, err)
}

func TestAdminService_ResetUserPassword_EmptyTarget(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newTestAdminService(db)

	_, err := svc.ResetUserPassword(context.Background(), "admin-1", "", true)
	require.Error(t, err)
}

func TestAdminService_ResetUserPassword_NotFound(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newTestAdminService(db)

	_, err := svc.ResetUserPassword(context.Background(), "admin-1", "ghost", true)
	require.Error(t, err)
}

func TestAdminService_SetUserQuota_EmptyTarget(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newTestAdminService(db)

	err := svc.SetUserQuota(context.Background(), "admin-1", "", 100)
	require.Error(t, err)
}

func TestAdminService_SetUserQuota_NotFound(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newTestAdminService(db)

	err := svc.SetUserQuota(context.Background(), "admin-1", "ghost", 100)
	require.Error(t, err)
}

func TestAdminService_GetUser_NonAdmin(t *testing.T) {
	db := newFakeDB()
	db.addUser("member-1", "m@test.com", "M", "member", "active")
	svc := newTestAdminService(db)

	_, err := svc.GetUser(context.Background(), "member-1", "anyone")
	require.Error(t, err)
}

func TestAdminService_UpdateUser_NonAdmin(t *testing.T) {
	db := newFakeDB()
	db.addUser("member-1", "m@test.com", "M", "member", "active")
	svc := newTestAdminService(db)

	_, err := svc.UpdateUser(context.Background(), "member-1", "user-1", "Name", "", "")
	require.Error(t, err)
}

func TestAdminService_UpdateUser_EmptyID(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newTestAdminService(db)

	_, err := svc.UpdateUser(context.Background(), "admin-1", "", "N", "", "")
	require.Error(t, err)
}

func TestAdminService_UpdateUser_AvatarOnly(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.addUser("user-1", "u@test.com", "U", "member", "active")
	svc := newTestAdminService(db)

	user, err := svc.UpdateUser(context.Background(), "admin-1", "user-1", "", "", "https://x.example.com/p.png")
	require.NoError(t, err)
	assert.Equal(t, "https://x.example.com/p.png", user.AvatarURL)
}

func TestAdminService_ListUsers_NonAdminDenied(t *testing.T) {
	db := newFakeDB()
	db.addUser("member-1", "m@test.com", "M", "member", "active")
	svc := newTestAdminService(db)

	_, _, _, err := svc.ListUsers(context.Background(), "member-1", "", "", "", 50)
	require.Error(t, err)
}

func TestAdminService_ListUsers_Pagination(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	for i := 0; i < 5; i++ {
		db.addUser("u"+string(rune('0'+i)), "u"+string(rune('0'+i))+"@test.com", "U", "member", "active")
	}
	svc := newTestAdminService(db)

	users, cursor, total, err := svc.ListUsers(context.Background(), "admin-1", "", "", "", 2)
	require.NoError(t, err)
	assert.Len(t, users, 2)
	assert.NotEmpty(t, cursor)
	assert.GreaterOrEqual(t, total, 6)

	// Page 2.
	users2, _, _, err := svc.ListUsers(context.Background(), "admin-1", "", "", cursor, 2)
	require.NoError(t, err)
	assert.NotEmpty(t, users2)

	// limit 0 → defaults to 50.
	users3, _, _, err := svc.ListUsers(context.Background(), "admin-1", "", "", "", 0)
	require.NoError(t, err)
	assert.NotEmpty(t, users3)

	// limit > 500 → capped.
	users4, _, _, err := svc.ListUsers(context.Background(), "admin-1", "", "", "", 1000)
	require.NoError(t, err)
	assert.NotEmpty(t, users4)
}

func TestAdminService_ListUsers_SearchFilter(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.addUser("u1", "alice@test.com", "Alice", "member", "active")
	db.addUser("u2", "bob@test.com", "Bob", "member", "active")
	svc := newTestAdminService(db)

	users, _, _, err := svc.ListUsers(context.Background(), "admin-1", "", "alice", "", 50)
	require.NoError(t, err)
	assert.NotEmpty(t, users)
	for _, u := range users {
		// Either email or name should contain "alice".
		assert.Contains(t, u.Email+u.Name, "alice")
	}
}

// ── GroupService extended ──────────────────────────────────────────────

func TestGroupService_UpdateGroup_EmptyID(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	svc := newTestGroupService(db)

	_, err := svc.UpdateGroup(context.Background(), "admin-1", "", "n", "")
	require.Error(t, err)
}

func TestGroupService_UpdateGroup_DBErrorOnExecute(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	db.addGroup("grp-1", "G", "")
	svc := newTestGroupService(db)
	db.err = errors.New("boom")

	_, err := svc.UpdateGroup(context.Background(), "admin-1", "grp-1", "X", "")
	require.Error(t, err)
}

func TestGroupService_DeleteGroup_DBError(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	db.err = errors.New("boom")
	svc := newTestGroupService(db)

	err := svc.DeleteGroup(context.Background(), "admin-1", "grp-1")
	require.Error(t, err)
}

func TestGroupService_ListGroups_DefaultsLimit(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	for i := 0; i < 3; i++ {
		db.addGroup("g"+string(rune('0'+i)), "G", "")
	}
	svc := newTestGroupService(db)

	groups, _, err := svc.ListGroups(context.Background(), "admin-1", "", 0)
	require.NoError(t, err)
	assert.Len(t, groups, 3)
}

func TestGroupService_AddGroupMember_DBError(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	db.err = errors.New("boom")
	svc := newTestGroupService(db)

	err := svc.AddGroupMember(context.Background(), "admin-1", "g", "m")
	require.Error(t, err)
}

func TestGroupService_RemoveGroupMember_MissingIDs(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	svc := newTestGroupService(db)

	err := svc.RemoveGroupMember(context.Background(), "admin-1", "", "m")
	require.Error(t, err)
	err = svc.RemoveGroupMember(context.Background(), "admin-1", "g", "")
	require.Error(t, err)
}

func TestGroupService_RemoveGroupMember_DBError(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	db.err = errors.New("boom")
	svc := newTestGroupService(db)

	err := svc.RemoveGroupMember(context.Background(), "admin-1", "g", "m")
	require.Error(t, err)
}

func TestGroupService_ListGroupMembers_EmptyGroupID(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	svc := newTestGroupService(db)

	_, err := svc.ListGroupMembers(context.Background(), "admin-1", "")
	require.Error(t, err)
}

func TestGroupService_ListGroupMembers_DBError(t *testing.T) {
	db := newFakeDB()
	seedGroupAdmin(db)
	db.err = errors.New("boom")
	svc := newTestGroupService(db)

	_, err := svc.ListGroupMembers(context.Background(), "admin-1", "g")
	require.Error(t, err)
}

// ── ProfileService extended ────────────────────────────────────────────

func TestProfileService_UpdateProfile_EmptyUserID(t *testing.T) {
	db := newFakeDB()
	svc := newTestProfileService(db)

	_, err := svc.UpdateProfile(context.Background(), "", "name", "")
	require.Error(t, err)
}

func TestProfileService_UpdateProfile_OnlyAvatar(t *testing.T) {
	db := newFakeDB()
	db.addUser("user-1", "x@test.com", "X", "member", "active")
	svc := newTestProfileService(db)

	user, err := svc.UpdateProfile(context.Background(), "user-1", "", "https://avatar.example.com/x.png")
	require.NoError(t, err)
	assert.Equal(t, "https://avatar.example.com/x.png", user.AvatarURL)
}

func TestProfileService_ListMySessions_EmptyUserID(t *testing.T) {
	db := newFakeDB()
	svc := newTestProfileService(db)

	_, err := svc.ListMySessions(context.Background(), "")
	require.Error(t, err)
}

func TestProfileService_RevokeSession_EmptyID(t *testing.T) {
	db := newFakeDB()
	svc := newTestProfileService(db)

	err := svc.RevokeSession(context.Background(), "u", "")
	require.Error(t, err)
}

func TestProfileService_RevokeSession_NotFound(t *testing.T) {
	db := newFakeDB()
	svc := newTestProfileService(db)

	err := svc.RevokeSession(context.Background(), "u", "ghost")
	require.Error(t, err)
}

func TestProfileService_RevokeAllSessions_EmptyPassword(t *testing.T) {
	db := newFakeDB()
	svc := newTestProfileService(db)

	_, err := svc.RevokeAllSessions(context.Background(), "u", "")
	require.Error(t, err)
}

func TestProfileService_RevokeAllSessions_UserNotFound(t *testing.T) {
	db := newFakeDB()
	svc := newTestProfileService(db)

	_, err := svc.RevokeAllSessions(context.Background(), "ghost", "anything")
	require.Error(t, err)
}

func TestProfileService_RevokeAllSessions_NoPasswordSet(t *testing.T) {
	db := newFakeDB()
	db.addUser("user-1", "x@test.com", "X", "member", "active")
	svc := newTestProfileService(db)

	_, err := svc.RevokeAllSessions(context.Background(), "user-1", "anything")
	require.Error(t, err)
}

func TestProfileService_ListMyPasskeys_EmptyUserID(t *testing.T) {
	db := newFakeDB()
	svc := newTestProfileService(db)

	_, err := svc.ListMyPasskeys(context.Background(), "")
	require.Error(t, err)
}

func TestProfileService_DeletePasskey_EmptyCred(t *testing.T) {
	db := newFakeDB()
	svc := newTestProfileService(db)

	err := svc.DeletePasskey(context.Background(), "u", "")
	require.Error(t, err)
}

func TestProfileService_DeletePasskey_NotFound(t *testing.T) {
	db := newFakeDB()
	svc := newTestProfileService(db)

	err := svc.DeletePasskey(context.Background(), "u", "no-such-cred")
	require.Error(t, err)
}

func TestProfileService_ChangePassword_EmptyArgs(t *testing.T) {
	db := newFakeDB()
	svc := newTestProfileService(db)

	err := svc.ChangePassword(context.Background(), "u", "", "new")
	require.Error(t, err)
	err = svc.ChangePassword(context.Background(), "u", "old", "")
	require.Error(t, err)
}

func TestProfileService_ChangePassword_UserNotFound(t *testing.T) {
	db := newFakeDB()
	svc := newTestProfileService(db)

	err := svc.ChangePassword(context.Background(), "ghost", "old", "NewStr0ng!Pass")
	require.Error(t, err)
}

func TestProfileService_ChangePassword_NoPasswordSet(t *testing.T) {
	db := newFakeDB()
	db.addUser("user-1", "x@test.com", "X", "member", "active")
	svc := newTestProfileService(db)

	err := svc.ChangePassword(context.Background(), "user-1", "old", "NewStr0ng!Pass")
	// The sentinel, not a plain error: it maps to FailedPrecondition, so a
	// passkey/OAuth-only account gets an actionable "set a password first"
	// instead of a 500 the client has to string-match.
	require.ErrorIs(t, err, ErrNoPasswordSet)
}

func TestProfileService_ListAuditEvents_ActorNotFound(t *testing.T) {
	db := newFakeDB()
	svc := newTestProfileService(db)

	_, _, err := svc.ListAuditEvents(context.Background(), "ghost", "", "", 0, 0, "", 50)
	require.Error(t, err)
}

func TestProfileService_ListAuditEvents_FilterAndPagination(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newTestProfileService(db)

	// Use limit > 500 to hit the cap branch.
	_, _, err := svc.ListAuditEvents(context.Background(), "admin-1", "target", "login", 1, 9999999999999, "0", 1000)
	require.NoError(t, err)
}

func TestProfileService_ListAuditEvents_WithEvents(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")

	// Add audit events with varying timestamps.
	for i, ts := range []int64{100, 200, 300, 400, 500} {
		id := "audit-" + string(rune('0'+i))
		details := `{}`
		if i == 0 {
			details = `{"key":"val"}`
		}
		db.mu.Lock()
		db.nodes[id] = mkAuditNode(id, "login_success", "admin-1", "target-1", ts, details)
		db.mu.Unlock()
	}

	svc := newTestProfileService(db)

	// Filter to event type that matches.
	events, _, err := svc.ListAuditEvents(context.Background(), "admin-1", "", "login_success", 150, 450, "", 2)
	require.NoError(t, err)
	require.NotEmpty(t, events)
	// At least one event should be returned with proper details.
	for _, e := range events {
		assert.NotNil(t, e.Details)
	}

	// Pagination cursor.
	_, cursor, err := svc.ListAuditEvents(context.Background(), "admin-1", "", "login_success", 0, 0, "", 2)
	require.NoError(t, err)
	if cursor != "" {
		_, _, err = svc.ListAuditEvents(context.Background(), "admin-1", "", "login_success", 0, 0, cursor, 2)
		require.NoError(t, err)
	}
}

// ── HelpService extended ───────────────────────────────────────────────

func TestHelpService_RequestAdminHelp_LongReasonTruncated(t *testing.T) {
	db := newFakeDB()
	svc := newTestHelpService(db)

	long := make([]byte, 2000)
	for i := range long {
		long[i] = 'r'
	}
	err := svc.RequestAdminHelp(context.Background(), "x@test.com", string(long), "", "")
	require.NoError(t, err)
}

func TestHelpService_RequestAdminHelp_DBErrorReturnsNil(t *testing.T) {
	// The function swallows DB errors and returns nil to prevent enumeration.
	db := newFakeDB()
	db.err = errors.New("boom")
	svc := newTestHelpService(db)

	err := svc.RequestAdminHelp(context.Background(), "x@test.com", "reason", "", "")
	require.NoError(t, err)
}

func TestHelpService_ListHelpRequests_LimitClamps(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newTestHelpService(db)

	_, _, _, err := svc.ListHelpRequests(context.Background(), "admin-1", "pending", "", 1000)
	require.NoError(t, err)
	_, _, _, err = svc.ListHelpRequests(context.Background(), "admin-1", "", "", 0)
	require.NoError(t, err)
}

func TestHelpService_ListHelpRequests_WithCursor(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	for i := 0; i < 5; i++ {
		db.addHelpRequest("hr-"+string(rune('0'+i)), "x@test.com", "pending", nowMs())
	}
	svc := newTestHelpService(db)

	_, cursor, _, err := svc.ListHelpRequests(context.Background(), "admin-1", "", "", 2)
	require.NoError(t, err)
	assert.NotEmpty(t, cursor)

	page2, _, _, err := svc.ListHelpRequests(context.Background(), "admin-1", "", cursor, 2)
	require.NoError(t, err)
	assert.NotEmpty(t, page2)
}

func TestHelpService_ResolveHelpRequest_NonAdmin(t *testing.T) {
	db := newFakeDB()
	db.addUser("member-1", "m@test.com", "M", "member", "active")
	svc := newTestHelpService(db)

	_, err := svc.ResolveHelpRequest(context.Background(), "member-1", "hr-1", false, "")
	require.Error(t, err)
}

func TestHelpService_ResolveHelpRequest_EmptyID(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newTestHelpService(db)

	_, err := svc.ResolveHelpRequest(context.Background(), "admin-1", "", false, "")
	require.Error(t, err)
}

func TestHelpService_ResolveHelpRequest_LongNotesTruncated(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.addHelpRequest("hr-1", "h@test.com", "pending", nowMs())
	svc := newTestHelpService(db)

	notes := make([]byte, 5000)
	for i := range notes {
		notes[i] = 'x'
	}
	hr, err := svc.ResolveHelpRequest(context.Background(), "admin-1", "hr-1", false, string(notes))
	require.NoError(t, err)
	assert.LessOrEqual(t, len(hr.ResolutionNotes), 2048)
}

func TestHelpService_RequireAdmin_ActorMissing(t *testing.T) {
	db := newFakeDB()
	svc := newTestHelpService(db)

	_, _, _, err := svc.ListHelpRequests(context.Background(), "ghost", "", "", 50)
	require.Error(t, err)
}

// ── friendlyDeviceName extra branches ──────────────────────────────────

func TestFriendlyDeviceName_AllBranches(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (Linux; Android 13)": "Browser on Android",
		"Mozilla/5.0 (iPad)":              "Browser on iOS",
		"Mozilla/5.0 (iPod)":              "Browser on iOS",
		"PostmanRuntime/7.32.2":           "Postman on Unknown OS",
		"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0": "Firefox on Linux",
		"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Edg/120.0":   "Edge on Windows",
	}
	for ua, want := range cases {
		assert.Equal(t, want, friendlyDeviceName(ua), "ua=%q", ua)
	}
}

func TestTruncateBranches(t *testing.T) {
	assert.Equal(t, "abc", truncate("abc", 5))
	assert.Equal(t, "abcde", truncate("abcdefghij", 5))
}

// ── checkAccountStatus all branches ────────────────────────────────────

func TestCheckAccountStatus_Branches(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	require.NoError(t, svc.checkAccountStatus(context.Background(), &User{Status: ""}, "", ""))
	require.NoError(t, svc.checkAccountStatus(context.Background(), &User{Status: "ACTIVE"}, "", ""))
	require.ErrorIs(t, svc.checkAccountStatus(context.Background(), &User{Status: "invited"}, "", ""), ErrInvitationPending)
	require.ErrorIs(t, svc.checkAccountStatus(context.Background(), &User{Status: "suspended"}, "", ""), ErrAccountNotActive)
}

// ── Stub implementations - smoke test all error paths ──────────────────

func TestStubRepository_AllMethodsReturnUnavailable(t *testing.T) {
	r := StubRepository{}
	ctx := context.Background()

	if _, err := r.FindUserByEmail(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("FindUserByEmail: %v", err)
	}
	if _, err := r.GetUser(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("GetUser: %v", err)
	}
	if _, err := r.CreateUser(ctx, &User{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreateUser: %v", err)
	}
	if err := r.UpdateUser(ctx, "", nil); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("UpdateUser: %v", err)
	}
	if _, err := r.IncrementFailedLoginCount(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("IncrementFailedLoginCount: %v", err)
	}
	if err := r.ResetFailedLoginCount(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("ResetFailedLoginCount: %v", err)
	}
	if err := r.SetUserLockedUntil(ctx, "", 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("SetUserLockedUntil: %v", err)
	}
	if _, err := r.FindRefreshTokenByHash(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("FindRefreshTokenByHash: %v", err)
	}
	if _, err := r.FindRefreshTokenByHashIncludingConsumed(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("FindRefreshTokenByHashIncludingConsumed: %v", err)
	}
	if _, err := r.CreateRefreshToken(ctx, &RefreshTokenRecord{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreateRefreshToken: %v", err)
	}
	if err := r.DeleteRefreshToken(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteRefreshToken: %v", err)
	}
	if err := r.DeleteRefreshTokensForUser(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteRefreshTokensForUser: %v", err)
	}
	if err := r.ConsumeRefreshTokenByHash(ctx, "", 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("ConsumeRefreshTokenByHash: %v", err)
	}
	if _, err := r.ListPasskeyCredentials(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("ListPasskeyCredentials: %v", err)
	}
	if _, err := r.GetPasskeyCredentialByCredID(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("GetPasskeyCredentialByCredID: %v", err)
	}
	if _, err := r.CreatePasskeyCredential(ctx, &PasskeyCredRecord{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreatePasskeyCredential: %v", err)
	}
	if err := r.UpdatePasskeyCredential(ctx, "", nil); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("UpdatePasskeyCredential: %v", err)
	}
	if _, err := r.GetPasskeyChallenge(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("GetPasskeyChallenge: %v", err)
	}
	if _, err := r.CreatePasskeyChallenge(ctx, &PasskeyChallengeRecord{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreatePasskeyChallenge: %v", err)
	}
	if err := r.DeletePasskeyChallenge(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeletePasskeyChallenge: %v", err)
	}
	if _, err := r.FindQrLoginSession(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("FindQrLoginSession: %v", err)
	}
	if _, err := r.CreateQrLoginSession(ctx, &QrLoginSessionRecord{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreateQrLoginSession: %v", err)
	}
	if err := r.UpdateQrLoginSession(ctx, "", nil); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("UpdateQrLoginSession: %v", err)
	}
	if _, err := r.GetTotpCredential(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("GetTotpCredential: %v", err)
	}
	if _, err := r.CreateTotpCredential(ctx, &TotpCredRecord{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreateTotpCredential: %v", err)
	}
	if err := r.UpdateTotpCredential(ctx, "", nil); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("UpdateTotpCredential: %v", err)
	}
	if err := r.DeleteTotpCredential(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteTotpCredential: %v", err)
	}
	if err := r.DeleteTotpCredentialsForUser(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteTotpCredentialsForUser: %v", err)
	}
	if _, err := r.CreateRecoveryCode(ctx, &RecoveryCodeRecord{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreateRecoveryCode: %v", err)
	}
	if _, err := r.FindRecoveryCodeByHash(ctx, "", ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("FindRecoveryCodeByHash: %v", err)
	}
	if err := r.UpdateRecoveryCode(ctx, "", nil); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("UpdateRecoveryCode: %v", err)
	}
	if err := r.DeleteRecoveryCodesForUser(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteRecoveryCodesForUser: %v", err)
	}
	if _, err := r.CreateLoginChallenge(ctx, &LoginChallengeRecord{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreateLoginChallenge: %v", err)
	}
	if _, err := r.GetLoginChallengeByChallengeID(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("GetLoginChallengeByChallengeID: %v", err)
	}
	if err := r.DeleteLoginChallenge(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteLoginChallenge: %v", err)
	}
	if _, err := r.FindInvitationByHash(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("FindInvitationByHash: %v", err)
	}
	if err := r.UpdateInvitation(ctx, "", nil); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("UpdateInvitation: %v", err)
	}
	if err := r.CreatePasswordResetToken(ctx, &PasswordResetToken{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreatePasswordResetToken: %v", err)
	}
	if _, err := r.FindPasswordResetTokenByHash(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("FindPasswordResetTokenByHash: %v", err)
	}
	if err := r.MarkPasswordResetTokenConsumed(ctx, "", 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("MarkPasswordResetTokenConsumed: %v", err)
	}
	if err := r.CreateEmailVerificationToken(ctx, &EmailVerificationToken{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreateEmailVerificationToken: %v", err)
	}
	if _, err := r.FindEmailVerificationTokenByHash(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("FindEmailVerificationTokenByHash: %v", err)
	}
	if err := r.MarkEmailVerificationTokenConsumed(ctx, "", 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("MarkEmailVerificationTokenConsumed: %v", err)
	}
	if err := r.SetUserEmailVerified(ctx, "", 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("SetUserEmailVerified: %v", err)
	}
	if err := r.CreateEmailChangeToken(ctx, &EmailChangeToken{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreateEmailChangeToken: %v", err)
	}
	if _, err := r.FindEmailChangeTokenByHash(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("FindEmailChangeTokenByHash: %v", err)
	}
	if err := r.MarkEmailChangeTokenConsumed(ctx, "", 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("MarkEmailChangeTokenConsumed: %v", err)
	}
	if err := r.UpdateUserEmail(ctx, "", "", 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("UpdateUserEmail: %v", err)
	}
	if _, err := r.FindUserByProviderID(ctx, "", ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("FindUserByProviderID: %v", err)
	}
	if err := r.CreateOAuthIdentity(ctx, &OAuthIdentity{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreateOAuthIdentity: %v", err)
	}
	if _, err := r.ListOAuthIdentitiesForUser(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("ListOAuthIdentitiesForUser: %v", err)
	}
	if err := r.DeleteExpiredWebAuthnChallenges(ctx, 0, 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteExpiredWebAuthnChallenges: %v", err)
	}
	if err := r.DeleteExpiredEmailVerificationTokens(ctx, 0, 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteExpiredEmailVerificationTokens: %v", err)
	}
	if err := r.DeleteExpiredPasswordResetTokens(ctx, 0, 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteExpiredPasswordResetTokens: %v", err)
	}
	if err := r.DeleteExpiredEmailChangeTokens(ctx, 0, 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteExpiredEmailChangeTokens: %v", err)
	}
	if err := r.DeleteExpiredLoginChallenges(ctx, 0, 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteExpiredLoginChallenges: %v", err)
	}
	if err := r.DeleteExpiredOAuthOneTimeCodes(ctx, 0, 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteExpiredOAuthOneTimeCodes: %v", err)
	}
	if err := r.DeleteExpiredNativeTokenRedemptions(ctx, 0, 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteExpiredNativeTokenRedemptions: %v", err)
	}
	if err := r.DeleteExpiredEmailLoginCodes(ctx, 0, 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteExpiredEmailLoginCodes: %v", err)
	}
	if err := r.DeleteExpiredMagicLinkTokens(ctx, 0, 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteExpiredMagicLinkTokens: %v", err)
	}
	if err := r.DeleteExpiredPhoneVerificationCodes(ctx, 0, 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteExpiredPhoneVerificationCodes: %v", err)
	}
	if err := r.DeleteExpiredQrLoginSessions(ctx, 0, 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteExpiredQrLoginSessions: %v", err)
	}
	if err := r.DeleteExpiredInvitations(ctx, 0, 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteExpiredInvitations: %v", err)
	}
	// Client assurance (attested devices + one-shot challenges): this test
	// claims to cover every method, so new Repository surface belongs here.
	if _, err := r.CreateAttestedDevice(ctx, &AttestedDeviceRecord{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreateAttestedDevice: %v", err)
	}
	if _, err := r.GetAttestedDeviceByKeyID(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("GetAttestedDeviceByKeyID: %v", err)
	}
	if err := r.UpdateAttestedDeviceCounter(ctx, "", 0, 0, 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("UpdateAttestedDeviceCounter: %v", err)
	}
	if err := r.DeleteStaleAttestedDevices(ctx, 0, 1); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteStaleAttestedDevices: %v", err)
	}
	if _, err := r.CreateAssuranceChallenge(ctx, &AssuranceChallengeRecord{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreateAssuranceChallenge: %v", err)
	}
	if _, err := r.ConsumeAssuranceChallenge(ctx, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("ConsumeAssuranceChallenge: %v", err)
	}
	if err := r.DeleteExpiredAssuranceChallenges(ctx, 0, 1); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("DeleteExpiredAssuranceChallenges: %v", err)
	}
}

func TestStubDB_AllMethodsReturnUnavailable(t *testing.T) {
	d := StubDB{}
	ctx := context.Background()

	if _, err := d.GetNode(ctx, "", "", 0, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("GetNode: %v", err)
	}
	if _, err := d.QueryNodes(ctx, "", "", 0, nil); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("QueryNodes: %v", err)
	}
	if _, err := d.ExecuteAtomic(ctx, "", "", nil); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("ExecuteAtomic: %v", err)
	}
	if _, err := d.GetEdgesFrom(ctx, "", "", "", 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("GetEdgesFrom: %v", err)
	}
	if _, err := d.GetEdgesTo(ctx, "", "", "", 0); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("GetEdgesTo: %v", err)
	}
	if _, err := d.SearchNodes(ctx, "", "", 0, ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("SearchNodes: %v", err)
	}
}

// ── NewAuthService / NewAdminService / NewGroupService / NewHelpService / NewProfileService nil logger ─

func TestNewAuthService_ShortPepperPanics(t *testing.T) {
	repo := newFakeRepo()
	cfg := testConfig()
	kr := testKeyRing(t)

	assert.Panics(t, func() {
		_ = NewAuthService(repo, cfg, kr, nil, nil, testTotpKey(), []byte("too-short"), nil, nil, nil)
	}, "AuthService must refuse a short recovery pepper rather than silently accept it")
}

func TestNewServices_NilLoggerIsSafe(t *testing.T) {
	repo := newFakeRepo()
	cfg := testConfig()
	kr := testKeyRing(t)

	a := NewAuthService(repo, cfg, kr, nil, nil, testTotpKey(), testTotpRecoveryPepper(), nil, nil, nil)
	assert.NotNil(t, a)

	db := newFakeDB()
	ad := NewAdminService(newFakeRepo(), db, "t", nil, cfg, nil, nil)
	assert.NotNil(t, ad)

	g := NewGroupService(db, "t", nil, nil)
	assert.NotNil(t, g)

	h := NewHelpService(db, "t", nil, nil)
	assert.NotNil(t, h)

	p := NewProfileService(StubRepository{}, db, "t", nil, nil)
	assert.NotNil(t, p)
}

// ── pstr / pstrOr / pi64 / pbool helpers — exercise non-default branches ─

func TestPayloadHelpers(t *testing.T) {
	p := map[string]any{
		"s":     "hello",
		"i64":   int64(42),
		"f64":   float64(7),
		"i":     int(5),
		"bt":    true,
		"bf":    false,
		"wrong": []byte{1, 2},
	}
	assert.Equal(t, "hello", pstr(p, "s"))
	assert.Equal(t, "", pstr(p, "missing"))
	assert.Equal(t, "", pstr(p, "wrong"))
	assert.Equal(t, "default", pstrOr(p, "missing", "default"))
	assert.Equal(t, "hello", pstrOr(p, "s", "default"))

	assert.Equal(t, int64(42), pi64(p, "i64"))
	assert.Equal(t, int64(7), pi64(p, "f64"))
	assert.Equal(t, int64(5), pi64(p, "i"))
	assert.Equal(t, int64(0), pi64(p, "missing"))
	assert.Equal(t, int64(0), pi64(p, "wrong"))

	assert.True(t, pbool(p, "bt"))
	assert.False(t, pbool(p, "bf"))
	assert.False(t, pbool(p, "missing"))
	assert.False(t, pbool(p, "wrong"))
}

func TestNodeFromNilSafe(t *testing.T) {
	assert.Nil(t, userFromNode(nil))
	assert.Nil(t, groupFromNode(nil))
	assert.Nil(t, helpRequestFromNode(nil))
	assert.Nil(t, sessionFromNode(nil))
	assert.Nil(t, passkeyInfoFromNode(nil))
	assert.Nil(t, auditEventFromNode(nil))
}

func TestActorStr(t *testing.T) {
	assert.Equal(t, "user:abc", actorStr("abc"))
}

// mkAuditNode builds an audit-event node payload for tests.
func mkAuditNode(id, eventType, actor, target string, createdAt int64, details string) *graph.Node {
	return &graph.Node{
		NodeID: id,
		TypeID: typeAuditEvent,
		Payload: map[string]any{
			afEventType:    eventType,
			afActorUserID:  actor,
			afTargetUserID: target,
			afIPAddress:    "1.2.3.4",
			afUserAgent:    "Agent",
			afSuccess:      true,
			afDetails:      details,
			afCreatedAt:    createdAt,
		},
	}
}

// ── totpGenerateCode helper — generates a valid TOTP code from a secret ─

func totpGenerateCode(secret string) (string, error) {
	return otptotp.GenerateCodeCustom(secret, time.Now(), otptotp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
}

// ── Validate password strength branch ──────────────────────────────────

func TestValidatePasswordStrength_Branches(t *testing.T) {
	require.NoError(t, validatePasswordStrength(strongPW))
	require.Error(t, validatePasswordStrength("short"))
}

// ── passwords helper coverage ──────────────────────────────────────────

func TestHashPasswordRoundtrip(t *testing.T) {
	h, err := passwords.Hash("MyStr0ng!Pass")
	require.NoError(t, err)
	assert.True(t, passwords.Verify("MyStr0ng!Pass", h))
	assert.False(t, passwords.Verify("WrongP@ss1!", h))
}
