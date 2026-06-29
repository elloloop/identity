package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/passwords"
	"github.com/elloloop/identity/pkg/totp"
)

// Strong password that satisfies strength requirements.
const strongPW = "MyStr0ng!Pass"

func hashPW(t *testing.T, pw string) string {
	t.Helper()
	h, err := passwords.Hash(pw)
	require.NoError(t, err)
	return h
}

type signupRaceRepo struct {
	*errorRepo
	findCalls int
}

func (r *signupRaceRepo) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	r.findCalls++
	if r.findCalls == 1 {
		return nil, nil
	}
	return r.errorRepo.FindUserByEmail(ctx, email)
}

// ── Signup ──────────────────────────────────────────────────────────────

func TestPasswordSignup_CreatesUserAndIssuesTokens(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "alice@example.com", strongPW, "Alice", "", 0)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "alice@example.com", result.User.Email)
	assert.Equal(t, "Alice", result.User.Name)
	assert.Equal(t, "member", result.User.Role)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Equal(t, int32(900), result.ExpiresIn)
	assert.False(t, result.TotpRequired)
}

func TestPasswordSignup_DuplicateEmail_NoEnumeration(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)

	fresh, err := svc.PasswordSignup(context.Background(), "alice@example.com", strongPW, "Alice", "", 0)
	require.NoError(t, err)
	rec.Reset()

	dup, err := svc.PasswordSignup(context.Background(), "alice@example.com", strongPW, "Alice", "", 0)
	require.NoError(t, err)
	require.NotNil(t, dup)

	assert.Equal(t, fresh.User.Email, dup.User.Email)
	assert.Equal(t, fresh.User.Name, dup.User.Name)
	assert.Equal(t, fresh.ExpiresIn, dup.ExpiresIn)
	assert.False(t, dup.TotpRequired)
	assert.NotEmpty(t, dup.User.ID)
	assert.NotEmpty(t, dup.AccessToken)
	assert.NotEmpty(t, dup.RefreshToken)

	assert.Len(t, repo.users, 1, "duplicate signup must not create a second user")
	assert.Len(t, repo.refreshTokens, 1, "duplicate signup must not mint a stored refresh token")

	_, _, _, err = svc.RefreshToken(context.Background(), dup.RefreshToken, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestPasswordSignup_DuplicateEmail_SendsNoticeEmail(t *testing.T) {
	svc, _, rec := newAuthSvcWithMailer(t)

	_, err := svc.PasswordSignup(context.Background(), "alice@example.com", strongPW, "Alice", "", 0)
	require.NoError(t, err)
	rec.Reset()

	_, err = svc.PasswordSignup(context.Background(), "alice@example.com", strongPW, "Alice", "", 0)
	require.NoError(t, err)

	sent := rec.Sent()
	require.Len(t, sent, 1)
	assert.Equal(t, "alice@example.com", sent[0].To)
	assert.Equal(t, "Someone tried to sign up with your email", sent[0].Subject)
	assert.Contains(t, sent[0].Text, "Someone tried to sign up with this email address.")
	assert.Contains(t, sent[0].Text, "https://app.test")
	assert.True(t, strings.Contains(strings.ToLower(sent[0].Text), "ignore"))
}

func TestPasswordSignup_DuplicateCreateRaceReturnsDecoy(t *testing.T) {
	base := newErrorRepo()
	winner := seedUser(base.fakeRepo, "race@example.com", hashPW(t, strongPW), "active")
	repo := &signupRaceRepo{errorRepo: base}
	repo.failCreateUser = true
	svc, rec := newAuthSvcWithMailerForRepo(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "race@example.com", strongPW, "Racer", "", 0)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEqual(t, winner.ID, result.User.ID)
	assert.Contains(t, result.User.ID, "signup-pending-")
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Len(t, rec.Sent(), 1)

	_, _, _, err = svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
	got, findErr := repo.FindUserByEmail(context.Background(), "race@example.com")
	require.NoError(t, findErr)
	require.NotNil(t, got)
	assert.Equal(t, winner.ID, got.ID)
}

func TestPasswordSignup_WeakPasswordFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.PasswordSignup(context.Background(), "alice@example.com", "short", "", "", 0)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrWeakPassword))
}

func TestPasswordSignup_InvalidEmailFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.PasswordSignup(context.Background(), "notanemail", strongPW, "", "", 0)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestPasswordSignup_LocalAuthDisabledFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.AuthAllowLocal = false

	_, err := svc.PasswordSignup(context.Background(), "alice@example.com", strongPW, "", "", 0)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrLocalAuthDisabled))
}

func TestPasswordSignup_DisabledFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.PasswordSignupEnabled = false

	_, err := svc.PasswordSignup(context.Background(), "alice@example.com", strongPW, "", "", 0)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignupDisabled))
}

// ── Login ───────────────────────────────────────────────────────────────

func TestPasswordLogin_CorrectPasswordSucceeds(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "bob@example.com", pwHash, "active")

	result, err := svc.PasswordLogin(context.Background(), "bob@example.com", strongPW, "1.2.3.4", "TestAgent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "bob@example.com", result.User.Email)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.False(t, result.TotpRequired)
}

func TestPasswordLogin_UnverifiedEmailBlocked(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.AuthRequireVerifiedEmail = true
	pwHash := hashPW(t, strongPW)
	user := seedUser(repo, "bob@example.com", pwHash, "active")
	user.EmailVerified = false
	user.EmailVerifiedAt = 0

	// Correct password, but the email is not verified — the gate fires only
	// after the password is proven, so no enumeration oracle is created.
	_, err := svc.PasswordLogin(context.Background(), "bob@example.com", strongPW, "1.2.3.4", "TestAgent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEmailVerificationRequired))
}

func TestPasswordLogin_VerifiedEmailAllowed(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.AuthRequireVerifiedEmail = true
	pwHash := hashPW(t, strongPW)
	user := seedUser(repo, "bob@example.com", pwHash, "active")
	user.EmailVerified = true
	user.EmailVerifiedAt = time.Now().UnixMilli()

	result, err := svc.PasswordLogin(context.Background(), "bob@example.com", strongPW, "1.2.3.4", "TestAgent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "bob@example.com", result.User.Email)
	assert.True(t, result.User.EmailVerified)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
}

func TestPasswordLogin_RequireVerifiedEmailDisabled_AllowsUnverified(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.AuthRequireVerifiedEmail = false // gate off: old behavior preserved
	pwHash := hashPW(t, strongPW)
	user := seedUser(repo, "bob@example.com", pwHash, "active")
	user.EmailVerified = false
	user.EmailVerifiedAt = 0

	result, err := svc.PasswordLogin(context.Background(), "bob@example.com", strongPW, "1.2.3.4", "TestAgent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "bob@example.com", result.User.Email)
	assert.False(t, result.User.EmailVerified)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
}

func TestPasswordLogin_WrongPasswordFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "bob@example.com", pwHash, "active")

	_, err := svc.PasswordLogin(context.Background(), "bob@example.com", "WrongP@ss1!", "1.2.3.4", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestPasswordLogin_UserNotFoundFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.PasswordLogin(context.Background(), "nobody@example.com", strongPW, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestPasswordLogin_LockedAccountFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	u := seedUser(repo, "locked@example.com", pwHash, "active")
	// Lock the account 1 hour in the future.
	u.LockedUntil = time.Now().Add(time.Hour).UnixMilli()

	_, err := svc.PasswordLogin(context.Background(), "locked@example.com", strongPW, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAccountLocked))
}

func TestPasswordLogin_NoPasswordSetFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	seedUser(repo, "oauth@example.com", "", "active") // no password hash

	_, err := svc.PasswordLogin(context.Background(), "oauth@example.com", "anything", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoPasswordSet))
}

func TestPasswordLogin_DeactivatedAccountFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "deac@example.com", pwHash, "deactivated")

	_, err := svc.PasswordLogin(context.Background(), "deac@example.com", strongPW, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAccountNotActive))
}

func TestPasswordLogin_FailedAttemptsLockAccount(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	u := seedUser(repo, "failing@example.com", pwHash, "active")

	// 5 failed attempts should lock.
	for i := 0; i < 5; i++ {
		_, _ = svc.PasswordLogin(context.Background(), "failing@example.com", "BadP@ss1!", "", "")
	}

	// Re-read the user to check lock.
	repo.mu.Lock()
	latest := repo.users[u.ID]
	repo.mu.Unlock()
	assert.True(t, latest.LockedUntil > time.Now().UnixMilli(), "account should be locked")
}

func TestPasswordLogin_TotpRequiredReturnsChallengeID(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	u := seedUser(repo, "totp@example.com", pwHash, "active")
	u.TotpRequired = true

	result, err := svc.PasswordLogin(context.Background(), "totp@example.com", strongPW, "", "")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.TotpRequired)
	assert.NotEmpty(t, result.LoginChallengeID)
	assert.Empty(t, result.AccessToken, "no tokens when TOTP required")
}

// ── RefreshToken ────────────────────────────────────────────────────────

func TestRefreshToken_RotatesToken(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	// Sign up to get initial tokens.
	result, err := svc.PasswordSignup(context.Background(), "refresh@example.com", strongPW, "", "", 0)
	require.NoError(t, err)
	originalRefresh := result.RefreshToken

	// Refresh.
	user, newAccess, newRefresh, err := svc.RefreshToken(context.Background(), originalRefresh, "", "")
	require.NoError(t, err)
	assert.NotNil(t, user)
	assert.NotEmpty(t, newAccess)
	assert.NotEmpty(t, newRefresh)
	assert.NotEqual(t, originalRefresh, newRefresh, "refresh token should be rotated")

	// Old token should not work anymore.
	_, _, _, err = svc.RefreshToken(context.Background(), originalRefresh, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestRefreshToken_ExpiredTokenFails(t *testing.T) {
	repo := newFakeRepo()
	// Use a time in the far future for the test clock so the token appears expired.
	futureTime := time.Now().Add(365 * 24 * time.Hour)
	svc := newTestAuthServiceWithTime(t, repo, time.Now)

	result, err := svc.PasswordSignup(context.Background(), "expire@example.com", strongPW, "", "", 0)
	require.NoError(t, err)

	// Advance the clock past the refresh token expiry.
	svc.nowFunc = func() time.Time { return futureTime }

	_, _, _, err = svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTokenExpired))
}

func TestRefreshToken_InvalidTokenFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, _, _, err := svc.RefreshToken(context.Background(), "bogus-token", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestRefreshToken_LookupErrorFailsClosed(t *testing.T) {
	repo := newErrorRepo()
	svc := newTestAuthServiceErr(t, repo)

	repo.failFindRefreshTokenIncluding = true
	_, _, _, err := svc.RefreshToken(context.Background(), "raw-token", "", "")
	require.Error(t, err)
}

func TestRefreshToken_ConsumeFailureDoesNotMintReplacement(t *testing.T) {
	repo := newErrorRepo()
	svc := newTestAuthServiceErr(t, repo)
	result, err := svc.PasswordSignup(context.Background(), "consume@example.com", strongPW, "", "", 0)
	require.NoError(t, err)

	repo.failConsumeRefreshToken = true
	_, _, _, err = svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.Error(t, err)
	list, snapErr := repo.refreshTokenSnapshot()
	require.NoError(t, snapErr)
	assert.Len(t, list, 1)
	stored, findErr := repo.FindRefreshTokenByHashIncludingConsumed(context.Background(), hashRefreshToken(result.RefreshToken))
	require.NoError(t, findErr)
	require.NotNil(t, stored)
	assert.Zero(t, stored.ConsumedAtMs)
}

func TestRefreshToken_ReplayRevokeFailureStillRejectsReplay(t *testing.T) {
	repo := newErrorRepo()
	svc := newTestAuthServiceErr(t, repo)
	result, err := svc.PasswordSignup(context.Background(), "replay-delete@example.com", strongPW, "", "", 0)
	require.NoError(t, err)

	_, _, _, err = svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.NoError(t, err)

	repo.failDeleteRefreshTokensForUser = true
	_, _, _, err = svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

// ── Logout ──────────────────────────────────────────────────────────────

func TestLogout_DeletesRefreshToken(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "logout@example.com", strongPW, "", "", 0)
	require.NoError(t, err)

	err = svc.Logout(context.Background(), result.RefreshToken)
	require.NoError(t, err)

	// Token should be gone.
	_, _, _, err = svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.Error(t, err)
}

func TestLogout_EmptyTokenIsNoop(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	err := svc.Logout(context.Background(), "")
	require.NoError(t, err)
}

// ── GetCurrentUser ──────────────────────────────────────────────────────

func TestGetCurrentUser_ReturnsUser(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "me@example.com", "", "active")

	user, err := svc.GetCurrentUser(context.Background(), u.ID)
	require.NoError(t, err)
	assert.Equal(t, "me@example.com", user.Email)
}

func TestGetCurrentUser_NotFoundFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.GetCurrentUser(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

// ── OAuthLogin ──────────────────────────────────────────────────────────

func TestOAuthLogin_CreatesNewUser(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	code := fakeOAuthCode("oauth@example.com", "OAuth User", "https://img.example.com/pic.jpg", "google")
	result, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: code, Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "", UserAgent: ""})
	require.NoError(t, err)
	assert.Equal(t, "oauth@example.com", result.User.Email)
	assert.Equal(t, "OAuth User", result.User.Name)
	assert.NotEmpty(t, result.AccessToken)
}

func TestOAuthLogin_ExistingUserUpdatesProfile(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	seedUser(repo, "existing@example.com", "", "active")

	code := fakeOAuthCode("existing@example.com", "New Name", "https://pic.url", "google")
	result, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: code, Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "", UserAgent: ""})
	require.NoError(t, err)
	assert.Equal(t, "existing@example.com", result.User.Email)
}

// ── QR Login ────────────────────────────────────────────────────────────

func TestQrLogin_InitiateApproveAndPoll(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	user := seedUser(repo, "qr@example.com", "", "active")

	// Step 1: Initiate.
	init, err := svc.InitiateQrLogin(context.Background(), "Pixel 8", "TestAgent", "10.0.0.1")
	require.NoError(t, err)
	assert.NotEmpty(t, init.SessionID)
	assert.NotEmpty(t, init.PollSecret)
	assert.NotContains(t, init.QRURL, init.PollSecret, "poll_secret must not leak into the QR URL")
	assert.Contains(t, init.QRURL, init.SessionID)
	assert.Equal(t, int32(300), init.ExpiresIn)

	// Step 2: Get session (status should be pending).
	info, err := svc.GetQrLoginSession(context.Background(), init.SessionID)
	require.NoError(t, err)
	assert.Equal(t, "pending", info.Status)
	assert.Equal(t, "Pixel 8", info.NewDeviceInfo)

	// Step 3: Approve.
	status, err := svc.ApproveQrLogin(context.Background(), init.SessionID, true, user.ID, "ApproverAgent")
	require.NoError(t, err)
	assert.Equal(t, "approved", status)

	// Step 4: Poll -- should return tokens.
	result, err := svc.PollQrLogin(context.Background(), init.SessionID, init.PollSecret, "10.0.0.1", "TestAgent")
	require.NoError(t, err)
	assert.Equal(t, "approved", result.Status)
	assert.NotNil(t, result.User)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)

	// Step 5: Poll again -- should be consumed.
	result2, err := svc.PollQrLogin(context.Background(), init.SessionID, init.PollSecret, "10.0.0.1", "TestAgent")
	require.NoError(t, err)
	assert.Equal(t, "consumed", result2.Status)
	assert.Nil(t, result2.User)
}

func TestQrLogin_PollWithoutSecret_AppearsExpired(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	user := seedUser(repo, "qrss@example.com", "", "active")

	init, err := svc.InitiateQrLogin(context.Background(), "Pixel", "", "")
	require.NoError(t, err)

	_, err = svc.ApproveQrLogin(context.Background(), init.SessionID, true, user.ID, "")
	require.NoError(t, err)

	// Missing secret.
	res, err := svc.PollQrLogin(context.Background(), init.SessionID, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, "expired", res.Status, "missing secret must look like an expired session")
	assert.Empty(t, res.AccessToken)

	// Wrong secret.
	res, err = svc.PollQrLogin(context.Background(), init.SessionID, "deadbeef", "", "")
	require.NoError(t, err)
	assert.Equal(t, "expired", res.Status)
	assert.Empty(t, res.AccessToken)

	// Correct secret still works after the failed attempts.
	res, err = svc.PollQrLogin(context.Background(), init.SessionID, init.PollSecret, "", "")
	require.NoError(t, err)
	assert.Equal(t, "approved", res.Status)
	assert.NotEmpty(t, res.AccessToken)
}

func TestQrLogin_RejectFlow(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	user := seedUser(repo, "qr2@example.com", "", "active")

	init, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.NoError(t, err)

	status, err := svc.ApproveQrLogin(context.Background(), init.SessionID, false, user.ID, "")
	require.NoError(t, err)
	assert.Equal(t, "rejected", status)

	result, err := svc.PollQrLogin(context.Background(), init.SessionID, init.PollSecret, "", "")
	require.NoError(t, err)
	assert.Equal(t, "rejected", result.Status)
}

func TestQrLogin_ExpiredSessionPollReturnsExpired(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	init, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.NoError(t, err)

	// Advance clock past expiry.
	svc.nowFunc = func() time.Time { return time.Now().Add(time.Hour) }

	result, err := svc.PollQrLogin(context.Background(), init.SessionID, init.PollSecret, "", "")
	require.NoError(t, err)
	assert.Equal(t, "expired", result.Status)
}

func TestQrLogin_NonexistentSessionReturnsExpired(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	result, err := svc.PollQrLogin(context.Background(), "nonexistent-session", "somesecret", "", "")
	require.NoError(t, err)
	assert.Equal(t, "expired", result.Status)
}

// TestQrLogin_ConcurrentPollOfApprovedSession_SingleWinner asserts the
// multi-replica regression for issue #14: N goroutines polling the same
// approved QR session must all succeed (each call is well-formed), but
// only ONE may walk away with tokens. The rest see status="consumed"
// — equivalent to "another replica already minted tokens for this
// session." The repository's ConsumeQrLoginSession is the
// serialization point.
func TestQrLogin_ConcurrentPollOfApprovedSession_SingleWinner(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	user := seedUser(repo, "qr-race@example.com", "", "active")

	init, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.NoError(t, err)

	_, err = svc.ApproveQrLogin(context.Background(), init.SessionID, true, user.ID, "")
	require.NoError(t, err)

	const N = 16
	type pollOutcome struct {
		status      string
		accessToken string
		err         error
	}
	results := make([]pollOutcome, N)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			<-start
			r, err := svc.PollQrLogin(context.Background(), init.SessionID, init.PollSecret, "", "")
			if err != nil {
				results[i] = pollOutcome{err: err}
				return
			}
			results[i] = pollOutcome{status: r.Status, accessToken: r.AccessToken}
		}()
	}
	close(start)
	wg.Wait()

	approvedWinners := 0
	consumedLosers := 0
	for _, r := range results {
		require.NoError(t, r.err)
		switch r.status {
		case "approved":
			approvedWinners++
			require.NotEmpty(t, r.accessToken, "winner must carry an access token")
		case "consumed":
			consumedLosers++
			require.Empty(t, r.accessToken, "loser must not carry a token")
		default:
			t.Fatalf("unexpected status %q", r.status)
		}
	}
	assert.Equal(t, 1, approvedWinners,
		"exactly one concurrent poll of the same approved QR session must mint tokens; got %d", approvedWinners)
	assert.Equal(t, N-1, consumedLosers,
		"all losers must observe status=consumed")

	// Each winning poll mints a refresh token. Losers must NOT mint
	// extra tokens: total refresh-token rows for the user must equal
	// the single winner.
	repo.mu.Lock()
	rtCount := 0
	for _, rt := range repo.refreshTokens {
		if rt.UserID == user.ID {
			rtCount++
		}
	}
	repo.mu.Unlock()
	assert.Equal(t, 1, rtCount,
		"only the winning poll may write a refresh-token row; got %d", rtCount)
}

// ── TOTP ────────────────────────────────────────────────────────────────

func TestTotpSetup_ReturnsSecretAndCodes(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "totp@example.com", "", "active")

	secret, qrURI, codes, err := svc.BeginTotpSetup(context.Background(), u.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.Contains(t, qrURI, "otpauth://totp/")
	assert.Len(t, codes, 10)
}

func TestTotpSetup_VerifyInvalidCodeFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "totp2@example.com", "", "active")

	_, _, _, err := svc.BeginTotpSetup(context.Background(), u.ID)
	require.NoError(t, err)

	ok, err := svc.VerifyTotpSetup(context.Background(), u.ID, "000000")
	require.Error(t, err)
	assert.False(t, ok)
	assert.True(t, errors.Is(err, ErrInvalidTotpCode))
}

func TestDisableTotp_RequiresPassword(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	u := seedUser(repo, "disable-totp@example.com", pwHash, "active")
	u.TotpRequired = true

	err := svc.DisableTotp(context.Background(), u.ID, "WrongP@ss1!")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))

	err = svc.DisableTotp(context.Background(), u.ID, strongPW)
	require.NoError(t, err)
}

func TestRegenerateRecoveryCodes_RequiresPassword(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	u := seedUser(repo, "regen@example.com", pwHash, "active")
	u.TotpRequired = true

	_, err := svc.RegenerateRecoveryCodes(context.Background(), u.ID, "WrongP@ss1!")
	require.Error(t, err)

	codes, err := svc.RegenerateRecoveryCodes(context.Background(), u.ID, strongPW)
	require.NoError(t, err)
	assert.Len(t, codes, 10)
}

func TestRegenerateRecoveryCodes_RequiresTotpEnabled(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "noregen@example.com", pwHash, "active")

	u, _ := repo.FindUserByEmail(context.Background(), "noregen@example.com")
	_, err := svc.RegenerateRecoveryCodes(context.Background(), u.ID, strongPW)
	require.Error(t, err)
}

// ── AcceptInvitation ────────────────────────────────────────────────────

func TestAcceptInvitation_Success(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	// Create invited user.
	u := seedUser(repo, "invited@example.com", "", "invited")

	// Create invitation.
	rawToken := "test-invitation-token-abc123"
	tokenHash := hashInvitationToken(rawToken)
	seedInvitation(repo, &InvitationRecord{
		TokenHash: tokenHash,
		Email:     "invited@example.com",
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})

	result, err := svc.AcceptInvitation(context.Background(), rawToken, strongPW, "New Name", "", "")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "invited@example.com", result.User.Email)
	assert.Equal(t, "New Name", result.User.Name)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
}

func TestAcceptInvitation_ExpiredFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "inv-expired@example.com", "", "invited")

	rawToken := "expired-token"
	tokenHash := hashInvitationToken(rawToken)
	seedInvitation(repo, &InvitationRecord{
		TokenHash: tokenHash,
		Email:     "inv-expired@example.com",
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(-time.Hour).UnixMilli(), // expired
		CreatedAt: time.Now().UnixMilli(),
	})

	_, err := svc.AcceptInvitation(context.Background(), rawToken, strongPW, "", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvitationExpired))
}

func TestAcceptInvitation_AlreadyAcceptedFails(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "inv-used@example.com", "", "invited")

	rawToken := "used-token"
	tokenHash := hashInvitationToken(rawToken)
	seedInvitation(repo, &InvitationRecord{
		TokenHash:  tokenHash,
		Email:      "inv-used@example.com",
		UserID:     u.ID,
		ExpiresAt:  time.Now().Add(time.Hour).UnixMilli(),
		AcceptedAt: time.Now().UnixMilli(), // already accepted
		CreatedAt:  time.Now().UnixMilli(),
	})

	_, err := svc.AcceptInvitation(context.Background(), rawToken, strongPW, "", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvitationUsed))
}

// ── VerifyTotp with recovery code ───────────────────────────────────────

func TestVerifyTotp_RecoveryCodeWorks(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	u := seedUser(repo, "recovery@example.com", pwHash, "active")
	u.TotpRequired = true

	// Set up TOTP credential (verified).
	encrypted, err := totp.EncryptSecret("JBSWY3DPEHPK3PXP", testTotpKey())
	require.NoError(t, err)
	repo.mu.Lock()
	credID := nextNodeID()
	repo.totpCreds[credID] = &TotpCredRecord{
		NodeID:          credID,
		UserID:          u.ID,
		SecretEncrypted: encrypted,
		Verified:        true,
	}
	repo.mu.Unlock()

	// Store a recovery code.
	recoveryCode := "ABCDEFGHJK"
	codeHash := totp.HashRecoveryCode(recoveryCode, testTotpRecoveryPepper())
	repo.mu.Lock()
	rcID := nextNodeID()
	repo.recoveryCodes[rcID] = &RecoveryCodeRecord{
		NodeID:   rcID,
		UserID:   u.ID,
		CodeHash: codeHash,
		Used:     false,
	}
	repo.mu.Unlock()

	// Create login challenge.
	challengeID := "test-challenge-123"
	repo.mu.Lock()
	lcID := nextNodeID()
	repo.loginChallenges[lcID] = &LoginChallengeRecord{
		NodeID:      lcID,
		ChallengeID: challengeID,
		UserID:      u.ID,
		ExpiresAt:   time.Now().Add(5 * time.Minute).UnixMilli(),
		CreatedAt:   time.Now().UnixMilli(),
	}
	repo.mu.Unlock()

	result, err := svc.VerifyTotp(context.Background(), challengeID, recoveryCode, "", "")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, u.ID, result.User.ID)
	assert.NotEmpty(t, result.AccessToken)

	// Recovery code should be marked used.
	repo.mu.Lock()
	rc := repo.recoveryCodes[rcID]
	repo.mu.Unlock()
	assert.True(t, rc.Used)
}

// TestVerifyTotp_RecoveryCodePepperMismatch confirms that a recovery
// code stored under a different pepper is rejected. A stolen DB with
// the old hashes is useless once the pepper rotates.
func TestVerifyTotp_RecoveryCodePepperMismatch(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	u := seedUser(repo, "pepper-mismatch@example.com", pwHash, "active")
	u.TotpRequired = true

	encrypted, err := totp.EncryptSecret("JBSWY3DPEHPK3PXP", testTotpKey())
	require.NoError(t, err)
	repo.mu.Lock()
	credID := nextNodeID()
	repo.totpCreds[credID] = &TotpCredRecord{
		NodeID:          credID,
		UserID:          u.ID,
		SecretEncrypted: encrypted,
		Verified:        true,
	}
	repo.mu.Unlock()

	// Store the recovery code hashed under a DIFFERENT pepper than the
	// service uses. The service must refuse to verify it.
	recoveryCode := "ABCDEFGHJK"
	wrongPepper := []byte("a-completely-different-pepper-32by")
	codeHash := totp.HashRecoveryCode(recoveryCode, wrongPepper)
	require.NotEmpty(t, codeHash)
	repo.mu.Lock()
	rcID := nextNodeID()
	repo.recoveryCodes[rcID] = &RecoveryCodeRecord{
		NodeID:   rcID,
		UserID:   u.ID,
		CodeHash: codeHash,
		Used:     false,
	}
	repo.mu.Unlock()

	challengeID := "test-challenge-pepper-mismatch"
	repo.mu.Lock()
	lcID := nextNodeID()
	repo.loginChallenges[lcID] = &LoginChallengeRecord{
		NodeID:      lcID,
		ChallengeID: challengeID,
		UserID:      u.ID,
		ExpiresAt:   time.Now().Add(5 * time.Minute).UnixMilli(),
		CreatedAt:   time.Now().UnixMilli(),
	}
	repo.mu.Unlock()

	_, err = svc.VerifyTotp(context.Background(), challengeID, recoveryCode, "", "")
	require.Error(t, err, "verify must fail when recovery code was hashed with a different pepper")

	// The code must remain unused so the user is not silently locked out
	// by a successful-looking flow.
	repo.mu.Lock()
	rc := repo.recoveryCodes[rcID]
	repo.mu.Unlock()
	assert.False(t, rc.Used)
}

// ── Passkey registration ────────────────────────────────────────────────

func TestBeginPasskeyRegistration_ReturnsOptions(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	u := seedUser(repo, "passkey@example.com", "", "active")

	optionsJSON, challengeID, err := svc.BeginPasskeyRegistration(context.Background(), u.ID, "My Key")
	require.NoError(t, err)
	assert.NotEmpty(t, optionsJSON)
	assert.NotEmpty(t, challengeID)
}

func TestBeginPasskeyLogin_ReturnsOptions(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	optionsJSON, challengeID, err := svc.BeginPasskeyLogin(context.Background(), "")
	require.NoError(t, err)
	assert.NotEmpty(t, optionsJSON)
	assert.NotEmpty(t, challengeID)
}

// ── FriendlyDeviceName ──────────────────────────────────────────────────

func TestFriendlyDeviceName(t *testing.T) {
	tests := []struct {
		ua       string
		expected string
	}{
		{"", "Unknown device"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36", "Chrome on macOS"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0", "Edge on Windows"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0", "Firefox on Windows"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.0 Safari/605.1.15", "Safari on macOS"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15", "Browser on iOS"},
		{"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0 Safari/537.36", "Chrome on Android"},
		{"PostmanRuntime/7.36.0", "Postman on Unknown OS"},
		{"curl/7.68.0", "curl on Unknown OS"},
		{"Go-http-client/2.0 (linux)", "Browser on Linux"},
	}
	for _, tc := range tests {
		result := friendlyDeviceName(tc.ua)
		assert.Equal(t, tc.expected, result, "ua=%q", tc.ua)
	}
}

func TestTokenExpiryHelpers(t *testing.T) {
	assert.Equal(t, int32(0), secondsToInt32(0))
	assert.Equal(t, int32(0), secondsToInt32(-1))
	assert.Equal(t, maxInt32, secondsToInt32(int(maxInt32)+1))
	assert.Equal(t, int32(60), secondsToInt32(60))
	assert.Equal(t, "abc", truncate("abcdef", 3))
	assert.Equal(t, "abc", truncate("abc", 3))
}

// ── Per-email signup throttle ──────────────────────────────────────────

func TestPasswordSignup_PerEmailThrottle_ReturnsDecoy(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.SignupEmailCooldownSeconds = 60
	svc.signupThrottle = newEmailSendThrottle(int64(svc.cfg.SignupEmailCooldownSeconds)*1000, 0)

	// First call: succeeds, user created.
	res1, err := svc.PasswordSignup(context.Background(), "throttle@example.com", strongPW, "T", "", 0)
	require.NoError(t, err)
	require.NotNil(t, res1)
	assert.NotContains(t, res1.User.ID, "signup-pending-")

	// Second call within cooldown: must return an anti-enumeration
	// decoy that LOOKS LIKE success but does not create a second user
	// and does not mint a valid refresh token.
	res2, err := svc.PasswordSignup(context.Background(), "throttle@example.com", strongPW, "T", "", 0)
	require.NoError(t, err)
	require.NotNil(t, res2)
	assert.Contains(t, res2.User.ID, "signup-pending-",
		"throttled signup must return synthetic decoy user, not the real one")
	assert.NotEmpty(t, res2.AccessToken)
	assert.NotEmpty(t, res2.RefreshToken)

	// The decoy refresh token must NOT be persisted — proves the
	// throttled caller cannot redeem it.
	_, _, _, err = svc.RefreshToken(context.Background(), res2.RefreshToken, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated),
		"throttled-signup decoy refresh token must not be redeemable")

	// Only ONE user in the repo.
	assert.Len(t, repo.users, 1, "throttled signup must not create a second user")
}

func TestPasswordSignup_PerEmailThrottle_DifferentEmails_Independent(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.SignupEmailCooldownSeconds = 60
	svc.signupThrottle = newEmailSendThrottle(int64(svc.cfg.SignupEmailCooldownSeconds)*1000, 0)

	res1, err := svc.PasswordSignup(context.Background(), "a@example.com", strongPW, "", "", 0)
	require.NoError(t, err)
	assert.NotContains(t, res1.User.ID, "signup-pending-")

	res2, err := svc.PasswordSignup(context.Background(), "b@example.com", strongPW, "", "", 0)
	require.NoError(t, err)
	assert.NotContains(t, res2.User.ID, "signup-pending-",
		"different email must not share throttle state")

	assert.Len(t, repo.users, 2)
}
