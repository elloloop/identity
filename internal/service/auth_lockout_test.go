package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLockout_NFailuresLockAccount verifies that exactly
// LoginMaxFailedAttempts (5) failures with the wrong password trip the
// lockout, after which a (correct) password attempt is rejected with
// ErrAccountLocked.
func TestLockout_NFailuresLockAccount(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "lock@example.com", pwHash, "active")

	for i := 0; i < svc.cfg.LoginMaxFailedAttempts; i++ {
		_, err := svc.PasswordLogin(context.Background(), "lock@example.com", "Wrong-PW!9", "", "")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrUnauthenticated),
			"attempt %d should be Unauthenticated, got %v", i+1, err)
	}

	// (N+1)th attempt with the CORRECT password is still rejected.
	_, err := svc.PasswordLogin(context.Background(), "lock@example.com", strongPW, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAccountLocked),
		"expected ErrAccountLocked after %d failures, got %v",
		svc.cfg.LoginMaxFailedAttempts, err)
}

// TestLockout_LockoutClearsAfterWindow verifies that once the lockout
// duration has elapsed, the same correct password unlocks the account
// and login proceeds.
func TestLockout_LockoutClearsAfterWindow(t *testing.T) {
	repo := newFakeRepo()
	now := time.Now()
	svc := newTestAuthServiceWithTime(t, repo, func() time.Time { return now })
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "expire-lock@example.com", pwHash, "active")

	// Trip the lockout.
	for i := 0; i < svc.cfg.LoginMaxFailedAttempts; i++ {
		_, _ = svc.PasswordLogin(context.Background(), "expire-lock@example.com", "Wrong-PW!9", "", "")
	}

	// Confirm we're locked.
	_, err := svc.PasswordLogin(context.Background(), "expire-lock@example.com", strongPW, "", "")
	require.True(t, errors.Is(err, ErrAccountLocked))

	// Advance the clock past the lockout window.
	now = now.Add(time.Duration(svc.cfg.LoginLockoutSeconds+1) * time.Second)

	result, err := svc.PasswordLogin(context.Background(), "expire-lock@example.com", strongPW, "", "")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.AccessToken)
}

// TestLockout_SuccessResetsCounter verifies that a successful login
// clears the failed-attempt counter, so a subsequent (N-1) failures do
// NOT trip the lockout (the count starts from 0 again after success).
func TestLockout_SuccessResetsCounter(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	u := seedUser(repo, "reset-cnt@example.com", pwHash, "active")

	max := svc.cfg.LoginMaxFailedAttempts
	require.Greater(t, max, 1, "test assumes max > 1")

	// (N-1) failures.
	for i := 0; i < max-1; i++ {
		_, _ = svc.PasswordLogin(context.Background(), "reset-cnt@example.com", "Wrong-PW!9", "", "")
	}
	// Confirm not locked yet.
	repo.mu.Lock()
	pre := repo.users[u.ID].FailedLoginCount
	repo.mu.Unlock()
	assert.Equal(t, max-1, pre, "counter should be N-1 before success")

	// Successful login resets.
	_, err := svc.PasswordLogin(context.Background(), "reset-cnt@example.com", strongPW, "", "")
	require.NoError(t, err)

	repo.mu.Lock()
	post := repo.users[u.ID].FailedLoginCount
	lock := repo.users[u.ID].LockedUntil
	repo.mu.Unlock()
	assert.Equal(t, 0, post, "counter should reset to 0 after success")
	assert.Equal(t, int64(0), lock, "lockedUntil should be 0 after success")

	// Another (N-1) failures must not lock — count is starting from 0.
	for i := 0; i < max-1; i++ {
		_, _ = svc.PasswordLogin(context.Background(), "reset-cnt@example.com", "Wrong-PW!9", "", "")
	}
	_, err = svc.PasswordLogin(context.Background(), "reset-cnt@example.com", strongPW, "", "")
	require.NoError(t, err, "should NOT be locked after only %d failures since reset", max-1)
}

// TestLockout_UnknownEmailDoesNotIncrement asserts that hammering
// PasswordLogin with an email that does NOT exist cannot lock that
// email's eventual real account. This protects against an attacker
// using lockout as a DoS against arbitrary users.
func TestLockout_UnknownEmailDoesNotIncrement(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	// Hammer attempts before the user exists.
	for i := 0; i < svc.cfg.LoginMaxFailedAttempts*3; i++ {
		_, err := svc.PasswordLogin(context.Background(), "ghost@example.com", "Wrong-PW!9", "", "")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrUnauthenticated))
	}

	// Now the real user signs up. Their account must NOT be pre-locked
	// or carrying an inherited counter.
	pwHash := hashPW(t, strongPW)
	u := seedUser(repo, "ghost@example.com", pwHash, "active")
	repo.mu.Lock()
	pre := repo.users[u.ID].FailedLoginCount
	lock := repo.users[u.ID].LockedUntil
	repo.mu.Unlock()
	assert.Equal(t, 0, pre, "fresh account should have FailedLoginCount=0")
	assert.Equal(t, int64(0), lock, "fresh account should have LockedUntil=0")

	result, err := svc.PasswordLogin(context.Background(), "ghost@example.com", strongPW, "", "")
	require.NoError(t, err)
	assert.NotEmpty(t, result.AccessToken)
}

// TestLockout_RepoIncrementErrorPropagated asserts that if the
// IncrementFailedLoginCount repo call errors, login still fails closed
// with ErrUnauthenticated rather than silently succeeding.
func TestLockout_RepoIncrementErrorPropagated(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "broken-repo@example.com", pwHash, "active")

	// Inject a single increment failure for the next failed attempt.
	repo.mu.Lock()
	repo.incrementErrCount = 1
	repo.mu.Unlock()

	_, err := svc.PasswordLogin(context.Background(), "broken-repo@example.com", "Wrong-PW!9", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated),
		"DB error during increment must NOT bypass the auth check; got %v", err)
}

// TestLockout_LockedAccountWithCorrectPassword nails the explicit
// invariant from the spec: while locked, the correct password is
// rejected the same as the wrong one.
func TestLockout_LockedAccountWithCorrectPassword(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	u := seedUser(repo, "still-locked@example.com", pwHash, "active")

	// Manually set the lock far into the future via the new repo method.
	future := time.Now().Add(time.Hour).UnixMilli()
	require.NoError(t, repo.SetUserLockedUntil(context.Background(), u.ID, future))

	_, err := svc.PasswordLogin(context.Background(), "still-locked@example.com", strongPW, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAccountLocked),
		"correct password must still be rejected while locked, got %v", err)
}

// TestLockout_AuditEventsEmitted asserts the four audit events that
// the lockout flow is supposed to emit fire at the right times:
//   - login_failure: on every wrong-password attempt
//   - account_locked: on the attempt that trips the lockout
//   - login_locked: on subsequent attempts during the lockout window
//   - login_success: on a clean post-lockout login
func TestLockout_AuditEventsEmitted(t *testing.T) {
	repo := newFakeRepo()
	rec := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, rec)
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "audit-lock@example.com", pwHash, "active")

	// (N) failures: each emits login_failure; the Nth also emits account_locked.
	for i := 0; i < svc.cfg.LoginMaxFailedAttempts; i++ {
		_, _ = svc.PasswordLogin(context.Background(), "audit-lock@example.com", "Wrong-PW!9", "", "")
	}
	failures := rec.countByEventType("login_failure")
	locked := rec.countByEventType("account_locked")
	assert.Equal(t, svc.cfg.LoginMaxFailedAttempts, failures, "one login_failure per wrong-password attempt")
	assert.Equal(t, 1, locked, "exactly one account_locked event when threshold is tripped")

	// Attempt-during-lockout emits login_locked, not login_failure.
	_, err := svc.PasswordLogin(context.Background(), "audit-lock@example.com", strongPW, "", "")
	require.True(t, errors.Is(err, ErrAccountLocked))
	assert.Equal(t, 1, rec.countByEventType("login_locked"), "exactly one login_locked event")
	assert.Equal(t, svc.cfg.LoginMaxFailedAttempts, rec.countByEventType("login_failure"),
		"login_failure count should not increase during lockout")

	// Clear the lock and try a clean success.
	require.NoError(t, repo.ResetFailedLoginCount(context.Background(), findUserID(t, repo, "audit-lock@example.com")))
	_, err = svc.PasswordLogin(context.Background(), "audit-lock@example.com", strongPW, "", "")
	require.NoError(t, err)
	assert.Equal(t, 1, rec.countByEventType("login_success"))
}

// findUserID looks up a userID by email through the repo's locked map.
func findUserID(t *testing.T, repo *fakeRepo, email string) string {
	t.Helper()
	repo.mu.Lock()
	defer repo.mu.Unlock()
	for _, u := range repo.users {
		if u.Email == email {
			return u.ID
		}
	}
	t.Fatalf("user %s not found", email)
	return ""
}
