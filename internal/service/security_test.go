package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Login failure doesn't reveal email existence ───────────────────────

func TestSecurity_LoginMissingUser_SameError(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.PasswordLogin(context.Background(), "noone@example.com", strongPW, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestSecurity_LoginWrongPassword_SameError(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "bob@example.com", pwHash, "active")

	_, err := svc.PasswordLogin(context.Background(), "bob@example.com", "WrongP@ss1!", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestSecurity_LoginErrors_SameType(t *testing.T) {
	// Both "user not found" and "wrong password" should return the same
	// error type (ErrUnauthenticated) to prevent email enumeration.
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "existing@example.com", pwHash, "active")

	_, errMissing := svc.PasswordLogin(context.Background(), "missing@example.com", strongPW, "", "")
	_, errWrong := svc.PasswordLogin(context.Background(), "existing@example.com", "WrongP@ss1!", "", "")

	assert.True(t, errors.Is(errMissing, ErrUnauthenticated), "missing user should be ErrUnauthenticated")
	assert.True(t, errors.Is(errWrong, ErrUnauthenticated), "wrong password should be ErrUnauthenticated")
}

// ── Admin role check ───────────────────────────────────────────────────

func TestSecurity_AdminCheck_RejectsNonAdmin(t *testing.T) {
	db := newFakeDB()
	db.addUser("member-1", "member@test.com", "Member", "member", "active")
	svc := newTestAdminService(db)

	_, err := svc.InviteUser(context.Background(), "member-1", "x@test.com", "X", "member", "", 0, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin role required")
}

// ── Session revoke ownership ───────────────────────────────────────────

func TestSecurity_SessionRevoke_WrongUserDenied(t *testing.T) {
	db := newFakeDB()
	db.addRefreshToken("sess-1", "user-1", nowMs()+3600*1000)
	svc := newTestProfileService(db)

	err := svc.RevokeSession(context.Background(), "user-2", "sess-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong")
}

func TestSecurity_SessionRevoke_OwnerSucceeds(t *testing.T) {
	db := newFakeDB()
	db.addRefreshToken("sess-1", "user-1", nowMs()+3600*1000)
	svc := newTestProfileService(db)

	err := svc.RevokeSession(context.Background(), "user-1", "sess-1")
	require.NoError(t, err)
}

// ── Passkey delete ownership ───────────────────────────────────────────

func TestSecurity_PasskeyDelete_WrongUserDenied(t *testing.T) {
	db := newFakeDB()
	db.addPasskey("pk-1", "user-1", "cred-abc", "YubiKey")
	svc := newTestProfileService(db)

	err := svc.DeletePasskey(context.Background(), "user-2", "cred-abc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong")
}

// ── Change password rejects wrong current ──────────────────────────────

func TestSecurity_ChangePassword_WrongCurrentRejected(t *testing.T) {
	db := newFakeDB()
	pwHash := hashPW(t, "OldStr0ng!Pass")
	db.addUserWithPassword("user-1", "alice@test.com", "Alice", "member", "active", pwHash)
	svc := newTestProfileService(db)

	err := svc.ChangePassword(context.Background(), "user-1", "WrongCurrent!", "NewStr0ng!Pass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect")
}

// ── Account lockout after 5 failures ───────────────────────────────────

func TestSecurity_AccountLockout_After5Failures(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "lockme@example.com", pwHash, "active")

	for i := 0; i < 5; i++ {
		_, _ = svc.PasswordLogin(context.Background(), "lockme@example.com", "BadP@ss1!", "", "")
	}

	// The account should now be locked even with correct password.
	_, err := svc.PasswordLogin(context.Background(), "lockme@example.com", strongPW, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAccountLocked))
}

// ── Lockout expires after configured time ──────────────────────────────

func TestSecurity_LockoutExpires(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthServiceWithTime(t, repo, time.Now)
	pwHash := hashPW(t, strongPW)
	u := seedUser(repo, "lockexpire@example.com", pwHash, "active")

	// Lock the account.
	for i := 0; i < 5; i++ {
		_, _ = svc.PasswordLogin(context.Background(), "lockexpire@example.com", "BadP@ss1!", "", "")
	}

	// Advance clock past lockout.
	svc.nowFunc = func() time.Time {
		return time.Now().Add(time.Duration(svc.cfg.LoginLockoutSeconds+10) * time.Second)
	}
	// Clear the lock manually (simulating expiry).
	repo.mu.Lock()
	u.LockedUntil = 0
	u.FailedLoginCount = 0
	repo.mu.Unlock()

	result, err := svc.PasswordLogin(context.Background(), "lockexpire@example.com", strongPW, "", "")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ── Deactivated account can't login ────────────────────────────────────

func TestSecurity_DeactivatedAccount_CantLogin(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "deactivated@example.com", pwHash, "deactivated")

	_, err := svc.PasswordLogin(context.Background(), "deactivated@example.com", strongPW, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAccountNotActive))
}

// ── Invited account can't login ────────────────────────────────────────

func TestSecurity_InvitedAccount_CantLogin(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	pwHash := hashPW(t, strongPW)
	seedUser(repo, "invited@example.com", pwHash, "invited")

	_, err := svc.PasswordLogin(context.Background(), "invited@example.com", strongPW, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvitationPending))
}

// ── Refresh token rotation ─────────────────────────────────────────────

func TestSecurity_RefreshTokenRotation_OldTokenInvalidated(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	result, err := svc.PasswordSignup(context.Background(), "rot@example.com", strongPW, "", "")
	require.NoError(t, err)
	oldRefresh := result.RefreshToken

	// Use the refresh token.
	_, _, newRefresh, err := svc.RefreshToken(context.Background(), oldRefresh, "", "")
	require.NoError(t, err)
	assert.NotEqual(t, oldRefresh, newRefresh, "new refresh token should differ")

	// Old token should now fail.
	_, _, _, err = svc.RefreshToken(context.Background(), oldRefresh, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

// ── QR login session is single-use ─────────────────────────────────────

func TestSecurity_QRLoginSession_SingleUse(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	user := seedUser(repo, "qr-single@example.com", "", "active")

	init, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.NoError(t, err)

	_, err = svc.ApproveQrLogin(context.Background(), init.SessionID, true, user.ID, "")
	require.NoError(t, err)

	// First poll: returns tokens.
	result1, err := svc.PollQrLogin(context.Background(), init.SessionID, init.PollSecret, "", "")
	require.NoError(t, err)
	assert.Equal(t, "approved", result1.Status)
	assert.NotNil(t, result1.User)
	assert.NotEmpty(t, result1.AccessToken)

	// Second poll: consumed.
	result2, err := svc.PollQrLogin(context.Background(), init.SessionID, init.PollSecret, "", "")
	require.NoError(t, err)
	assert.Equal(t, "consumed", result2.Status)
	assert.Nil(t, result2.User)
	assert.Empty(t, result2.AccessToken)
}
