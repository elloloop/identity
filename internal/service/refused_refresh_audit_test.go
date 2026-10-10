package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A refused refresh keeps its token, so a client can replay it at will. Each
// account's refusal is audited once per window for each reason, however often
// it is replayed; every replay is still refused, and the next window records
// it again. Accounts are paced apart.
func TestRefusedRefreshAudit_OncePerAccountPerWindow(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	ctx := context.Background()
	now := time.Now()
	svc.nowFunc = func() time.Time { return now }

	var refreshes []string
	for _, addr := range []string{"replayer@example.com", "bystander@example.com"} {
		user := seedUser(repo, addr, "", StatusActive)
		user.EmailVerified = true
		_, refresh, err := svc.issueTokens(ctx, user, "", "")
		require.NoError(t, err)
		require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"email_verified": false, "email_verified_at": int64(0)}))
		refreshes = append(refreshes, refresh)
	}
	svc.cfg.AuthRequireVerifiedEmail = true
	refused := func() int { return writer.countByEventTypeAndDetail("login_failure", "reason", "email_not_verified") }

	for range 5 {
		_, _, _, err := svc.RefreshToken(ctx, refreshes[0], "", "")
		require.ErrorIs(t, err, ErrEmailVerificationRequired)
	}
	assert.Equal(t, 1, refused())

	_, _, _, err := svc.RefreshToken(ctx, refreshes[1], "", "")
	require.ErrorIs(t, err, ErrEmailVerificationRequired)
	assert.Equal(t, 2, refused(), "another account's refusal is its own")

	now = now.Add(replayedRefusalAuditWindow)
	_, _, _, err = svc.RefreshToken(ctx, refreshes[0], "", "")
	require.ErrorIs(t, err, ErrEmailVerificationRequired)
	assert.Equal(t, 3, refused(), "the next window records the refusal again")
}

// The date-of-birth step is paced the same way on refresh, and recorded with
// the step that refused. A refused sign-in is a fresh act and is audited
// every time.
func TestRefusedRefreshAudit_DOBStepPacedOnRefreshOnly(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	ctx := context.Background()

	res, err := svc.PasswordSignup(ctx, "dobless@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	enableAgeGate(t, svc, true)

	for range 3 {
		_, _, _, err = svc.RefreshToken(ctx, res.RefreshToken, "", "")
		require.ErrorIs(t, err, ErrDOBRequired)
	}
	for range 2 {
		_, err = svc.PasswordLogin(ctx, "dobless@example.com", strongPW, "", "")
		require.ErrorIs(t, err, ErrDOBRequired)
	}
	assert.Equal(t, 3, writer.countByEventTypeAndDetail("login_failure", "reason", "dob_required"))
	assert.Equal(t, 1, writer.countByEventTypeAndDetail("login_failure", "gate", "refresh"))
	assert.Equal(t, 2, writer.countByEventTypeAndDetail("login_failure", "gate", "sign_in"))
}

// A refresh refused over a lockout keeps its token too, so its login_locked
// row is paced the same way; a refused sign-in is a fresh act and is audited
// every time. Each row names the gate that refused.
func TestRefusedRefreshAudit_LockoutPacedOnRefreshOnly(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	ctx := context.Background()
	now := time.Now()
	svc.nowFunc = func() time.Time { return now }
	user := seedUser(repo, "locked-replayer@example.com", "", StatusActive)
	_, refresh, err := svc.issueTokens(ctx, user, "", "")
	require.NoError(t, err)

	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"locked_until": now.Add(time.Hour).UnixMilli()}))
	for range 5 {
		_, _, _, err = svc.RefreshToken(ctx, refresh, "", "")
		require.ErrorIs(t, err, ErrAccountLocked)
	}
	locked := func() int { return writer.countByEventType("login_locked") }
	assert.Equal(t, 1, locked())
	assert.Equal(t, 1, writer.countByEventTypeAndDetail("login_locked", "gate", "refresh"))

	stored, err := repo.GetUser(ctx, user.ID)
	require.NoError(t, err)
	for range 2 {
		require.ErrorIs(t, svc.checkAccountStatus(ctx, stored, "", "", sessionGateSignIn), ErrAccountLocked)
	}
	assert.Equal(t, 3, locked())
	assert.Equal(t, 2, writer.countByEventTypeAndDetail("login_locked", "gate", "sign_in"))

	now = now.Add(replayedRefusalAuditWindow)
	_, _, _, err = svc.RefreshToken(ctx, refresh, "", "")
	require.ErrorIs(t, err, ErrAccountLocked)
	assert.Equal(t, 4, locked(), "the next window records the refusal again")
}
