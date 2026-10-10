package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/audit"
)

// approvedQrLogin initiates a QR login and approves it as user, returning the
// session id and the poll secret the scanning device holds.
func approvedQrLogin(ctx context.Context, t *testing.T, svc *AuthService, user *User) (string, string) {
	t.Helper()
	init, err := svc.InitiateQrLogin(ctx, "Phone", "agent", "10.0.0.1")
	require.NoError(t, err)
	status, err := svc.ApproveQrLogin(ctx, init.SessionID, true, user.ID, "approver")
	require.NoError(t, err)
	require.Equal(t, "approved", status)
	return init.SessionID, init.PollSecret
}

func requireQrSessionStatus(ctx context.Context, t *testing.T, repo *fakeRepo, sessionID, want string) {
	t.Helper()
	session, err := repo.FindQrLoginSession(ctx, sessionID)
	require.NoError(t, err)
	require.NotNil(t, session)
	assert.Equal(t, want, session.Status)
}

func refreshTokenCount(repo *fakeRepo, userID string) int {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	n := 0
	for _, rt := range repo.refreshTokens {
		if rt.UserID == userID {
			n++
		}
	}
	return n
}

// An account that may not sign in by any other path gets no session through a
// QR hand-off either, and the refusal leaves the hand-off approved: once the
// account is eligible again, the device's next poll in the window completes.
func TestPollQrLogin_IneligibleAccountRefusedBeforeConsuming(t *testing.T) {
	open := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "p", Access: ProjectAccessConfig{Mode: AccessModeOpen}})
	cases := []struct {
		name    string
		refuse  map[string]any
		restore map[string]any
		access  string
		wantErr error
	}{
		{
			name:    "deactivated",
			refuse:  map[string]any{"status": StatusDeactivated},
			restore: map[string]any{"status": StatusActive},
			access:  AccessModeOpen,
			wantErr: ErrAccountNotActive,
		},
		{
			name:    "invited",
			refuse:  map[string]any{"status": StatusInvited},
			restore: map[string]any{"status": StatusActive},
			access:  AccessModeOpen,
			wantErr: ErrInvitationPending,
		},
		{
			name:    "locked",
			refuse:  map[string]any{"locked_until": time.Now().Add(time.Hour).UnixMilli()},
			restore: map[string]any{"locked_until": int64(0)},
			access:  AccessModeOpen,
			wantErr: ErrAccountLocked,
		},
		{
			name:    "project closed",
			access:  AccessModeClosed,
			wantErr: ErrAccessNotAllowed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo)
			user := seedUser(repo, "qr-gate@example.com", "", StatusActive)
			sessionID, secret := approvedQrLogin(open, t, svc, user)
			if tc.refuse != nil {
				require.NoError(t, repo.UpdateUser(open, user.ID, tc.refuse))
			}

			for range 2 {
				res, err := svc.PollQrLogin(WithProjectScope(open, &ProjectScope{ProjectID: "p", Access: ProjectAccessConfig{Mode: tc.access}}), sessionID, secret, "10.0.0.1", "agent")
				require.ErrorIs(t, err, tc.wantErr, "a retry is refused the same way")
				assert.Nil(t, res)
			}
			requireQrSessionStatus(open, t, repo, sessionID, "approved")
			assert.Zero(t, refreshTokenCount(repo, user.ID), "a refused hand-off writes no session")

			if tc.restore != nil {
				require.NoError(t, repo.UpdateUser(open, user.ID, tc.restore))
			}
			res, err := svc.PollQrLogin(open, sessionID, secret, "10.0.0.1", "agent")
			require.NoError(t, err)
			assert.Equal(t, "approved", res.Status)
			assert.NotEmpty(t, res.AccessToken)
			requireQrSessionStatus(open, t, repo, sessionID, "consumed")
		})
	}
}

// With verification required, a QR hand-off into an account whose address is
// unproven is refused before it is consumed, audited at the QR poll gate and
// sent a verification email; once the address is verified the same hand-off
// completes.
func TestPollQrLogin_UnverifiedAddressRefusedBeforeConsuming(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	writer := newRecordingAuditWriter()
	svc.audit = audit.NewLogger(writer, "test-tenant", nil)
	svc.cfg.AuthRequireVerifiedEmail = true
	ctx := context.Background()
	user := seedUser(repo, "qr-unverified@example.com", "", StatusActive)
	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"email_verified": false, "email_verified_at": int64(0)}))
	sessionID, secret := approvedQrLogin(ctx, t, svc, user)

	res, err := svc.PollQrLogin(ctx, sessionID, secret, "10.0.0.1", "agent")
	require.ErrorIs(t, err, ErrEmailVerificationRequired)
	assert.Nil(t, res)
	requireQrSessionStatus(ctx, t, repo, sessionID, "approved")
	assert.Zero(t, refreshTokenCount(repo, user.ID))
	assert.Equal(t, 1, writer.countByEventTypeAndDetail("login_failure", "gate", "qr_poll"))
	assert.Len(t, rec.Sent(), 1, "a refused sign-in is sent a verification email")

	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"email_verified": true, "email_verified_at": time.Now().UnixMilli()}))
	res, err = svc.PollQrLogin(ctx, sessionID, secret, "10.0.0.1", "agent")
	require.NoError(t, err)
	assert.Equal(t, "approved", res.Status)
	assert.NotEmpty(t, res.AccessToken)

	res, err = svc.PollQrLogin(ctx, sessionID, secret, "10.0.0.1", "agent")
	require.NoError(t, err)
	assert.Equal(t, "consumed", res.Status)
}

// An approved hand-off that was not redeemed within its window expires, so a
// refused hand-off cannot wait indefinitely for its account to become
// eligible.
func TestPollQrLogin_ApprovedSessionExpires(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	user := seedUser(repo, "qr-late@example.com", "", StatusActive)
	ctx := context.Background()
	sessionID, secret := approvedQrLogin(ctx, t, svc, user)

	svc.nowFunc = func() time.Time { return time.Now().Add(time.Hour) }
	res, err := svc.PollQrLogin(ctx, sessionID, secret, "10.0.0.1", "agent")
	require.NoError(t, err)
	assert.Equal(t, "expired", res.Status)
	assert.Empty(t, res.AccessToken)
	requireQrSessionStatus(ctx, t, repo, sessionID, "expired")
	assert.Zero(t, refreshTokenCount(repo, user.ID))
}

// A refused poll leaves the hand-off approved, so the device can replay it at
// will: each account's refusal is audited once per window for each reason,
// however often it polls, and the next window records it again.
func TestPollQrLogin_RefusalAuditPaced(t *testing.T) {
	cases := []struct {
		name    string
		refuse  func(svc *AuthService, now time.Time) map[string]any
		wantErr error
		count   func(w *recordingAuditWriter) int
	}{
		{
			name: "unverified address",
			refuse: func(svc *AuthService, _ time.Time) map[string]any {
				svc.cfg.AuthRequireVerifiedEmail = true
				return map[string]any{"email_verified": false, "email_verified_at": int64(0)}
			},
			wantErr: ErrEmailVerificationRequired,
			count: func(w *recordingAuditWriter) int {
				return w.countByEventTypeAndDetail("login_failure", "gate", "qr_poll")
			},
		},
		{
			name: "locked",
			refuse: func(_ *AuthService, now time.Time) map[string]any {
				return map[string]any{"locked_until": now.Add(time.Hour).UnixMilli()}
			},
			wantErr: ErrAccountLocked,
			count:   func(w *recordingAuditWriter) int { return w.countByEventType("login_locked") },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeRepo()
			writer := newRecordingAuditWriter()
			svc := newTestAuthServiceWithAudit(t, repo, writer)
			ctx := context.Background()
			now := time.Now()
			svc.nowFunc = func() time.Time { return now }
			svc.cfg.QRLoginExpirySeconds = int(2 * replayedRefusalAuditWindow / time.Second)
			user := seedUser(repo, "qr-replayer@example.com", "", StatusActive)
			sessionID, secret := approvedQrLogin(ctx, t, svc, user)
			require.NoError(t, repo.UpdateUser(ctx, user.ID, tc.refuse(svc, now)))

			for range 5 {
				_, err := svc.PollQrLogin(ctx, sessionID, secret, "10.0.0.1", "agent")
				require.ErrorIs(t, err, tc.wantErr)
			}
			assert.Equal(t, 1, tc.count(writer))

			now = now.Add(replayedRefusalAuditWindow)
			_, err := svc.PollQrLogin(ctx, sessionID, secret, "10.0.0.1", "agent")
			require.ErrorIs(t, err, tc.wantErr)
			assert.Equal(t, 2, tc.count(writer), "the next window records the refusal again")
		})
	}
}
