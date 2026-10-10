package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With verification required, no path issues a session to an account whose
// address is unproven: the gate sits where every session is minted. An
// account with no address, an anonymous one, or a proven one is unaffected.
func TestIssueTokens_VerifiedEmailGate(t *testing.T) {
	cases := []struct {
		name      string
		email     string
		verified  bool
		anonymous bool
		wantErr   bool
	}{
		{"unproven address", "unproven@example.com", false, false, true},
		{"proven address", "proven@example.com", true, false, false},
		{"no address", "", false, false, false},
		{"anonymous", "", false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, rec := newAuthSvcWithMailer(t)
			svc.cfg.AuthRequireVerifiedEmail = true
			user := seedUser(repo, tc.email, "", StatusActive)
			user.EmailVerified = tc.verified
			user.IsAnonymous = tc.anonymous

			access, refresh, err := svc.issueTokens(context.Background(), user, "", "")
			if !tc.wantErr {
				require.NoError(t, err)
				assert.NotEmpty(t, access)
				return
			}
			require.ErrorIs(t, err, ErrEmailVerificationRequired)
			assert.Empty(t, access)
			assert.Empty(t, refresh)
			repo.mu.Lock()
			stored := len(repo.refreshTokens)
			repo.mu.Unlock()
			assert.Zero(t, stored, "a refused session writes nothing")
			assert.Len(t, rec.Sent(), 1, "a refused sign-in is sent a verification email")
		})
	}
}

// A session opened before an account's address became unproven cannot be
// refreshed past the gate, and a refused refresh sends no email.
func TestRefreshToken_VerifiedEmailGate(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	ctx := context.Background()
	user := seedUser(repo, "later@example.com", "", StatusActive)
	user.EmailVerified = true
	_, refresh, err := svc.issueTokens(ctx, user, "", "")
	require.NoError(t, err)

	svc.cfg.AuthRequireVerifiedEmail = true
	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"email_verified": false, "email_verified_at": int64(0)}))

	_, _, _, err = svc.RefreshToken(ctx, refresh, "", "")
	require.ErrorIs(t, err, ErrEmailVerificationRequired)
	assert.Empty(t, rec.Sent(), "a refresh is not a sign-in, so it sends no email")
}

// Redeeming an invitation does not prove the address, since the token is
// shown to the inviting admin too. With verification required, the invitee is
// sent a verification email instead of a session, and signs in once it is
// redeemed.
func TestAcceptInvitation_UnprovenInviteeGetsVerificationNotSession(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.cfg.AuthRequireVerifiedEmail = true
	ctx := context.Background()
	u := seedUser(repo, "invitee@example.com", "", StatusInvited)
	const rawToken = "invitation-token-for-gate"
	seedInvitation(repo, &InvitationRecord{
		TokenHash: hashInvitationToken(rawToken),
		Email:     u.Email,
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})

	res, err := svc.AcceptInvitation(ctx, rawToken, strongPW, "Invitee", "", "")
	require.NoError(t, err)
	assert.Equal(t, u.ID, res.User.ID)
	assert.Empty(t, res.AccessToken)
	assert.Empty(t, res.RefreshToken)
	require.Len(t, rec.Sent(), 1)

	_, err = svc.PasswordLogin(ctx, u.Email, strongPW, "", "")
	require.True(t, errors.Is(err, ErrEmailVerificationRequired), "unproven until the link is redeemed: %v", err)

	_, err = svc.VerifyEmail(ctx, extractTokenFromLink(t, rec.Sent()[0].Text))
	require.NoError(t, err)
	login, err := svc.PasswordLogin(ctx, u.Email, strongPW, "", "")
	require.NoError(t, err)
	assert.NotEmpty(t, login.AccessToken)
}
