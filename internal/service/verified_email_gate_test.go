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
		{"anonymous holding an address", "held@example.com", false, true, false},
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
				assert.Empty(t, rec.Sent(), "a session issued sends no verification email")
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
// refreshed past the gate. The refusal comes before the token is consumed, so
// a client retrying it is refused the same way rather than tripping replay
// detection, and the token rotates normally once the address is verified. A
// refused refresh sends no email, and is audited with the gate that refused.
func TestRefreshToken_VerifiedEmailGate(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	ctx := context.Background()
	user := seedUser(repo, "later@example.com", "", StatusActive)
	user.EmailVerified = true
	_, refresh, err := svc.issueTokens(ctx, user, "", "")
	require.NoError(t, err)

	svc.cfg.AuthRequireVerifiedEmail = true
	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"email_verified": false, "email_verified_at": int64(0)}))

	for range 2 {
		_, _, _, err = svc.RefreshToken(ctx, refresh, "", "")
		require.ErrorIs(t, err, ErrEmailVerificationRequired, "a retry is refused the same way, not as a replay")
	}
	assert.Equal(t, 2, writer.countByEventTypeAndDetail("login_failure", "gate", "refresh"))

	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"email_verified": true, "email_verified_at": time.Now().UnixMilli()}))
	_, access, rotated, err := svc.RefreshToken(ctx, refresh, "", "")
	require.NoError(t, err)
	assert.NotEmpty(t, access)
	assert.NotEqual(t, refresh, rotated)
}

// A refused refresh sends no email: its user did not just sign in.
func TestRefreshToken_VerifiedEmailGateSendsNoEmail(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	ctx := context.Background()
	user := seedUser(repo, "quiet@example.com", "", StatusActive)
	user.EmailVerified = true
	_, refresh, err := svc.issueTokens(ctx, user, "", "")
	require.NoError(t, err)

	svc.cfg.AuthRequireVerifiedEmail = true
	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"email_verified": false, "email_verified_at": int64(0)}))
	_, _, _, err = svc.RefreshToken(ctx, refresh, "", "")
	require.ErrorIs(t, err, ErrEmailVerificationRequired)
	assert.Empty(t, rec.Sent())
}

// A sign-in that proves the address is not refused: a one-time code mailed to
// an unverified account's address verifies it, then signs it in.
func TestVerifiedEmailGate_PasswordlessProofSignsIn(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.cfg.AuthRequireVerifiedEmail = true
	ctx := context.Background()
	user := seedUser(repo, "provenbycode@example.com", "", StatusActive)

	require.NoError(t, svc.RequestEmailLoginCode(ctx, user.Email))
	sent := rec.Sent()
	require.Len(t, sent, 1)
	res, err := svc.VerifyEmailLoginCode(ctx, user.Email, extractCodeFromEmail(t, sent[0].Text), "", "")
	require.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
	assert.True(t, res.User.EmailVerified)
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

// A provider sign-in that does not prove the account's address (a provider
// linked under another address) is refused end to end, audited at the
// sign-in gate, and sent a verification email.
func TestVerifiedEmailGate_ProviderSignInWithoutProofIsRefused(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	svc.cfg.AuthRequireVerifiedEmail = true
	ctx := context.Background()
	user := seedUser(repo, "unproven@example.com", "", StatusActive)
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: user.ID, Provider: "google", ProviderUserID: "sub-linker@example.com", CreatedAt: 1,
	}))

	_, err := svc.OAuthLogin(ctx, OAuthLoginParams{
		Code:        fakeOAuthCode("linker@example.com", "Linker", "", "google"),
		Provider:    "google",
		RedirectURI: "https://app/cb",
	})
	require.ErrorIs(t, err, ErrEmailVerificationRequired)
	assert.Equal(t, 1, writer.countByEventTypeAndDetail("login_failure", "gate", "sign_in"))
	repo.mu.Lock()
	stored := len(repo.refreshTokens)
	repo.mu.Unlock()
	assert.Zero(t, stored)
}

// The backstop where sessions are minted refuses an unproven address on its
// own, silently: the audited gates run before it on every current path.
func TestIssueTokensWithSessionStart_VerifiedEmailBackstop(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	svc.cfg.AuthRequireVerifiedEmail = true
	user := seedUser(repo, "backstop@example.com", "", StatusActive)

	_, _, err := svc.issueTokensWithSessionStart(context.Background(), user, "", "", 0, 0)
	require.ErrorIs(t, err, ErrEmailVerificationRequired)
	assert.Zero(t, writer.countByEventType("login_failure"))
}

// A sign-in that cannot yield a session is not asked for a second factor, so
// no challenge is issued (and no recovery code can be spent on it).
func TestVerifiedEmailGate_RefusesBeforeTheSecondFactor(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.AuthRequireVerifiedEmail = true
	ctx := context.Background()
	user := seedUser(repo, "twofactor@example.com", "", StatusActive)
	user.TotpRequired = true

	res, err := svc.requireSecondFactor(ctx, user, false, "", "")
	require.ErrorIs(t, err, ErrEmailVerificationRequired)
	assert.Nil(t, res)
}

// A refresh for an account that is both unverified and missing a date of
// birth is refused for the address, before the DOB step: completing that step
// could not yield a session. The token is kept.
func TestRefreshToken_VerifiedEmailGateRunsBeforeTheDOBStep(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := context.Background()
	user := seedUser(repo, "nodob@example.com", "", StatusActive)
	user.EmailVerified = true
	_, refresh, err := svc.issueTokens(ctx, user, "", "")
	require.NoError(t, err)

	svc.cfg.AuthRequireVerifiedEmail = true
	svc.cfg.AgeGateRequireDOB = true
	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"email_verified": false, "email_verified_at": int64(0)}))

	for range 2 {
		_, _, _, err = svc.RefreshToken(ctx, refresh, "", "")
		require.ErrorIs(t, err, ErrEmailVerificationRequired)
		require.False(t, errors.Is(err, ErrDOBRequired))
	}
}
