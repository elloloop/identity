package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/jwt"
)

func authTimeOf(t *testing.T, svc *AuthService, access string) int64 {
	t.Helper()
	claims, err := jwt.VerifyAccessToken(access, svc.signer, "", "", false)
	require.NoError(t, err)
	return claims.AuthTime
}

// A QR handoff proves no credential on the new device: its session carries
// no auth_time, so a stolen session cannot launder itself into a "recent
// sign-in" by approving its own QR login, and a merge from it is refused.
func TestAuthTime_QrHandoffIsNotASignIn(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.AccountMergeEnabled = true
	ctx := context.Background()
	user := seedUser(repo, "qr@example.com", "", StatusActive)
	user.EmailVerified = true
	seedUser(repo, "other@example.com", hashPW(t, strongPW), StatusActive).EmailVerified = true

	init, err := svc.InitiateQrLogin(ctx, "Pixel 8", "agent", "203.0.113.10")
	require.NoError(t, err)
	_, err = svc.ApproveQrLogin(ctx, init.SessionID, true, user.ID, "ApproverAgent")
	require.NoError(t, err)
	res, err := svc.PollQrLogin(ctx, init.SessionID, init.PollSecret, "203.0.113.10", "agent")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	authTime := authTimeOf(t, svc, res.AccessToken)
	require.Zero(t, authTime, "a QR session has no sign-in on record")

	_, err = svc.MergeAccounts(ctx, user.ID, authTime, "other@example.com", strongPW, "203.0.113.10", "agent", false)
	require.ErrorIs(t, err, ErrReauthenticationRequired)
	_, newAccess, _, err := svc.RefreshToken(ctx, res.RefreshToken, "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Zero(t, authTimeOf(t, svc, newAccess), "nor does its refresh")
}

// The required-DOB step continues the session it interrupted: reached from a
// refresh, it does not turn that refresh into a new sign-in.
func TestAuthTime_DOBCompletionContinuesTheSession(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	signedInAt := time.Now().Add(-time.Hour).Truncate(time.Second)
	svc.nowFunc = func() time.Time { return signedInAt }
	res, err := svc.PasswordSignup(ctx, "dob-later@example.com", strongPW, "Later", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	svc.nowFunc = time.Now

	enableAgeGate(t, svc, true)
	_, _, _, err = svc.RefreshToken(ctx, res.RefreshToken, "203.0.113.10", "agent")
	ticket := dobTicketFrom(t, err)
	done, err := svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(30), "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Zero(t, authTimeOf(t, svc, done.AccessToken), "a refresh behind it: no sign-in")

	seedUser(repo, "dob-signin@example.com", hashPW(t, strongPW), StatusActive)
	svc.nowFunc = func() time.Time { return signedInAt }
	_, err = svc.PasswordLogin(ctx, "dob-signin@example.com", strongPW, "203.0.113.10", "agent")
	svc.nowFunc = time.Now
	ticket = dobTicketFrom(t, err)
	done, err = svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(30), "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Equal(t, signedInAt.Unix(), authTimeOf(t, svc, done.AccessToken), "the sign-in behind it, not now")
}

// A refresh row from before sessions were anchored has no sign-in on record.
func TestAuthTime_UnanchoredRefreshHasNone(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	seedUser(repo, "legacy@example.com", hashPW(t, strongPW), StatusActive)
	login, err := svc.PasswordLogin(ctx, "legacy@example.com", strongPW, "203.0.113.10", "agent")
	require.NoError(t, err)
	row, err := repo.FindRefreshTokenByHash(ctx, sha256Hex(login.RefreshToken))
	require.NoError(t, err)
	row.SessionStartedAt = 0

	_, access, _, err := svc.RefreshToken(ctx, login.RefreshToken, "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Zero(t, authTimeOf(t, svc, access))
}
