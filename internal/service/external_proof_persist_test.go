package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errVerifiedWriteFailed = errors.New("disk full")

// A proof whose verified flag cannot be stored leaves the account exactly as
// the store has it, so nothing downstream reads it as verified.
func TestExternalProof_FailedWriteLeavesUserUnverified(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	seeded := seedUser(repo, "owner@example.com", hashPW(t, strongPW), "active")
	user, err := repo.GetUser(ctx, seeded.ID)
	require.NoError(t, err)
	repo.updateUserErr = errVerifiedWriteFailed

	err = svc.markEmailVerifiedViaExternalProof(ctx, user, externalProof{address: user.Email, method: "oauth"}, nowMs())

	require.ErrorIs(t, err, errVerifiedWriteFailed)
	assert.False(t, user.EmailVerified)
	assert.Zero(t, user.EmailVerifiedAt)
	assert.NotEmpty(t, user.PasswordHash)
}

// The sign-in that brought the proof fails rather than issuing a token that
// claims a verified address the store still holds unverified.
func TestExternalProof_FailedWriteFailsTheSignIn(t *testing.T) {
	t.Run("oauth", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		svc.cfg.AuthRequireVerifiedEmail = false
		seedUser(repo, "owner@example.com", "", "active")
		repo.updateUserErr = errVerifiedWriteFailed

		res, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{
			Code: fakeOAuthCode("owner@example.com", "Owner", "", "google"), Provider: "google",
			RedirectURI: "https://app/cb",
		})

		require.ErrorIs(t, err, errVerifiedWriteFailed)
		assert.Nil(t, res)
	})
	t.Run("passwordless", func(t *testing.T) {
		svc, repo, rec := passwordlessSvc(t)
		svc.cfg.AuthRequireVerifiedEmail = false
		ctx := context.Background()
		seedUser(repo, "owner@example.com", "", "active")
		require.NoError(t, svc.RequestEmailLoginCode(ctx, "owner@example.com"))
		code := extractCodeFromEmail(t, rec.Sent()[0].Text)
		repo.updateUserErr = errVerifiedWriteFailed

		res, err := svc.VerifyEmailLoginCode(ctx, "owner@example.com", code, "", "")

		require.ErrorIs(t, err, errVerifiedWriteFailed)
		assert.Nil(t, res)
	})
}
