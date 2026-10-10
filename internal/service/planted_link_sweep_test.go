package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func linkedProviders(t *testing.T, repo *fakeRepo, userID string) []string {
	t.Helper()
	links, err := repo.ListOAuthIdentitiesForUser(context.Background(), userID)
	require.NoError(t, err)
	out := make([]string, 0, len(links))
	for _, l := range links {
		out = append(out, l.Provider+"/"+l.ProviderUserID)
	}
	return out
}

// A provider link added to an account before its address was proven is as
// untrusted as a planted password: when the owner proves the address with an
// emailed code, the link is voided, and it no longer signs in to the account.
func TestPasswordlessProof_VoidsPlantedProviderLink(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	ctx := context.Background()
	victim := seedUser(repo, "victim@example.com", "", StatusActive)
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: victim.ID, Provider: "google", ProviderUserID: "sub-planter@example.com",
		EmailAtLinkTime: "victim@example.com", CreatedAt: 1,
	}))
	// The account holds no password or passkey, so only the link is voided;
	// that alone must revoke the sessions it could have opened.
	const plantedSessionHash = "planted-link-session-hash"
	_, err := repo.CreateRefreshToken(ctx, &RefreshTokenRecord{
		TokenHash: plantedSessionHash, UserID: victim.ID, ExpiresAt: 1 << 62,
	})
	require.NoError(t, err)

	require.NoError(t, svc.RequestEmailLoginCode(ctx, "victim@example.com"))
	res, err := svc.VerifyEmailLoginCode(ctx, "victim@example.com", extractCodeFromEmail(t, rec.Sent()[0].Text), "", "")
	require.NoError(t, err)
	require.Equal(t, victim.ID, res.User.ID)
	assert.True(t, res.User.EmailVerified)
	assert.Empty(t, linkedProviders(t, repo, victim.ID), "the planted link is voided")

	found, err := repo.FindUserByProviderID(ctx, "google", "sub-planter@example.com")
	require.NoError(t, err)
	assert.Nil(t, found, "the voided link no longer signs in to the account")

	tok, err := repo.FindRefreshTokenByHash(ctx, plantedSessionHash)
	require.NoError(t, err)
	assert.Nil(t, tok, "a session the voided link could have opened is revoked")
}

// A provider sign-in that proves the address keeps its own link and voids
// every other link added while the address was unproven.
func TestOAuthProof_KeepsProvingLinkAndVoidsOthers(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	owner := seedUser(repo, "owner@example.com", "", StatusActive)
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: owner.ID, Provider: "github", ProviderUserID: "sub-planter@example.com",
		EmailAtLinkTime: "owner@example.com", CreatedAt: 1,
	}))
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: owner.ID, Provider: "google", ProviderUserID: "sub-owner@example.com",
		EmailAtLinkTime: "owner@example.com", CreatedAt: 2,
	}))

	res := oauthLoginAs(t, svc, "owner@example.com")
	require.Equal(t, owner.ID, res.User.ID)
	assert.True(t, res.User.EmailVerified)
	assert.Equal(t, []string{"google/sub-owner@example.com"}, linkedProviders(t, repo, owner.ID))
}

// An address that is already proven gains nothing from another proof, so the
// account's provider links are left alone.
func TestExternalProof_VerifiedAccountKeepsItsLinks(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	ctx := context.Background()
	user := seedUser(repo, "kept@example.com", "", StatusActive)
	user.EmailVerified = true
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: user.ID, Provider: "google", ProviderUserID: "sub-kept@example.com",
		EmailAtLinkTime: "kept@example.com", CreatedAt: 1,
	}))

	require.NoError(t, svc.RequestEmailLoginCode(ctx, "kept@example.com"))
	_, err := svc.VerifyEmailLoginCode(ctx, "kept@example.com", extractCodeFromEmail(t, rec.Sent()[0].Text), "", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"google/sub-kept@example.com"}, linkedProviders(t, repo, user.ID))
}

// A provider address with a "+tag" outside Gmail canonicalizes to an existing
// account's address without proving it. Such a sign-in neither signs in to the
// account nor links to it, or it would put back a link the proof just voided.
func TestOAuthLogin_TaggedAddressDoesNotClaimExistingAccount(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	owner := seedUser(repo, "someone@example.com", "", StatusActive)
	owner.EmailVerified = true

	res, err := svc.OAuthLogin(ctx, OAuthLoginParams{
		Code:        fakeOAuthCode("someone+x@example.com", "Someone", "", "google"),
		Provider:    "google",
		RedirectURI: "https://app/cb",
	})
	require.ErrorIs(t, err, ErrUnauthenticated)
	assert.Nil(t, res)
	assert.Empty(t, linkedProviders(t, repo, owner.ID), "the tagged provider account is not linked")
}

// When the sweep cannot read what the account holds, the proof fails the
// sign-in with a retryable error instead of verifying the address around the
// credentials it could not see. The address stays unproven and nothing is
// issued, so the next proof, once the store answers, sweeps them.
func TestExternalProof_FailsClosedWhenTheSweepCannotRead(t *testing.T) {
	storeDown := errors.New("connection reset by peer")
	cases := map[string]struct {
		fail    func(repo *fakeRepo, err error)
		signIn  func(t *testing.T, svc *AuthService, rec *recordingTransport) (*LoginResult, error)
		proving []string
	}{
		"passwordless, provider links unreadable": {
			fail:   func(repo *fakeRepo, err error) { repo.listOAuthIdentitiesErr = err },
			signIn: passwordlessSignIn("victim@example.com"),
		},
		"passwordless, passkeys unreadable": {
			fail:   func(repo *fakeRepo, err error) { repo.listPasskeyCredsErr = err },
			signIn: passwordlessSignIn("victim@example.com"),
		},
		"provider, provider links unreadable": {
			fail:    func(repo *fakeRepo, err error) { repo.listOAuthIdentitiesErr = err },
			signIn:  oauthSignIn("victim@example.com"),
			proving: []string{"google/sub-victim@example.com"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			svc, repo, rec := passwordlessSvc(t)
			svc.oauthResolver = newOAuthResolver(svc.cfg.DefaultProjectID, defaultTestOAuthRegistry(), svc.cfg.OAuthHubSharing, zap.NewNop())
			ctx := context.Background()
			victim := seedUser(repo, "victim@example.com", "", StatusActive)
			require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
				UserID: victim.ID, Provider: "github", ProviderUserID: "sub-planter",
				EmailAtLinkTime: "victim@example.com", CreatedAt: 1,
			}))

			tc.fail(repo, storeDown)
			res, err := tc.signIn(t, svc, rec)
			require.ErrorIs(t, err, ErrUnavailable)
			assert.NotContains(t, err.Error(), storeDown.Error(), "the store's error is not returned to the caller")
			assert.Nil(t, res)
			stored, err := repo.GetUser(ctx, victim.ID)
			require.NoError(t, err)
			assert.False(t, stored.EmailVerified, "the address stays unproven so the next proof sweeps again")
			tc.fail(repo, nil)
			assert.Contains(t, linkedProviders(t, repo, victim.ID), "github/sub-planter")

			res, err = tc.signIn(t, svc, rec)
			require.NoError(t, err)
			assert.True(t, res.User.EmailVerified)
			want := tc.proving
			if want == nil {
				want = []string{}
			}
			assert.ElementsMatch(t, want, linkedProviders(t, repo, victim.ID), "the retried proof voids the planted link")
		})
	}
}

func passwordlessSignIn(addr string) func(*testing.T, *AuthService, *recordingTransport) (*LoginResult, error) {
	return func(t *testing.T, svc *AuthService, rec *recordingTransport) (*LoginResult, error) {
		t.Helper()
		require.NoError(t, svc.RequestEmailLoginCode(context.Background(), addr))
		sent := rec.Sent()
		return svc.VerifyEmailLoginCode(context.Background(), addr, extractCodeFromEmail(t, sent[len(sent)-1].Text), "", "")
	}
}

func oauthSignIn(addr string) func(*testing.T, *AuthService, *recordingTransport) (*LoginResult, error) {
	return func(_ *testing.T, svc *AuthService, _ *recordingTransport) (*LoginResult, error) {
		return svc.OAuthLogin(context.Background(), OAuthLoginParams{
			Code:        fakeOAuthCode(addr, "Someone", "", "google"),
			Provider:    "google",
			RedirectURI: "https://app/cb",
		})
	}
}
