package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
