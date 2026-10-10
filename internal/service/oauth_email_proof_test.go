package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func oauthLoginAs(t *testing.T, svc *AuthService, providerEmail string) *LoginResult {
	t.Helper()
	res, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{
		Code:        fakeOAuthCode(providerEmail, "Someone", "", "google"),
		Provider:    "google",
		RedirectURI: "https://app/cb",
	})
	require.NoError(t, err)
	return res
}

// A signed-in user can link a provider account whose address is not the
// account's. Signing in through that link proves the provider's address, not
// the account's: the account stays unverified and keeps its password.
func TestOAuthLogin_LinkedProviderDoesNotVerifyAnotherAddress(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	user := seedUser(repo, "claimed@example.com", hashPW(t, strongPW), StatusActive)

	_, err := svc.LinkIdentity(ctx, user.ID, fakeOAuthCode("linker@example.com", "Linker", "", "google"),
		"google", "https://app/cb", "", "", "")
	require.NoError(t, err)

	res := oauthLoginAs(t, svc, "linker@example.com")
	require.Equal(t, user.ID, res.User.ID)

	stored, err := repo.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, "claimed@example.com", stored.Email)
	assert.False(t, stored.EmailVerified, "the provider never asserted the account's address")
	assert.NotEmpty(t, stored.PasswordHash, "nothing proved the address, so no credential is voided")
}

// An account with no address (a username account) that signs in through a
// linked provider is not marked verified, and keeps its password.
func TestOAuthLogin_LinkedProviderDoesNotVerifyAnAccountWithoutAddress(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	user := seedUser(repo, "", hashPW(t, strongPW), StatusActive)
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: user.ID, Provider: "google", ProviderUserID: "sub-linked@example.com", CreatedAt: 1,
	}))

	res := oauthLoginAs(t, svc, "linked@example.com")
	require.Equal(t, user.ID, res.User.ID)

	stored, err := repo.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.False(t, stored.EmailVerified)
	assert.NotEmpty(t, stored.PasswordHash)
}

// The provider's proof carries to the account's address only when dropping a
// "+tag" to canonicalize it is provably the same mailbox: always at Gmail,
// never elsewhere, where a tagged address may be delivered somewhere else.
func TestOAuthLogin_TaggedAddressProofCarriesOnlyAtGmail(t *testing.T) {
	cases := []struct {
		name          string
		providerEmail string
		wantEmail     string
		wantVerified  bool
	}{
		{"untagged", "plain@example.com", "plain@example.com", true},
		{"gmail tag", "first.last+news@gmail.com", "firstlast@gmail.com", true},
		{"tag elsewhere", "someone+news@example.com", "someone@example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo)

			created := oauthLoginAs(t, svc, tc.providerEmail)
			assert.Equal(t, tc.wantEmail, created.User.Email)
			assert.Equal(t, tc.wantVerified, created.User.EmailVerified, "a new account")

			repo2 := newFakeRepo()
			svc2 := newTestAuthService(t, repo2)
			existing := seedUser(repo2, tc.wantEmail, "", StatusActive)
			found := oauthLoginAs(t, svc2, tc.providerEmail)
			require.Equal(t, existing.ID, found.User.ID)
			stored, err := repo2.GetUser(context.Background(), existing.ID)
			require.NoError(t, err)
			assert.Equal(t, tc.wantVerified, stored.EmailVerified, "an existing account")
		})
	}
}

func TestProofCarriesTo(t *testing.T) {
	cases := []struct {
		proven, stored string
		want           bool
	}{
		{"a@example.com", "a@example.com", true},
		{"A@Example.com", "a@example.com", true},
		{"a.b+x@googlemail.com", "ab@gmail.com", true},
		{"a@example.com", "b@example.com", false},
		{"a@example.com", "", false},
		{"", "", false},
		{"a+x@example.com", "a@example.com", false},
		{"a@example.com", "a+x@example.com", false},
		{"+x@gmail.com", "+x@gmail.com", false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, proofCarriesTo(tc.proven, tc.stored), "%q proves %q", tc.proven, tc.stored)
	}
}
