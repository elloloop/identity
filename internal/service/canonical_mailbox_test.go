package service

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// tagOnlyAddress passes the raw-address checks (validateEmailFormat) but has
// no mailbox left once canonicalization drops its "+tag": it would be stored
// or looked up as "@corp.com".
const tagOnlyAddress = "+x@corp.com"

func TestCanonicalMailbox_RefusesATagOnlyLocalPartThatPassesRawValidation(t *testing.T) {
	require.NoError(t, validateEmailFormat(tagOnlyAddress), "the raw check alone lets it through")
	got, usable := CanonicalMailbox(tagOnlyAddress)
	require.Equal(t, "@corp.com", got)
	require.False(t, usable)
}

// Every path that stores or looks up an account's address from caller input
// refuses an address with no mailbox once canonical, rather than storing or
// querying "@corp.com".
func TestTagOnlyAddressIsRefusedOnEveryAccountPath(t *testing.T) {
	ctx := context.Background()

	t.Run("password signup", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		_, err := svc.PasswordSignup(ctx, tagOnlyAddress, "Str0ng!Pass1-x", "X", "", 0, "")
		require.ErrorIs(t, err, ErrInvalidArgument)
		got, _ := repo.FindUserByEmail(ctx, "@corp.com")
		require.Nil(t, got, "no account stored under @corp.com")
	})

	t.Run("password login", func(t *testing.T) {
		svc := newTestAuthService(t, newFakeRepo())
		_, err := svc.PasswordLogin(ctx, tagOnlyAddress, "Str0ng!Pass1-x", "1.2.3.4", "ua")
		require.ErrorIs(t, err, ErrInvalidArgument)
	})

	t.Run("passkey signup", func(t *testing.T) {
		svc := newTestAuthService(t, newFakeRepo())
		_, _, err := svc.BeginPasskeySignup(ctx, tagOnlyAddress, "laptop")
		require.ErrorIs(t, err, ErrInvalidArgument)
	})

	t.Run("anonymous upgrade", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		actx := anonCtx(true, AccessModeOpen)
		anon, err := svc.SignInAnonymously(actx, "1.2.3.4", "ua")
		require.NoError(t, err)
		_, err = svc.UpgradeAnonymousWithPassword(actx, anon.User.ID, AnonymousPasswordCredential{
			Email: tagOnlyAddress, Password: "Str0ng-Passw0rd!x",
		})
		require.ErrorIs(t, err, ErrInvalidArgument)
	})

	t.Run("first platform admin bootstrap", func(t *testing.T) {
		f := newAdminFixture("")
		_, err := f.svc.CreateFirstPlatformAdmin(ctx, "", tagOnlyAddress, "")
		require.ErrorIs(t, err, ErrInvalidArgument)
	})

	// requireNoTagOnlyAccount checks nothing was created under the address a
	// tag-only one canonicalizes to.
	requireNoTagOnlyAccount := func(t *testing.T, repo *fakeRepo) {
		t.Helper()
		got, err := repo.FindUserByEmail(ctx, "@corp.com")
		require.NoError(t, err)
		require.Nil(t, got, "no account under @corp.com")
	}

	t.Run("oauth login", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		_, err := svc.OAuthLogin(ctx, OAuthLoginParams{
			Code: fakeOAuthCode(tagOnlyAddress, "X", "", "google"), Provider: "google", RedirectURI: "https://app/cb",
		})
		require.ErrorIs(t, err, ErrUnauthenticated)
		requireNoTagOnlyAccount(t, repo)
	})

	t.Run("native oauth login", func(t *testing.T) {
		repo := newFakeRepo()
		signer := newNativeTokenSigner(t)
		svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), nil)
		_, err := svc.NativeOAuthLogin(ctx, NativeOAuthLoginParams{
			Provider: "google", IDToken: signer.googleToken(t, "g-sub-tag", tagOnlyAddress, nativeGoogleAud), Product: "easyloops",
		})
		require.ErrorIs(t, err, ErrUnauthenticated)
		requireNoTagOnlyAccount(t, repo)
	})

	t.Run("anonymous oauth upgrade", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		actx := anonCtx(true, AccessModeOpen)
		anon, err := svc.SignInAnonymously(actx, "1.2.3.4", "ua")
		require.NoError(t, err)
		_, err = svc.UpgradeAnonymousWithOAuth(actx, anon.User.ID, AnonymousOAuthCredential{
			Provider:    testOAuthProvider,
			Code:        fakeOAuthCode(tagOnlyAddress, "X", "", testOAuthProvider),
			RedirectURI: testOAuthRedirect,
		})
		require.ErrorIs(t, err, errNoUsableMailbox)
		requireNoTagOnlyAccount(t, repo)
	})

	t.Run("passkey login", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		seedCredential := func(email, rawID string) string {
			t.Helper()
			u := seedUser(repo, email, "", "active")
			id := base64.RawURLEncoding.EncodeToString([]byte(rawID))
			_, err := repo.CreatePasskeyCredential(ctx, &PasskeyCredRecord{CredentialID: id, UserID: u.ID})
			require.NoError(t, err)
			return id
		}
		alice := seedCredential("alicesmith@gmail.com", "alice-key")
		// An account stored under "@corp.com" (by a release that did not check)
		// must not be reachable by a tag-only address.
		stray := seedCredential("@corp.com", "stray-key")

		opts, _, err := svc.BeginPasskeyLogin(ctx, "Alice.Smith+x@googlemail.com")
		require.NoError(t, err)
		require.Contains(t, opts, alice, "a dotted/tagged spelling finds the account's credentials")

		opts, _, err = svc.BeginPasskeyLogin(ctx, tagOnlyAddress)
		require.NoError(t, err)
		require.False(t, strings.Contains(opts, stray), "a tag-only address names no account: empty allow list")
	})

	t.Run("tenant invitation", func(t *testing.T) {
		f := newMembershipFixtureNoMail()
		f.seedAdmin(mTestProject, mTestTenant, mAdminID)
		_, err := f.svc.CreateTenantInvitation(withProject(mTestProject), mAdminID, mTestTenant, "+x@acme.com", RoleMember)
		require.ErrorIs(t, err, ErrInvalidArgument)
	})

	t.Run("passwordless", func(t *testing.T) {
		svc, _, rec := newAuthSvcWithMailer(t)
		svc.returnAllow = mustReturnAllowlist(t, "https://app.test/")
		// Anti-enumeration: the requests still answer nil, but nothing is sent.
		require.NoError(t, svc.RequestEmailLoginCode(ctx, tagOnlyAddress))
		require.NoError(t, svc.RequestMagicLink(ctx, tagOnlyAddress, "https://app.test/cb"))
		require.NoError(t, svc.RequestPasswordReset(ctx, tagOnlyAddress))
		require.Empty(t, rec.Sent(), "no code or link is mailed to @corp.com")
		_, err := svc.VerifyEmailLoginCode(ctx, tagOnlyAddress, "123456", "1.2.3.4", "ua")
		require.True(t, errors.Is(err, ErrEmailLoginCodeInvalid), "err = %v", err)
	})
}
