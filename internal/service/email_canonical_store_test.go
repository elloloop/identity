package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// legacyGmailAccount seeds an account stored, as releases before every write
// path canonicalized could store it, under a dotted Gmail spelling, linked to
// a provider identity the fake exchanger resolves for "stable-1@example.com".
func legacyGmailAccount(t *testing.T, repo *fakeRepo) *User {
	t.Helper()
	u := seedUser(repo, "first.last@gmail.com", "", StatusActive)
	u.EmailVerified = true
	require.NoError(t, repo.CreateOAuthIdentity(context.Background(), &OAuthIdentity{
		UserID: u.ID, Provider: "google", ProviderUserID: "sub-stable-1@example.com",
		EmailAtLinkTime: "first.last@gmail.com", CreatedAt: 1,
	}))
	return u
}

func providerSignIn(t *testing.T, svc *AuthService) *LoginResult {
	t.Helper()
	res, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{
		Code: fakeOAuthCode("stable-1@example.com", "First", "", "google"), Provider: "google", RedirectURI: "https://app/cb",
	})
	require.NoError(t, err)
	return res
}

// A provider sign-in finds the account by its provider id, never by email, so
// a stored non-canonical spelling would otherwise survive every sign-in.
func TestSignIn_StoresTheCanonicalEmail(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	legacy := legacyGmailAccount(t, repo)

	res := providerSignIn(t, svc)
	require.Equal(t, legacy.ID, res.User.ID)
	require.Equal(t, "firstlast@gmail.com", res.User.Email, "the session already carries the canonical form")

	stored, err := repo.GetUser(context.Background(), legacy.ID)
	require.NoError(t, err)
	require.Equal(t, "firstlast@gmail.com", stored.Email)
	require.True(t, stored.EmailVerified, "the same mailbox stays verified")
	require.Equal(t, 1, writer.countByEventTypeAndDetail("email_canonicalized", "source", "sign_in"))

	// Every spelling of the mailbox now finds the one account.
	found, err := repo.FindUserByEmail(context.Background(), "firstlast@gmail.com")
	require.NoError(t, err)
	require.Equal(t, legacy.ID, found.ID)

	providerSignIn(t, svc)
	require.Equal(t, 1, writer.countByEventType("email_canonicalized"), "a canonical address is left alone")
}

// Two live accounts for one mailbox are not resolved at sign-in: the rewrite
// would collide, and which account to keep is an operator's decision.
func TestSignIn_LeavesTheEmailWhenAnotherAccountHoldsTheCanonicalForm(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	legacy := legacyGmailAccount(t, repo)
	other := seedUser(repo, "firstlast@gmail.com", "", StatusActive)

	res := providerSignIn(t, svc)
	require.Equal(t, legacy.ID, res.User.ID, "the sign-in still succeeds")

	stored, _ := repo.GetUser(context.Background(), legacy.ID)
	require.Equal(t, "first.last@gmail.com", stored.Email)
	held, _ := repo.GetUser(context.Background(), other.ID)
	require.Equal(t, "firstlast@gmail.com", held.Email)
	require.Zero(t, writer.countByEventType("email_canonicalized"))
}

// An account already merged into this one never signs in again, so a
// canonical spelling it still holds is released to the survivor.
func TestSignIn_TakesTheCanonicalFormFromAnAccountMergedIntoIt(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	legacy := legacyGmailAccount(t, repo)
	retired := seedUser(repo, "firstlast@gmail.com", "", StatusDeactivated)
	retired.MergedIntoUserID = legacy.ID
	retired.EmailVerified = true

	providerSignIn(t, svc)

	stored, _ := repo.GetUser(context.Background(), legacy.ID)
	require.Equal(t, "firstlast@gmail.com", stored.Email)
	gone, _ := repo.GetUser(context.Background(), retired.ID)
	require.Empty(t, gone.Email)
	require.False(t, gone.EmailVerified)
	require.Equal(t, 1, writer.countByEventTypeAndDetail("email_canonicalized", "freed_from", retired.ID))
}

func TestStoreCanonicalEmail_NothingToDo(t *testing.T) {
	repo := newFakeRepo()
	for _, u := range []*User{nil, {}, {ID: "x"}, seedUser(repo, "firstlast@gmail.com", "", StatusActive)} {
		rw, err := storeCanonicalEmail(context.Background(), repo, u, 1)
		require.NoError(t, err)
		require.False(t, rw.Rewritten)
	}
}

// A token issued without a sign-in (a refresh of an older session) rewrites
// too, and says so.
func TestSessionToken_StoresTheCanonicalEmail(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	legacy := legacyGmailAccount(t, repo)

	_, _, err := svc.issueTokensWithSessionStart(context.Background(), legacy, "", "", sessionGateSignIn, 1, 0)
	require.NoError(t, err)
	require.Equal(t, "firstlast@gmail.com", storedUserEmail(t, repo, legacy.ID))
	require.Equal(t, 1, writer.countByEventTypeAndDetail("email_canonicalized", "source", "session"))
}

// Only an account merged into THIS one gives its spelling up.
func TestStoreCanonicalEmail_LeavesASpellingMergedIntoAnotherAccount(t *testing.T) {
	repo := newFakeRepo()
	legacy := seedUser(repo, "first.last@gmail.com", "", StatusActive)
	elsewhere := seedUser(repo, "firstlast@gmail.com", "", StatusDeactivated)
	elsewhere.MergedIntoUserID = "someone-else"

	_, err := storeCanonicalEmail(context.Background(), repo, legacy, 1)
	require.ErrorIs(t, err, errCanonicalEmailHeld)
	require.Equal(t, "first.last@gmail.com", storedUserEmail(t, repo, legacy.ID))
	require.Equal(t, "firstlast@gmail.com", storedUserEmail(t, repo, elsewhere.ID))
}

func TestStoreCanonicalEmail_StoreFailure(t *testing.T) {
	repo := newFakeRepo()
	legacy := seedUser(repo, "first.last@gmail.com", "", StatusActive)
	repo.findUserByEmailErr = errors.New("unavailable")
	_, err := storeCanonicalEmail(context.Background(), repo, legacy, 1)
	require.Error(t, err)
	require.Equal(t, "first.last@gmail.com", legacy.Email, "the caller's copy is unchanged on failure")
}

func storedUserEmail(t *testing.T, repo *fakeRepo, id string) string {
	t.Helper()
	u, err := repo.GetUser(context.Background(), id)
	require.NoError(t, err)
	return u.Email
}

// A canonical form the account's proof does not carry over to is never
// written: no mailbox left, or a +tag dropped outside Gmail.
func TestStoreCanonicalEmail_KeepsSpellingsItCannotProve(t *testing.T) {
	repo := newFakeRepo()
	for _, addr := range []string{"+x@corp.example", "ann+work@corp.example"} {
		u := seedUser(repo, addr, "", StatusActive)
		u.EmailVerified = true
		_, err := storeCanonicalEmail(context.Background(), repo, u, 1)
		require.ErrorIs(t, err, errCanonicalEmailNotRewritable, addr)
		require.Equal(t, addr, storedUserEmail(t, repo, u.ID))
	}
	gmail := seedUser(repo, "a.b+news@gmail.com", "", StatusActive)
	rw, err := storeCanonicalEmail(context.Background(), repo, gmail, 1)
	require.NoError(t, err)
	require.True(t, rw.Rewritten, "Gmail delivers every +tag to the one inbox")
	require.Equal(t, "ab@gmail.com", storedUserEmail(t, repo, gmail.ID))
}
