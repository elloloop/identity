package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// proofSvc is a service that mails, signs in with providers and permits
// anonymous accounts, so a test can drive every way an address gets proven.
func proofSvc(t *testing.T) (*AuthService, *fakeRepo, *recordingTransport) {
	t.Helper()
	svc, repo, rec := passwordlessSvc(t)
	svc.oauthResolver = newOAuthResolver(svc.cfg.DefaultProjectID, defaultTestOAuthRegistry(), svc.cfg.OAuthHubSharing, zap.NewNop())
	return svc, repo, rec
}

// redeemVerificationLink mails a verification link for userID and redeems it.
func redeemVerificationLink(t *testing.T, svc *AuthService, rec *recordingTransport, userID string) (*User, error) {
	t.Helper()
	require.NoError(t, svc.SendEmailVerification(context.Background(), userID, EmailLinkParams{}))
	sent := rec.Sent()
	return svc.VerifyEmail(context.Background(), extractTokenFromLink(t, sent[len(sent)-1].Text))
}

// resetPassword sets a new password through the emailed reset flow.
func resetPassword(t *testing.T, svc *AuthService, rec *recordingTransport, addr, password string) {
	t.Helper()
	require.NoError(t, svc.RequestPasswordReset(context.Background(), addr, EmailLinkParams{}))
	sent := rec.Sent()
	require.NoError(t, svc.ConfirmPasswordReset(context.Background(), extractTokenFromLink(t, sent[len(sent)-1].Text), password))
}

func linkEmails(t *testing.T, repo *fakeRepo, userID string) map[string]string {
	t.Helper()
	links, err := repo.ListOAuthIdentitiesForUser(context.Background(), userID)
	require.NoError(t, err)
	out := make(map[string]string, len(links))
	for _, l := range links {
		out[l.Provider+"/"+l.ProviderUserID] = l.EmailAtLinkTime
	}
	return out
}

// An anonymous account upgraded through a provider that asserted a +tag
// address outside Gmail holds the untagged address unproven. Whoever upgraded
// it may not own that mailbox, so when its owner redeems a verification link
// the provider link and everything else added before it are voided, and the
// sessions they opened end. A link whose provider asserted the account's own
// address is kept.
func TestVerificationLink_VoidsWhatAProviderClaimantAdded(t *testing.T) {
	svc, repo, rec := proofSvc(t)
	ctx := anonCtx(true, AccessModeOpen)

	anon, err := svc.SignInAnonymously(ctx, "", "")
	require.NoError(t, err)
	cred := oauthCred()
	cred.Code = fakeOAuthCode("someone+news@example.com", "Someone", "", "google")
	up, err := svc.UpgradeAnonymousWithOAuth(ctx, anon.User.ID, cred)
	require.NoError(t, err)
	claimed := up.User
	require.Equal(t, "someone@example.com", claimed.Email)
	require.False(t, claimed.EmailVerified)

	_, err = svc.LinkIdentity(ctx, claimed.ID, fakeOAuthCode("claimant@example.org", "C", "", "github"), "github", "https://app/cb", "", "", "")
	require.NoError(t, err)
	_, err = svc.LinkIdentity(ctx, claimed.ID, fakeOAuthCode("someone@example.com", "S", "", "microsoft"), "microsoft", "https://app/cb", "", "", "")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"google/sub-someone+news@example.com": "someone+news@example.com",
		"github/sub-claimant@example.org":     "claimant@example.org",
		"microsoft/sub-someone@example.com":   "someone@example.com",
	}, linkEmails(t, repo, claimed.ID), "a link records the address its provider asserted")
	_, err = repo.CreatePasskeyCredential(ctx, &PasskeyCredRecord{UserID: claimed.ID, CredentialID: "claimant-passkey"})
	require.NoError(t, err)
	const claimantSession = "claimant-session-hash"
	_, err = repo.CreateRefreshToken(ctx, &RefreshTokenRecord{TokenHash: claimantSession, UserID: claimed.ID, ExpiresAt: 1 << 62})
	require.NoError(t, err)

	verified, err := redeemVerificationLink(t, svc, rec, claimed.ID)
	require.NoError(t, err)
	assert.True(t, verified.EmailVerified)

	assert.Equal(t, []string{"microsoft/sub-someone@example.com"}, linkedProviders(t, repo, claimed.ID),
		"only the link whose provider asserted the account's own address survives")
	passkeys, err := repo.ListPasskeyCredentials(ctx, claimed.ID)
	require.NoError(t, err)
	assert.Empty(t, passkeys, "a passkey enrolled by the claimant is voided")
	tok, err := repo.FindRefreshTokenByHash(ctx, claimantSession)
	require.NoError(t, err)
	assert.Nil(t, tok, "the claimant's session ends")
}

// A new account created by a provider sign-in from a +tag address outside
// Gmail is held unverified the same way, and its owner proving the address
// with a verification link voids that provider's link. The owner is not
// locked out: a password reset to the proven address signs them in.
func TestVerificationLink_VoidsATaggedProviderSignUpWithoutLockingTheOwnerOut(t *testing.T) {
	svc, repo, rec := proofSvc(t)
	ctx := context.Background()

	res, err := oauthSignIn("someone+x@example.com")(t, svc, rec)
	require.NoError(t, err)
	require.False(t, res.User.EmailVerified)
	userID := res.User.ID

	_, err = redeemVerificationLink(t, svc, rec, userID)
	require.NoError(t, err)
	assert.Empty(t, linkedProviders(t, repo, userID), "the tagged sign-up's link is voided")
	found, err := repo.FindUserByProviderID(ctx, "google", "sub-someone+x@example.com")
	require.NoError(t, err)
	assert.Nil(t, found, "the voided link no longer signs in to the account")

	resetPassword(t, svc, rec, "someone@example.com", "Owner-Passw0rd!x")
	login, err := svc.PasswordLogin(ctx, "someone@example.com", "Owner-Passw0rd!x", "", "")
	require.NoError(t, err)
	assert.Equal(t, userID, login.User.ID)
}

// A verification link completes the sign-up that set an account's
// credentials, so on an account no provider claimed it keeps its password and
// every link, whatever address the provider asserted.
func TestVerificationLink_KeepsASignUpsCredentials(t *testing.T) {
	svc, repo, rec := proofSvc(t)
	ctx := context.Background()
	user := seedUser(repo, "owner@example.com", hashPW(t, "Owner-Passw0rd!x"), StatusActive)
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: user.ID, Provider: "github", ProviderUserID: "sub-other",
		EmailAtLinkTime: "owner@personal.example.org", CreatedAt: 1,
	}))

	verified, err := redeemVerificationLink(t, svc, rec, user.ID)
	require.NoError(t, err)
	assert.True(t, verified.EmailVerified)
	assert.Equal(t, []string{"github/sub-other"}, linkedProviders(t, repo, user.ID))
	_, err = svc.PasswordLogin(ctx, "owner@example.com", "Owner-Passw0rd!x", "", "")
	require.NoError(t, err, "the sign-up's password still signs in")
}

// When the voiding cannot read the account's links, the verification link
// fails with a retryable error and is not spent, so the same link proves the
// address once the store answers.
func TestVerificationLink_FailsClosedOnAClaimedAccount(t *testing.T) {
	svc, repo, rec := proofSvc(t)
	res, err := oauthSignIn("someone+x@example.com")(t, svc, rec)
	require.NoError(t, err)
	require.NoError(t, svc.SendEmailVerification(context.Background(), res.User.ID, EmailLinkParams{}))
	sent := rec.Sent()
	token := extractTokenFromLink(t, sent[len(sent)-1].Text)

	repo.listOAuthIdentitiesErr = assert.AnError
	_, err = svc.VerifyEmail(context.Background(), token)
	require.ErrorIs(t, err, ErrUnavailable)
	repo.listOAuthIdentitiesErr = nil
	stored, err := repo.GetUser(context.Background(), res.User.ID)
	require.NoError(t, err)
	assert.False(t, stored.EmailVerified)

	verified, err := svc.VerifyEmail(context.Background(), token)
	require.NoError(t, err)
	assert.True(t, verified.EmailVerified)
	assert.Empty(t, linkedProviders(t, repo, res.User.ID))
}

// A password an invitation set before the address was proven — by the
// invitee or by the inviting admin, who sees the token too — is cleared by a
// sign-in that proves the address, and the owner can set a new one.
func TestExternalProof_ClearsAnInvitationPasswordWithoutLockingTheOwnerOut(t *testing.T) {
	svc, repo, rec := proofSvc(t)
	ctx := context.Background()
	token := seedInvitedUser(t, repo, "invitee@example.com")
	accepted, err := svc.AcceptInvitation(ctx, token, accessTestPassword, "Invitee", "", "")
	require.NoError(t, err)
	require.False(t, accepted.User.EmailVerified)

	res, err := passwordlessSignIn("invitee@example.com")(t, svc, rec)
	require.NoError(t, err)
	assert.True(t, res.User.EmailVerified)
	_, err = svc.PasswordLogin(ctx, "invitee@example.com", accessTestPassword, "", "")
	require.Error(t, err, "the invitation's password no longer signs in")

	resetPassword(t, svc, rec, "invitee@example.com", "Owner-Passw0rd!x")
	login, err := svc.PasswordLogin(ctx, "invitee@example.com", "Owner-Passw0rd!x", "", "")
	require.NoError(t, err)
	assert.Equal(t, accepted.User.ID, login.User.ID)
}

// The provider link an anonymous upgrade carried over from a +tag address is
// voided by a sign-in that proves the untagged address, and the proving
// provider's own link survives.
func TestExternalProof_VoidsTheLinkAnAnonymousUpgradeCarried(t *testing.T) {
	svc, repo, rec := proofSvc(t)
	ctx := anonCtx(true, AccessModeOpen)
	anon, err := svc.SignInAnonymously(ctx, "", "")
	require.NoError(t, err)
	cred := oauthCred()
	cred.Code = fakeOAuthCode("someone+news@example.com", "Someone", "", "github")
	cred.Provider = "github"
	up, err := svc.UpgradeAnonymousWithOAuth(ctx, anon.User.ID, cred)
	require.NoError(t, err)

	res, err := oauthSignIn("someone@example.com")(t, svc, rec)
	require.NoError(t, err)
	require.Equal(t, up.User.ID, res.User.ID)
	assert.True(t, res.User.EmailVerified)
	assert.Equal(t, []string{"google/sub-someone@example.com"}, linkedProviders(t, repo, up.User.ID),
		"the proving link survives and the carried-over link is voided")
}

// A link a signed-in caller adds after the proof has listed the account's
// links is still voided: the proof lists them again once the address is
// marked verified.
func TestExternalProof_VoidsALinkAddedWhileItRuns(t *testing.T) {
	svc, repo, rec := proofSvc(t)
	ctx := context.Background()
	victim := seedUser(repo, "victim@example.com", "", StatusActive)
	repo.listOAuthIdentitiesHook = func() {
		repo.listOAuthIdentitiesHook = nil
		require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
			UserID: victim.ID, Provider: "github", ProviderUserID: "sub-late",
			EmailAtLinkTime: "planter@example.org", CreatedAt: 1,
		}))
	}
	const lateSession = "late-link-session-hash"
	_, err := repo.CreateRefreshToken(ctx, &RefreshTokenRecord{TokenHash: lateSession, UserID: victim.ID, ExpiresAt: 1 << 62})
	require.NoError(t, err)

	res, err := passwordlessSignIn("victim@example.com")(t, svc, rec)
	require.NoError(t, err)
	assert.True(t, res.User.EmailVerified)
	assert.Empty(t, linkedProviders(t, repo, victim.ID), "the link added mid-proof is voided")
	tok, err := repo.FindRefreshTokenByHash(ctx, lateSession)
	require.NoError(t, err)
	assert.Nil(t, tok, "the session that could have added it ends")
}

// A sign-in with a planted password that lands between the proof's first
// revocation and its verified write opens a session that revocation missed;
// the proof ends it once the password is gone.
func TestExternalProof_EndsASessionOpenedWhileItRuns(t *testing.T) {
	svc, repo, rec := proofSvc(t)
	ctx := context.Background()
	victim := seedUser(repo, "victim@example.com", hashPW(t, "Planted-Passw0rd!x"), StatusActive)
	const lateSession = "mid-proof-session-hash"
	listings := 0
	repo.listOAuthIdentitiesHook = func() {
		listings++
		if listings == 2 {
			_, err := repo.CreateRefreshToken(ctx, &RefreshTokenRecord{TokenHash: lateSession, UserID: victim.ID, ExpiresAt: 1 << 62})
			require.NoError(t, err)
		}
	}

	res, err := passwordlessSignIn("victim@example.com")(t, svc, rec)
	require.NoError(t, err)
	assert.True(t, res.User.EmailVerified)
	tok, err := repo.FindRefreshTokenByHash(ctx, lateSession)
	require.NoError(t, err)
	assert.Nil(t, tok, "a session opened while the proof ran ends with the voided password")
}

// A LinkIdentity call that began while the address was unproven withdraws its
// link when the address is proven before its insert lands, since the proof's
// listings may both have run before the insert.
func TestLinkIdentity_WithdrawsALinkWhenTheAddressIsProvenMeanwhile(t *testing.T) {
	svc, repo, _ := proofSvc(t)
	ctx := context.Background()
	user := seedUser(repo, "victim@example.com", "", StatusActive)
	repo.createOAuthIdentityHook = func() {
		repo.createOAuthIdentityHook = nil
		require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"email_verified": true, "email_verified_at": int64(1)}))
	}

	_, err := svc.LinkIdentity(ctx, user.ID, fakeOAuthCode("planter@example.org", "P", "", "github"), "github", "https://app/cb", "", "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
	assert.Empty(t, linkedProviders(t, repo, user.ID), "the link is withdrawn")
}

// An account deleted while LinkIdentity runs is not found: the call does not
// report an address proven, and the link does not outlive the account.
func TestLinkIdentity_AccountDeletedMeanwhileIsNotFound(t *testing.T) {
	svc, repo, _ := proofSvc(t)
	ctx := context.Background()
	user := seedUser(repo, "gone@example.com", "", StatusActive)
	repo.createOAuthIdentityHook = func() {
		repo.createOAuthIdentityHook = nil
		require.NoError(t, repo.DeleteUser(ctx, user.ID))
	}

	_, err := svc.LinkIdentity(ctx, user.ID, fakeOAuthCode("gone@example.org", "G", "", "github"), "github", "https://app/cb", "", "", "")
	require.ErrorIs(t, err, ErrNotFound)
	assert.NotErrorIs(t, err, ErrUnauthenticated)
	assert.Empty(t, linkedProviders(t, repo, user.ID), "the link is withdrawn")
}

// A LinkIdentity call on an unproven account that no proof races keeps its
// link.
func TestLinkIdentity_KeepsALinkOnAnUnprovenAccount(t *testing.T) {
	svc, repo, _ := proofSvc(t)
	user := seedUser(repo, "someone@example.com", hashPW(t, "Owner-Passw0rd!x"), StatusActive)

	_, err := svc.LinkIdentity(context.Background(), user.ID, fakeOAuthCode("someone@example.org", "S", "", "github"), "github", "https://app/cb", "", "", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"github/sub-someone@example.org"}, linkedProviders(t, repo, user.ID))
}
