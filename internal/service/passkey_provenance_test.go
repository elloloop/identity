package service

import (
	"context"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/jwt"
	"github.com/stretchr/testify/require"
)

func provenanceSignIn(t *testing.T, svc *AuthService, access string) SessionSignIn {
	t.Helper()
	claims, err := jwt.VerifyAccessToken(access, svc.signer, "", "", false)
	require.NoError(t, err)
	return SessionSignIn{AuthTimeSec: claims.AuthTime, AMR: claims.AMR, RecoveryEmailID: claims.RecoveryEmailID, SessionID: claims.SID}
}

func (f reauthenticationFixture) passkeyLogin(t *testing.T, eligible bool) *LoginResult {
	t.Helper()
	for _, key := range f.repo.passkeyCreds {
		key.ReauthenticationEligible = eligible
	}
	f.user.EmailVerified = true
	_, id, err := f.service.BeginPasskeyLogin(context.Background(), f.user.Email)
	require.NoError(t, err)
	challenge, err := f.repo.GetPasskeyChallenge(context.Background(), id)
	require.NoError(t, err)
	login, err := f.service.CompletePasskeyLogin(context.Background(), id, f.assertion(t, challenge.Challenge, true), "", "")
	require.NoError(t, err)
	return login
}

func TestLegacyPasskeyLoginAndRefreshCannotAttachCredentials(t *testing.T) {
	f := newReauthenticationFixture(t)
	login := f.passkeyLogin(t, false)
	f.service.cfg.AccountMergeEnabled = true
	other := seedUser(f.repo, "merge-source@example.test", hashPW(t, strongPW), StatusActive)
	other.EmailVerified = true
	require.NotEmpty(t, login.AccessToken, "ordinary legacy-key sign-in remains available")
	ctx := context.Background()
	for range 2 {
		signIn := provenanceSignIn(t, f.service, login.AccessToken)
		require.False(t, signIn.credentialEnrollment().Trusted)
		_, _, err := f.service.BeginPasskeyRegistration(ctx, f.user.ID, signIn, "replacement", false)
		require.ErrorIs(t, err, ErrRecoveryReauthenticationRequired)
		_, err = f.service.LinkIdentity(ctx, f.user.ID, signIn, "code", "google", "https://example.com/callback", "", "", "")
		require.ErrorIs(t, err, ErrRecoveryReauthenticationRequired)
		_, err = f.service.MergeAccounts(ctx, f.user.ID, signIn, other.Email, strongPW, "", "", false)
		require.ErrorIs(t, err, ErrRecoveryReauthenticationRequired)
		require.Empty(t, f.user.PasswordHash)
		require.Empty(t, other.MergedIntoUserID)
		require.Zero(t, other.FailedLoginCount)
		_, access, refresh, err := f.service.RefreshToken(ctx, login.RefreshToken, "", "", "")
		require.NoError(t, err)
		require.Equal(t, authTimeOf(t, f.service, login.AccessToken), authTimeOf(t, f.service, access))
		login.AccessToken, login.RefreshToken = access, refresh
	}
	_, _, err := f.service.BeginReauthentication(ctx, f.user.ID, SessionSignIn{}, "account.pin.set", f.user.ID)
	require.ErrorIs(t, err, ErrReauthenticationKeyEnrollmentRequired)
}

func TestEligiblePasskeyEnrollmentTrustEndsWhenSourceIsRemoved(t *testing.T) {
	f := newReauthenticationFixture(t)
	login := f.passkeyLogin(t, true)
	signIn := provenanceSignIn(t, f.service, login.AccessToken)
	require.True(t, signIn.credentialEnrollment().Trusted)
	require.Equal(t, f.credentialID, signIn.credentialEnrollment().PasskeyID)
	ctx := context.Background()
	_, _, err := f.service.BeginPasskeyRegistration(ctx, f.user.ID, signIn, "second", false)
	require.NoError(t, err)
	require.NoError(t, f.repo.DeletePasskeyCredential(ctx, f.user.ID, f.credentialID))
	_, _, err = f.service.BeginPasskeyRegistration(ctx, f.user.ID, signIn, "replacement", false)
	require.ErrorIs(t, err, ErrRecoveryReauthenticationRequired)
	_, _, err = f.service.CompletePasskeyRegistration(ctx, f.user.ID, signIn, "unused", "{}", "replacement", false, "", "")
	require.ErrorIs(t, err, ErrRecoveryReauthenticationRequired)
	_, access, _, err := f.service.RefreshToken(ctx, login.RefreshToken, "", "", "")
	require.NoError(t, err, "removing enrollment authority does not erase ordinary sign-in access")
	require.False(t, provenanceSignIn(t, f.service, access).credentialEnrollment().Trusted)
}

func TestMixedPasskeysExposeEligibilityAndFilterAssertions(t *testing.T) {
	f := newReauthenticationFixture(t)
	ctx := context.Background()
	_, err := f.repo.CreatePasskeyCredential(ctx, &PasskeyCredRecord{UserID: f.user.ID, CredentialID: "bGVnYWN5", DeviceName: "Legacy"})
	require.NoError(t, err)
	options, _, err := f.service.BeginReauthentication(ctx, f.user.ID, SessionSignIn{}, "account.pin.set", f.user.ID)
	require.NoError(t, err)
	require.Contains(t, options, f.credentialID)
	require.NotContains(t, options, "bGVnYWN5")
	profile := newTestProfileServiceWithRepo(f.repo, newFakeDB())
	keys, err := profile.ListMyPasskeys(ctx, f.user.ID)
	require.NoError(t, err)
	require.Len(t, keys, 2)
	for _, key := range keys {
		require.Equal(t, key.CredentialID == f.credentialID, key.ReauthenticationEligible)
	}
	proof := f.proof(t, "account.pin.set", f.user.ID, true)
	for _, key := range f.repo.passkeyCreds {
		key.ReauthenticationEligible = false
	}
	require.Error(t, f.service.VerifyReauthentication(ctx, f.user.ID, SessionSignIn{}, proof, "account.pin.set", f.user.ID))
}

func TestQrHandoffCannotCarryEnrollmentTrust(t *testing.T) {
	for _, eligible := range []bool{false, true} {
		f := newReauthenticationFixture(t)
		login := f.passkeyLogin(t, eligible)
		ctx := context.Background()
		init, err := f.service.InitiateQrLogin(ctx, "device", "agent", "")
		require.NoError(t, err)
		_, err = f.service.ApproveQrLogin(ctx, init.SessionID, true, f.user.ID, provenanceSignIn(t, f.service, login.AccessToken), "", "")
		require.NoError(t, err)
		result, err := f.service.PollQrLogin(ctx, init.SessionID, init.PollSecret, "", "")
		require.NoError(t, err)
		signIn := provenanceSignIn(t, f.service, result.AccessToken)
		require.Zero(t, signIn.AuthTimeSec)
		require.False(t, signIn.credentialEnrollment().Trusted)
		_, access, _, err := f.service.RefreshToken(ctx, result.RefreshToken, "", "", "")
		require.NoError(t, err)
		require.False(t, provenanceSignIn(t, f.service, access).credentialEnrollment().Trusted)
		_, _, err = f.service.BeginPasskeyRegistration(ctx, f.user.ID, provenanceSignIn(t, f.service, access), "replacement", false)
		require.ErrorIs(t, err, ErrRecoveryReauthenticationRequired)
	}
}

func TestEnrollmentProvenanceRejectsMissingConflictingOrRecoveryClaims(t *testing.T) {
	for _, amr := range [][]string{
		nil,
		{AMRCredentialEnrollment, AMRRecoveryEmail},
		{AMRCredentialEnrollment, AMRUnvouched},
		{AMRCredentialEnrollment, enrollmentPasskeyPrefix},
		{AMRCredentialEnrollment, enrollmentPasskeyPrefix + "one", enrollmentPasskeyPrefix + "two"},
	} {
		require.False(t, (SessionSignIn{AMR: amr}).credentialEnrollment().Trusted)
	}
}

func TestDOBCompletionPreservesEnrollmentProvenanceWithoutRenewal(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		f := newReauthenticationFixture(t)
		f.user.DateOfBirthMs = nil
		f.user.EmailVerified = true
		enableAgeGate(t, f.service, true)
		ctx := context.Background()
		_, _, err := f.service.issueSignInTokens(ctx, f.user, "", "", f.service.nowMs(), f.service.nowMs(), "", credentialEnrollment{Trusted: trusted})
		ticket := dobTicketFrom(t, err)
		old := f.service.nowFunc
		f.service.nowFunc = func() time.Time { return old().Add(6 * time.Minute) }
		result, err := f.service.SubmitDateOfBirth(ctx, ticket, new(old().AddDate(-35, 0, 0).UnixMilli()), "", "")
		require.NoError(t, err)
		signIn := provenanceSignIn(t, f.service, result.AccessToken)
		require.Equal(t, trusted, signIn.credentialEnrollment().Trusted)
		require.Equal(t, old().Unix(), signIn.AuthTimeSec)
		_, _, err = f.service.BeginPasskeyRegistration(ctx, f.user.ID, signIn, "replacement", false)
		require.ErrorIs(t, err, ErrRecoveryReauthenticationRequired)
	}
}

func TestMergeCannotAttachCredentialsAfterEligibleSourceRemoval(t *testing.T) {
	f := newReauthenticationFixture(t)
	login := f.passkeyLogin(t, true)
	f.service.cfg.AccountMergeEnabled = true
	signIn := provenanceSignIn(t, f.service, login.AccessToken)
	ctx := context.Background()
	other := seedUser(f.repo, "merge-source@example.test", hashPW(t, strongPW), StatusActive)
	other.EmailVerified = true
	require.NoError(t, f.repo.DeletePasskeyCredential(ctx, f.user.ID, f.credentialID))
	_, err := f.service.MergeAccounts(ctx, f.user.ID, signIn, other.Email, strongPW, "", "", false)
	require.ErrorIs(t, err, ErrRecoveryReauthenticationRequired)
	require.Empty(t, f.user.PasswordHash)
	require.Empty(t, other.MergedIntoUserID)
}
