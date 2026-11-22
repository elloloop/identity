package service

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func eligibilityProof(t *testing.T, f reauthenticationFixture, signIn SessionSignIn, verified bool) *PasskeyReauthentication {
	t.Helper()
	options, id, err := f.service.BeginPasskeyEligibilityVerification(context.Background(), f.user.ID, signIn, f.credentialID)
	require.NoError(t, err)
	require.Contains(t, options, `"userVerification":"required"`)
	challenge, err := f.repo.GetPasskeyChallenge(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, passkeyEligibilityAction, challenge.Action)
	require.Equal(t, f.credentialID, challenge.ResourceID)
	return &PasskeyReauthentication{ChallengeID: id, CredentialJSON: f.assertion(t, challenge.Challenge, verified)}
}

func legacyEligibilityFixture(t *testing.T) (reauthenticationFixture, SessionSignIn) {
	t.Helper()
	f := newReauthenticationFixture(t)
	for _, key := range f.repo.passkeyCreds {
		key.ReauthenticationEligible = false
	}
	return f, SessionSignIn{AuthTimeSec: f.service.nowMs() / 1000, AMR: []string{AMRCredentialEnrollment}}
}

func TestPasskeyEligibilityVerificationExplicitAndSingleUse(t *testing.T) {
	f, signIn := legacyEligibilityFixture(t)
	proof := eligibilityProof(t, f, signIn, true)
	ctx := context.Background()
	key, err := f.repo.GetPasskeyCredentialByCredID(ctx, f.credentialID)
	require.NoError(t, err)
	require.False(t, key.ReauthenticationEligible, "begin/cancellation does not promote the key")
	info, err := f.service.CompletePasskeyEligibilityVerification(ctx, f.user.ID, signIn, f.credentialID, proof)
	require.NoError(t, err)
	require.True(t, info.ReauthenticationEligible)
	require.Equal(t, f.credentialID, info.CredentialID)
	keys, err := f.repo.ListPasskeyCredentials(ctx, f.user.ID)
	require.NoError(t, err)
	require.Len(t, keys, 1, "the original key is preserved without a replacement")
	require.Equal(t, key.PublicKey, keys[0].PublicKey)
	_, err = f.service.CompletePasskeyEligibilityVerification(ctx, f.user.ID, signIn, f.credentialID, proof)
	require.ErrorIs(t, err, ErrParentalConsentStepUpFailed)
	_, _, err = f.service.BeginReauthentication(ctx, f.user.ID, SessionSignIn{}, "account.pin.set", f.user.ID)
	require.NoError(t, err)
}

func TestPasskeyEligibilityRequiresIndependentFreshAuthenticationAtBothSteps(t *testing.T) {
	f, valid := legacyEligibilityFixture(t)
	proof := eligibilityProof(t, f, valid, true)
	ctx := context.Background()
	for _, signIn := range []SessionSignIn{
		{},
		{AuthTimeSec: valid.AuthTimeSec},
		{AuthTimeSec: valid.AuthTimeSec - 301, AMR: valid.AMR},
		{AuthTimeSec: valid.AuthTimeSec, AMR: []string{AMRCredentialEnrollment, AMRRecoveryEmail}},
		{AuthTimeSec: valid.AuthTimeSec, AMR: []string{AMRCredentialEnrollment, AMRUnvouched}},
		{AMR: valid.AMR},
	} {
		_, _, err := f.service.BeginPasskeyEligibilityVerification(ctx, f.user.ID, signIn, f.credentialID)
		require.Error(t, err)
		_, err = f.service.CompletePasskeyEligibilityVerification(ctx, f.user.ID, signIn, f.credentialID, proof)
		require.Error(t, err)
	}
	key, err := f.repo.GetPasskeyCredentialByCredID(ctx, f.credentialID)
	require.NoError(t, err)
	require.False(t, key.ReauthenticationEligible)
}

func TestPasskeyEligibilityCompletionRechecksFreshnessWithoutExpiringChallenge(t *testing.T) {
	f, signIn := legacyEligibilityFixture(t)
	signIn.AuthTimeSec -= 299
	proof := eligibilityProof(t, f, signIn, true)
	old := f.service.nowFunc
	f.service.nowFunc = func() time.Time { return old().Add(2 * time.Second) }
	_, err := f.service.CompletePasskeyEligibilityVerification(context.Background(), f.user.ID, signIn, f.credentialID, proof)
	require.ErrorIs(t, err, ErrRecoveryReauthenticationRequired)
}

func TestPasskeyEligibilityRejectsWrongPurposeMissingKeyAndUnverifiedAssertion(t *testing.T) {
	for _, refusal := range []string{"wrong purpose", "deleted", "other owner", "expired", "no user verification"} {
		t.Run(refusal, func(t *testing.T) {
			f, signIn := legacyEligibilityFixture(t)
			proof := eligibilityProof(t, f, signIn, refusal != "no user verification")
			ctx := context.Background()
			switch refusal {
			case "wrong purpose":
				f.repo.passkeyChallenges[proof.ChallengeID].Action = "account.pin.set"
			case "expired":
				f.repo.passkeyChallenges[proof.ChallengeID].ExpiresAt = f.service.nowMs()
			case "deleted":
				require.NoError(t, f.repo.DeletePasskeyCredential(ctx, f.user.ID, f.credentialID))
			case "other owner":
				for _, key := range f.repo.passkeyCreds {
					key.UserID = "other"
				}
			}
			_, err := f.service.CompletePasskeyEligibilityVerification(ctx, f.user.ID, signIn, f.credentialID, proof)
			require.Error(t, err)
			for _, key := range f.repo.passkeyCreds {
				require.False(t, key.ReauthenticationEligible)
			}
		})
	}
}

func TestPasskeyEligibilityPurposeCannotBeMintedByGenericReauthentication(t *testing.T) {
	f := newReauthenticationFixture(t)
	_, _, err := f.service.BeginReauthentication(context.Background(), f.user.ID, SessionSignIn{}, passkeyEligibilityAction, f.credentialID)
	require.ErrorIs(t, err, ErrInvalidArgument)
}

func TestPasskeyEligibilityConcurrentCompletionHasOneWinner(t *testing.T) {
	f, signIn := legacyEligibilityFixture(t)
	proof := eligibilityProof(t, f, signIn, true)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := f.service.CompletePasskeyEligibilityVerification(context.Background(), f.user.ID, signIn, f.credentialID, proof); err == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	require.Equal(t, int32(1), wins.Load())
}

type failedEligibilityPromotion struct{ Repository }

func (r failedEligibilityPromotion) WithProject(id string) Repository {
	return failedEligibilityPromotion{r.Repository.WithProject(id)}
}

func (failedEligibilityPromotion) MarkPasskeyReauthenticationEligible(context.Context, *PasskeyCredRecord) (bool, error) {
	return false, ErrServiceUnavailable
}

func TestPasskeyEligibilityStorageFailureCannotPromoteOrReplay(t *testing.T) {
	f, signIn := legacyEligibilityFixture(t)
	proof := eligibilityProof(t, f, signIn, true)
	f.service.defaultRepo = failedEligibilityPromotion{f.repo}
	_, err := f.service.CompletePasskeyEligibilityVerification(context.Background(), f.user.ID, signIn, f.credentialID, proof)
	require.ErrorIs(t, err, ErrServiceUnavailable)
	key, err := f.repo.GetPasskeyCredentialByCredID(context.Background(), f.credentialID)
	require.NoError(t, err)
	require.False(t, key.ReauthenticationEligible)
	f.service.defaultRepo = f.repo
	_, err = f.service.CompletePasskeyEligibilityVerification(context.Background(), f.user.ID, signIn, f.credentialID, proof)
	require.ErrorIs(t, err, ErrParentalConsentStepUpFailed)
}
