package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signInRaceRepo runs a concurrent sign-in to completion the first time the
// account is looked up by email, then answers that lookup as it stood before:
// the interleaving in which this request loses the race to create the account.
type signInRaceRepo struct {
	*fakeRepo
	concurrent func()
}

func (r *signInRaceRepo) WithProject(string) Repository { return r }

func (r *signInRaceRepo) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	if run := r.concurrent; run != nil {
		r.concurrent = nil
		run()
		return nil, nil
	}
	return r.fakeRepo.FindUserByEmail(ctx, email)
}

// Two sign-ins by one provider identity whose address reaches its account
// only by dropping a +tag outside Gmail race to create that account. The one
// that loses is answered as a sign-in that arrives after the winner: through
// the link the winner made, not refused as a stranger to the account.
func TestOAuthLogin_TaggedAddressLosingTheCreateRaceIsTheDuplicate(t *testing.T) {
	for _, requireVerified := range []bool{true, false} {
		name := "verification not required"
		if requireVerified {
			name = "verification required"
		}
		t.Run(name, func(t *testing.T) {
			repo := &signInRaceRepo{fakeRepo: newFakeRepo()}
			svc := newTestAuthService(t, repo.fakeRepo)
			svc.defaultRepo = repo
			svc.cfg.AuthRequireVerifiedEmail = requireVerified
			ctx := context.Background()
			signIn := func() (*LoginResult, error) {
				return svc.OAuthLogin(ctx, OAuthLoginParams{
					Code:     fakeOAuthCode("someone+news@example.com", "Someone", "", "google"),
					Provider: "google", RedirectURI: "https://app/cb",
				})
			}
			var winner *LoginResult
			var winnerErr error
			repo.concurrent = func() { winner, winnerErr = signIn() }

			loser, loserErr := signIn()
			duplicate, duplicateErr := signIn()

			require.Nil(t, repo.concurrent, "the race was run")
			if requireVerified {
				require.ErrorIs(t, winnerErr, ErrEmailVerificationRequired)
				require.ErrorIs(t, duplicateErr, ErrEmailVerificationRequired)
				require.ErrorIs(t, loserErr, ErrEmailVerificationRequired)
				return
			}
			require.NoError(t, winnerErr)
			require.NoError(t, duplicateErr)
			require.NoError(t, loserErr)
			assert.Equal(t, winner.User.ID, loser.User.ID)
			assert.Equal(t, duplicate.User.ID, loser.User.ID)
			assert.NotEmpty(t, loser.AccessToken)
		})
	}
}
