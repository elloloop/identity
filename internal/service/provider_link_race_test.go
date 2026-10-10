package service

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// providerLinkRaceRepo answers the first provider-id lookup as though no link
// existed yet: the state a request sees when a concurrent one links the same
// identity between its lookup and its insert.
type providerLinkRaceRepo struct {
	*errorRepo
	looked bool
}

func (r *providerLinkRaceRepo) WithProject(string) Repository { return r }

func (r *providerLinkRaceRepo) FindUserByProviderID(ctx context.Context, provider, providerUserID string) (*User, error) {
	if !r.looked {
		r.looked = true
		return nil, nil
	}
	return r.errorRepo.FindUserByProviderID(ctx, provider, providerUserID)
}

// Concurrent links of one provider identity, onto one account and onto
// several, leave exactly one link; every other caller is told it exists.
func TestLinkIdentity_ConcurrentLinksLeaveOne(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	shared := seedUser(repo, "shared@example.com", "hash", StatusActive)
	const callers = 16
	owners := make([]string, callers)
	for i := range owners {
		owners[i] = shared.ID
		if i%2 == 1 {
			owners[i] = seedUser(repo, "other"+string(rune('a'+i))+"@example.com", "hash", StatusActive).ID
		}
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	var won int64
	errs := make(chan error, callers)
	for _, uid := range owners {
		wg.Add(1)
		go func(uid string) {
			defer wg.Done()
			<-start
			_, err := svc.LinkIdentity(ctx, uid, fakeOAuthCode("contested@example.com", "C", "", "google"),
				"google", "https://app/cb", "", "", "")
			if err == nil {
				atomic.AddInt64(&won, 1)
				return
			}
			errs <- err
		}(uid)
	}
	close(start)
	wg.Wait()
	close(errs)

	assert.EqualValues(t, 1, won)
	for err := range errs {
		assert.ErrorIs(t, err, ErrAlreadyExists)
	}
}

// A store failure that is not a conflict is not reported as one: the link
// does not exist, and a retry may succeed.
func TestLinkIdentity_StoreFailureIsNotAlreadyLinked(t *testing.T) {
	repo := newErrorRepo()
	svc := newTestAuthServiceErr(t, repo)
	ctx := context.Background()
	u := seedUser(repo.fakeRepo, "linker@example.com", "hash", StatusActive)
	repo.failCreateOAuthIdentity = true

	_, err := svc.LinkIdentity(ctx, u.ID, fakeOAuthCode("linker@example.com", "L", "", "google"),
		"google", "https://app/cb", "", "", "")
	require.ErrorIs(t, err, errInjected)
	assert.NotErrorIs(t, err, ErrAlreadyExists)
}

// The upgrade that loses the race to link a provider identity (its lookup
// found none, another account's insert landed first) is refused as already
// linked, as when the lookup sees the link, and stays anonymous.
func TestUpgradeAnonymousWithOAuth_LosingTheLinkRaceIsAlreadyLinked(t *testing.T) {
	base := newErrorRepo()
	repo := &providerLinkRaceRepo{errorRepo: base}
	svc := newTestAuthServiceErr(t, base)
	svc.defaultRepo = repo
	ctx := anonCtx(true, AccessModeOpen)

	other, err := base.CreateUser(ctx, &User{Email: "other@example.com"})
	require.NoError(t, err)
	require.NoError(t, base.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: other, Provider: testOAuthProvider, ProviderUserID: "sub-" + testOAuthEmail, CreatedAt: 1,
	}))
	res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	require.NoError(t, err)
	repo.looked = false

	_, err = svc.UpgradeAnonymousWithOAuth(ctx, res.User.ID, oauthCred())
	require.ErrorIs(t, err, ErrAlreadyExists)
	require.True(t, repo.looked)
	after, err := base.GetUser(ctx, res.User.ID)
	require.NoError(t, err)
	assert.True(t, after.IsAnonymous, "a refused upgrade leaves the account anonymous")
}
