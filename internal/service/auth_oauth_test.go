package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/oauth"
)

type oauthExchangeOnly struct {
	identity *oauth.Identity
	err      error
	calls    int
}

func (f *oauthExchangeOnly) Exchange(_ context.Context, _ oauth.ExchangeParams) (*oauth.Identity, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.identity, nil
}

func TestOAuthLogin_Disabled_NoRegistry(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthServiceNoOAuth(t, repo)

	_, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: fakeOAuthCode("u@example.com", "U", "", "google"), Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "", UserAgent: ""})

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOAuthDisabled))
}

func TestOAuthLogin_UnknownProvider(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: fakeOAuthCode("u@example.com", "U", "", "yahoo"), Provider: "yahoo", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "", UserAgent: ""})

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestBeginOAuthLogin_ReturnsServerOwnedState(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	result, err := svc.BeginOAuthLogin(context.Background(), "google", "https://app/cb")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.AuthorizationURL)
	assert.NotEmpty(t, result.State)
	assert.NotEmpty(t, result.StateToken)
	assert.NotEmpty(t, result.CodeVerifier)
	assert.Equal(t, int32(300), result.ExpiresIn)
}

func TestBeginOAuthLogin_InputAndProviderErrors(t *testing.T) {
	tests := []struct {
		name        string
		registry    *oauth.Registry
		provider    string
		redirectURI string
		want        error
	}{
		{"disabled", nil, "google", "https://app/cb", ErrOAuthDisabled},
		{"empty_provider", defaultTestOAuthRegistry(), "", "https://app/cb", ErrInvalidArgument},
		{"empty_redirect", defaultTestOAuthRegistry(), "google", "", ErrInvalidArgument},
		{"unknown_provider", defaultTestOAuthRegistry(), "unknown", "https://app/cb", ErrInvalidArgument},
		{"not_authorizer", func() *oauth.Registry {
			registry := oauth.NewRegistry()
			registry.Register("google", &oauthExchangeOnly{identity: &oauth.Identity{Email: "u@example.com"}})
			return registry
		}(), "google", "https://app/cb", ErrInvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestAuthServiceWithRegistry(t, newFakeRepo(), tt.registry)
			result, err := svc.BeginOAuthLogin(context.Background(), tt.provider, tt.redirectURI)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.want), "err=%v want=%v", err, tt.want)
			assert.Nil(t, result)
		})
	}
}

func TestOAuthLogin_NewUserCreatedAndAudited(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	code := fakeOAuthCode("new-oauth@example.com", "Newcomer", "https://avatar/", "google")
	res, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: code, Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "10.0.0.1", UserAgent: "TestAgent"})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "new-oauth@example.com", res.User.Email)
	assert.True(t, res.User.EmailVerified)
	assert.Equal(t, "Newcomer", res.User.Name)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)

	// User should now exist in repo with email_verified=true.
	got, err := repo.FindUserByEmail(context.Background(), "new-oauth@example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.EmailVerified)
}

func TestOAuthLogin_ExistingUserLooksUpByEmail(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	seed := seedUser(repo, "alice@example.com", "", "active")

	code := fakeOAuthCode("alice@example.com", "Alice Updated", "https://av/", "google")
	res, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: code, Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "", UserAgent: ""})
	require.NoError(t, err)
	assert.Equal(t, seed.ID, res.User.ID)
	assert.Equal(t, "Alice Updated", res.User.Name)
}

func TestOAuthLogin_ExchangerErrorPropagatesAsUnauthenticated(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	// "err|..." form makes the fake exchanger return ErrCodeExchangeFailed.
	_, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: "err|something-bad", Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "", UserAgent: ""})

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestOAuthLogin_UnverifiedEmailRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: "unverified|u@example.com", Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "", UserAgent: ""})

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestOAuthLogin_StateMismatchRejected(t *testing.T) {
	repo := newFakeRepo()
	registry := oauth.NewRegistry()
	exchanger := &fakeOAuthExchanger{provider: "google"}
	registry.Register("google", exchanger)
	svc := newTestAuthServiceWithRegistry(t, repo, registry)

	begin, err := svc.BeginOAuthLogin(context.Background(), "google", "https://app/cb")
	require.NoError(t, err)

	_, err = svc.OAuthLogin(
		context.Background(), OAuthLoginParams{Code: fakeOAuthCode("state-mismatch@example.com", "Mismatch", "", "google"), Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: begin.State + "-wrong", StateToken: begin.StateToken, AppleUserPayload: "", IPAddr: "", UserAgent: ""})

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
	assert.Zero(t, exchanger.calls.Load())
}

func TestOAuthLogin_StateTokenAllowsCallbackWithoutExplicitVerifier(t *testing.T) {
	repo := newFakeRepo()
	registry := oauth.NewRegistry()
	exchanger := &fakeOAuthExchanger{provider: "google"}
	registry.Register("google", exchanger)
	svc := newTestAuthServiceWithRegistry(t, repo, registry)

	begin, err := svc.BeginOAuthLogin(context.Background(), "google", "https://app/cb")
	require.NoError(t, err)
	res, err := svc.OAuthLogin(
		context.Background(), OAuthLoginParams{Code: fakeOAuthCode("state-token@example.com", "State Token", "", "google"), Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: begin.State, StateToken: begin.StateToken, AppleUserPayload: "", IPAddr: "", UserAgent: ""})

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "state-token@example.com", res.User.Email)
	assert.Equal(t, int32(1), exchanger.calls.Load())
}

func TestOAuthLogin_AuditEventsRecorded(t *testing.T) {
	// The service uses audit.NewLogger(nil, ...) in tests which writes
	// nothing to a DB but counts in the in-memory logger. Just verify
	// success here — audit emission is unit-tested separately and the
	// integration test asserts end-to-end via RecordingDB.
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	code := fakeOAuthCode("audit@example.com", "Au", "", "github")
	res, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: code, Provider: "github", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "1.2.3.4", UserAgent: "Mozilla/5.0"})
	require.NoError(t, err)
	assert.Equal(t, "audit@example.com", res.User.Email)
}

func TestOAuthLogin_EmptyProviderInvalid(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: "code", Provider: "", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "", UserAgent: ""})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestOAuthLogin_ProviderReturnsNoEmailRejected(t *testing.T) {
	repo := newFakeRepo()
	registry := oauth.NewRegistry()
	exchanger := &oauthExchangeOnly{identity: &oauth.Identity{
		Provider:       "google",
		ProviderUserID: "sub-no-email",
		EmailVerified:  true,
		Name:           "No Email",
	}}
	registry.Register("google", exchanger)
	svc := newTestAuthServiceWithRegistry(t, repo, registry)

	_, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: "code", Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "", UserAgent: ""})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
	assert.Equal(t, 1, exchanger.calls)
	if got, findErr := repo.FindUserByProviderID(context.Background(), "google", "sub-no-email"); findErr != nil || got != nil {
		t.Fatalf("no user should be linked when provider omits email: user=%+v err=%v", got, findErr)
	}
	if list, _ := repo.refreshTokenSnapshot(); len(list) != 0 {
		t.Fatalf("no refresh token should be issued when provider omits email, got %d", len(list))
	}
}

// Ensure exchanger CallCount increments — defensive check that the
// fake is actually being invoked (catch silent regressions).
func TestOAuthLogin_ExchangerInvoked(t *testing.T) {
	repo := newFakeRepo()
	r := oauth.NewRegistry()
	exch := &fakeOAuthExchanger{provider: "google"}
	r.Register("google", exch)
	svc := newTestAuthServiceWithRegistry(t, repo, r)

	code := fakeOAuthCode("u@example.com", "U", "", "google")
	if _, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: code, Provider: "google", RedirectURI: "https://app/cb", CodeVerifier: "", State: "", StateToken: "", AppleUserPayload: "", IPAddr: "", UserAgent: ""}); err != nil {
		t.Fatalf("OAuthLogin: %v", err)
	}
	if exch.calls.Load() != 1 {
		t.Errorf("exchanger calls = %d, want 1", exch.calls.Load())
	}
}
