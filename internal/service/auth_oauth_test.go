package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/oauth"
)

func TestOAuthLogin_Disabled_NoRegistry(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthServiceNoOAuth(t, repo)

	_, err := svc.OAuthLogin(context.Background(),
		fakeOAuthCode("u@example.com", "U", "", "google"),
		"google", "https://app/cb", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOAuthDisabled))
}

func TestOAuthLogin_UnknownProvider(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.OAuthLogin(context.Background(),
		fakeOAuthCode("u@example.com", "U", "", "yahoo"),
		"yahoo", "https://app/cb", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestOAuthLogin_NewUserCreatedAndAudited(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	code := fakeOAuthCode("new-oauth@example.com", "Newcomer", "https://avatar/", "google")
	res, err := svc.OAuthLogin(context.Background(), code, "google", "https://app/cb", "10.0.0.1", "TestAgent")
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
	res, err := svc.OAuthLogin(context.Background(), code, "google", "https://app/cb", "", "")
	require.NoError(t, err)
	assert.Equal(t, seed.ID, res.User.ID)
	assert.Equal(t, "Alice Updated", res.User.Name)
}

func TestOAuthLogin_ExchangerErrorPropagatesAsUnauthenticated(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	// "err|..." form makes the fake exchanger return ErrCodeExchangeFailed.
	_, err := svc.OAuthLogin(context.Background(),
		"err|something-bad", "google", "https://app/cb", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestOAuthLogin_UnverifiedEmailRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.OAuthLogin(context.Background(),
		"unverified|u@example.com", "google", "https://app/cb", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestOAuthLogin_AuditEventsRecorded(t *testing.T) {
	// The service uses audit.NewLogger(nil, ...) in tests which writes
	// nothing to a DB but counts in the in-memory logger. Just verify
	// success here — audit emission is unit-tested separately and the
	// integration test asserts end-to-end via RecordingDB.
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	code := fakeOAuthCode("audit@example.com", "Au", "", "github")
	res, err := svc.OAuthLogin(context.Background(), code, "github", "https://app/cb", "1.2.3.4", "Mozilla/5.0")
	require.NoError(t, err)
	assert.Equal(t, "audit@example.com", res.User.Email)
}

func TestOAuthLogin_EmptyProviderInvalid(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	_, err := svc.OAuthLogin(context.Background(), "code", "", "https://app/cb", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
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
	if _, err := svc.OAuthLogin(context.Background(), code, "google", "https://app/cb", "", ""); err != nil {
		t.Fatalf("OAuthLogin: %v", err)
	}
	if exch.calls.Load() != 1 {
		t.Errorf("exchanger calls = %d, want 1", exch.calls.Load())
	}
}
