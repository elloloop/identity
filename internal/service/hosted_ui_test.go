package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The default test service (empty DefaultProjectID: every request is the
// default project) offers password + signup + the env providers.
func TestHostedUIOptions_Defaults(t *testing.T) {
	svc := newTestAuthService(t, newFakeRepo())

	opts := svc.HostedUIOptions(withProject("proj-1"))

	assert.True(t, opts.PasswordLoginEnabled)
	assert.True(t, opts.PasswordSignupEnabled)
	assert.Equal(t, []string{"github", "google", "microsoft"}, opts.OAuthProviders)
}

// The deployment-level password-signup switch is reflected while login stays.
func TestHostedUIOptions_SignupDisabled(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.PasswordSignupEnabled = false

	opts := svc.HostedUIOptions(withProject("proj-1"))

	assert.True(t, opts.PasswordLoginEnabled)
	assert.False(t, opts.PasswordSignupEnabled)
}

// Project-wide AllowedMethods gate what the page may offer: an oauth-only
// project hides the password form; a password-only project lists no
// providers.
func TestHostedUIOptions_AllowedMethodsGate(t *testing.T) {
	svc := newTestAuthService(t, newFakeRepo())

	oauthOnly := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID:     "proj-1",
		LoginDefaults: ProjectLoginConfig{AllowedMethods: "oauth"},
	})
	opts := svc.HostedUIOptions(oauthOnly)
	assert.False(t, opts.PasswordLoginEnabled)
	assert.False(t, opts.PasswordSignupEnabled)
	assert.NotEmpty(t, opts.OAuthProviders)

	passwordOnly := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID:     "proj-1",
		LoginDefaults: ProjectLoginConfig{AllowedMethods: "password, email_otp"},
	})
	opts = svc.HostedUIOptions(passwordOnly)
	assert.True(t, opts.PasswordLoginEnabled)
	assert.Empty(t, opts.OAuthProviders)
}

// Provider listing follows the same isolation rules a login attempt hits: a
// genuinely non-default project with no config of its own lists nothing
// under strict isolation and the hub's providers under hub sharing.
func TestHostedUIOptions_ProviderIsolationAndHubSharing(t *testing.T) {
	strict := hubSharingService(t, newFakeRepo(), false)
	opts := strict.HostedUIOptions(withProject("proj-hub"))
	assert.Empty(t, opts.OAuthProviders,
		"strict isolation must not advertise the hub's providers")

	sharing := hubSharingService(t, newFakeRepo(), true)
	opts = sharing.HostedUIOptions(withProject("proj-hub"))
	assert.Equal(t, []string{"github", "google", "microsoft"}, opts.OAuthProviders,
		"hub sharing must advertise the borrowed hub providers")
}

// A project's own configured provider is listed for that project (and merged
// with the hub's under sharing, without duplicates).
func TestHostedUIOptions_ProjectOwnProviderListed(t *testing.T) {
	svc := hubSharingService(t, newFakeRepo(), true)

	scope := &ProjectScope{
		ProjectID: "proj-own",
		OAuth:     ProjectOAuthConfig{Google: &ProjectOAuthGoogle{ClientID: "own-google"}},
	}
	opts := svc.HostedUIOptions(WithProjectScope(context.Background(), scope))

	assert.Equal(t, []string{"github", "google", "microsoft"}, opts.OAuthProviders)

	strict := hubSharingService(t, newFakeRepo(), false)
	opts = strict.HostedUIOptions(WithProjectScope(context.Background(), scope))
	assert.Equal(t, []string{"google"}, opts.OAuthProviders,
		"strict isolation lists only the project's own providers")
}
