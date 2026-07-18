package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// providerKeys projects the option entries down to their keys for
// order-sensitive assertions.
func providerKeys(providers []HostedUIProvider) []string {
	keys := make([]string, 0, len(providers))
	for _, p := range providers {
		keys = append(keys, p.Key)
	}
	return keys
}

// The default test service (empty DefaultProjectID: every request is the
// default project) offers password + signup + the env providers as its own.
func TestHostedUIOptions_Defaults(t *testing.T) {
	svc := newTestAuthService(t, newFakeRepo())

	opts := svc.HostedUIOptions(withProject("proj-1"))

	assert.True(t, opts.PasswordLoginEnabled)
	assert.True(t, opts.PasswordSignupEnabled)
	assert.Equal(t, []string{"github", "google", "microsoft"}, providerKeys(opts.OAuthProviders))
	for _, p := range opts.OAuthProviders {
		assert.False(t, p.NeedsProjectKey, "%s: the default project's providers are its own", p.Key)
		assert.Empty(t, p.StartOrigin, "%s: no auth-domain configured, links stay relative", p.Key)
	}
}

// The deployment-level password-signup switch is reflected while login stays.
func TestHostedUIOptions_SignupDisabled(t *testing.T) {
	svc := newTestAuthService(t, newFakeRepo())
	svc.cfg.PasswordSignupEnabled = false

	opts := svc.HostedUIOptions(withProject("proj-1"))

	assert.True(t, opts.PasswordLoginEnabled)
	assert.False(t, opts.PasswordSignupEnabled)
}

// GATEWAY_AUTH_ALLOW_LOCAL=false disables the password RPCs, so the page
// must not offer a form that can only fail.
func TestHostedUIOptions_LocalAuthDisabled(t *testing.T) {
	svc := newTestAuthService(t, newFakeRepo())
	svc.cfg.AuthAllowLocal = false

	opts := svc.HostedUIOptions(withProject("proj-1"))

	assert.False(t, opts.PasswordLoginEnabled)
	assert.False(t, opts.PasswordSignupEnabled)
	assert.NotEmpty(t, opts.OAuthProviders, "oauth is unaffected by the local-auth switch")
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
// under strict isolation; under hub sharing it lists the hub's providers as
// BORROWED — flagged to need a project_key and routed to the hub's origin.
func TestHostedUIOptions_ProviderIsolationAndHubSharing(t *testing.T) {
	strict := hubSharingService(t, newFakeRepo(), false)
	opts := strict.HostedUIOptions(withProject("proj-hub"))
	assert.Empty(t, opts.OAuthProviders,
		"strict isolation must not advertise the hub's providers")

	sharing := hubSharingService(t, newFakeRepo(), true)
	sharing.cfg.DefaultProjectAuthDomains = "auth.hub.test, alt.hub.test"
	opts = sharing.HostedUIOptions(withProject("proj-hub"))
	assert.Equal(t, []string{"github", "google", "microsoft"}, providerKeys(opts.OAuthProviders))
	for _, p := range opts.OAuthProviders {
		assert.True(t, p.NeedsProjectKey, "%s: borrowed providers need the key to re-scope the hub callback", p.Key)
		assert.Equal(t, "https://auth.hub.test", p.StartOrigin,
			"%s: a borrowed provider's flow must start on the hub origin", p.Key)
	}
}

// A project's own configured provider is its own (relative or own-domain
// start, no key needed) and wins over the hub's borrowed copy of the same
// provider; the remaining hub providers merge in as borrowed.
func TestHostedUIOptions_ProjectOwnProviderWinsOverBorrowed(t *testing.T) {
	svc := hubSharingService(t, newFakeRepo(), true)

	scope := &ProjectScope{
		ProjectID:         "proj-own",
		PrimaryAuthDomain: "auth.own.test",
		OAuth:             ProjectOAuthConfig{Google: &ProjectOAuthGoogle{ClientID: "own-google"}},
	}
	opts := svc.HostedUIOptions(WithProjectScope(context.Background(), scope))

	assert.Equal(t, []string{"google", "github", "microsoft"}, providerKeys(opts.OAuthProviders))
	byKey := map[string]HostedUIProvider{}
	for _, p := range opts.OAuthProviders {
		byKey[p.Key] = p
	}
	assert.False(t, byKey["google"].NeedsProjectKey, "own google must not be listed as borrowed")
	assert.Equal(t, "https://auth.own.test", byKey["google"].StartOrigin,
		"own provider starts on the project's own auth-domain")
	assert.True(t, byKey["github"].NeedsProjectKey)
	assert.True(t, byKey["microsoft"].NeedsProjectKey)

	strict := hubSharingService(t, newFakeRepo(), false)
	opts = strict.HostedUIOptions(WithProjectScope(context.Background(), scope))
	assert.Equal(t, []string{"google"}, providerKeys(opts.OAuthProviders),
		"strict isolation lists only the project's own providers")
}
