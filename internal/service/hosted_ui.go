package service

import (
	"context"
	"strings"
)

// HostedUIProvider is one OAuth provider the hosted auth UI may offer.
type HostedUIProvider struct {
	// Key is the provider key (/oauth/start/{key}).
	Key string `json:"key"`
	// StartOrigin is the absolute origin whose /oauth/start must begin this
	// provider's flow, or "" when the current page origin works. A provider
	// client is registered with exactly one callback URL: a project's own
	// provider for the project's auth-domain, a borrowed (hub-shared) one
	// for the hub's — starting the flow anywhere else makes the provider
	// reject the redirect_uri.
	StartOrigin string `json:"startOrigin"`
	// NeedsProjectKey marks a borrowed provider: its callback lands on the
	// hub host, which can only re-scope to this project via the project_key
	// prefixed into the OAuth state, so the page must have been opened with
	// a project_key for the button to work.
	NeedsProjectKey bool `json:"needsProjectKey"`
}

// HostedUIOptions are the sign-in / sign-up capabilities the hosted auth UI
// (/auth/) may offer for the request's resolved project. The page renders
// ONLY what is enabled server-side; every method remains enforced by its
// RPC/flow regardless (a stricter tenant LoginPolicy still applies at login
// time).
type HostedUIOptions struct {
	// PasswordLoginEnabled reports whether the password form may render:
	// local auth is enabled deployment-wide (GATEWAY_AUTH_ALLOW_LOCAL) and
	// the project-wide AllowedMethods either impose no restriction or
	// include "password".
	PasswordLoginEnabled bool
	// PasswordSignupEnabled reports whether email sign-up may render:
	// password login is allowed, the deployment enables password signup, and
	// the project lets people create their own email accounts
	// (accounts.email_signup "self").
	PasswordSignupEnabled bool
	// UsernameSignupEnabled reports whether username sign-up may render:
	// password login and signup are allowed and the project admits username
	// self-signup (UsernameSignup's own rule).
	UsernameSignupEnabled bool
	// UsernameLoginEnabled reports whether the identifier field takes a
	// username: the project has username accounts (accounts.username_signup
	// is not "off"). Managed children sign in on their own apps.
	UsernameLoginEnabled bool
	// OAuthProviders are the providers the page may offer buttons for,
	// resolved with the same precedence a login attempt uses (project
	// config, then the default registry for the default project or under
	// hub sharing). Empty when the project disallows the oauth method.
	OAuthProviders []HostedUIProvider
}

// HostedUIOptions resolves what the hosted auth UI may offer for the
// request's project. It reads the same sources the login paths enforce —
// project-wide AllowedMethods (login_policy_enforce), the deployment's
// local-auth and password-signup flags, and the OAuth resolver's provider
// precedence — so the page mirrors the project-wide policy.
func (s *AuthService) HostedUIOptions(ctx context.Context) HostedUIOptions {
	allowed := ""
	authDomain := ""
	scope := ProjectScopeFromContext(ctx)
	if scope != nil {
		allowed = scope.LoginDefaults.AllowedMethods
		authDomain = scope.PrimaryAuthDomain
	}
	methodAllowed := func(method string) bool {
		return strings.TrimSpace(allowed) == "" || allowedMethodsContains(allowed, method)
	}

	opts := HostedUIOptions{
		PasswordLoginEnabled: s.cfg.AuthAllowLocal && methodAllowed(LoginMethodPassword),
	}
	signupOn := opts.PasswordLoginEnabled && s.cfg.PasswordSignupEnabled
	accounts := accountsFor(scope)
	opts.PasswordSignupEnabled = signupOn && accounts.emailSignup() == SignupSelf
	opts.UsernameSignupEnabled = signupOn && usernameSelfSignupRefusal(scope) == nil
	opts.UsernameLoginEnabled = opts.PasswordLoginEnabled && accounts.usernameSignup() != SignupOff
	if methodAllowed(LoginMethodOAuth) {
		own, borrowed := s.oauthResolver.providersFor(ctx)
		for _, key := range own {
			opts.OAuthProviders = append(opts.OAuthProviders, HostedUIProvider{
				Key:         key,
				StartOrigin: authDomainOrigin(authDomain),
			})
		}
		for _, key := range borrowed {
			opts.OAuthProviders = append(opts.OAuthProviders, HostedUIProvider{
				Key:             key,
				StartOrigin:     authDomainOrigin(s.cfg.DefaultPrimaryAuthDomain()),
				NeedsProjectKey: true,
			})
		}
	}
	return opts
}

// authDomainOrigin turns a serving hostname into the https origin browser
// links use (the same scheme rule branded links follow), or "" when no
// hostname is configured — the page then links relative to its own origin.
func authDomainOrigin(hostname string) string {
	if hostname == "" {
		return ""
	}
	return "https://" + hostname
}
