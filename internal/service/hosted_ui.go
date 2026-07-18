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
	// PasswordSignupEnabled reports whether the sign-up toggle may render:
	// password login is allowed AND the deployment enables password signup.
	PasswordSignupEnabled bool
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
	if scope := ProjectScopeFromContext(ctx); scope != nil {
		allowed = scope.LoginDefaults.AllowedMethods
		authDomain = scope.PrimaryAuthDomain
	}
	methodAllowed := func(method string) bool {
		return strings.TrimSpace(allowed) == "" || allowedMethodsContains(allowed, method)
	}

	opts := HostedUIOptions{
		PasswordLoginEnabled: s.cfg.AuthAllowLocal && methodAllowed(LoginMethodPassword),
	}
	opts.PasswordSignupEnabled = opts.PasswordLoginEnabled && s.cfg.PasswordSignupEnabled
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
