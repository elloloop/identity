package service

import (
	"context"
	"strings"
)

// HostedUIOptions are the sign-in / sign-up capabilities the hosted auth UI
// (/auth/) may offer for the request's resolved project. The page renders
// ONLY what is enabled server-side, so the UI never advertises a method the
// server would reject.
type HostedUIOptions struct {
	// PasswordLoginEnabled reports whether the password form may render:
	// the project-wide AllowedMethods either impose no restriction or
	// include "password".
	PasswordLoginEnabled bool
	// PasswordSignupEnabled reports whether the sign-up toggle may render:
	// password login is allowed AND the deployment enables password signup.
	PasswordSignupEnabled bool
	// OAuthProviders are the provider keys the page may offer buttons for,
	// resolved with the same precedence a login attempt uses (project
	// config, then the default registry for the default project or under
	// hub sharing). Empty when the project disallows the oauth method.
	OAuthProviders []string
}

// HostedUIOptions resolves what the hosted auth UI may offer for the
// request's project. It reads the same sources the login paths enforce —
// project-wide AllowedMethods (login_policy_enforce), the deployment's
// password-signup flag, and the OAuth resolver's provider precedence — so
// the page and the server cannot disagree.
func (s *AuthService) HostedUIOptions(ctx context.Context) HostedUIOptions {
	allowed := ""
	if scope := ProjectScopeFromContext(ctx); scope != nil {
		allowed = scope.LoginDefaults.AllowedMethods
	}
	methodAllowed := func(method string) bool {
		return strings.TrimSpace(allowed) == "" || allowedMethodsContains(allowed, method)
	}

	opts := HostedUIOptions{
		PasswordLoginEnabled: methodAllowed(LoginMethodPassword),
	}
	opts.PasswordSignupEnabled = opts.PasswordLoginEnabled && s.cfg.PasswordSignupEnabled
	if methodAllowed(LoginMethodOAuth) {
		opts.OAuthProviders = s.oauthResolver.providersFor(ctx)
	}
	return opts
}
