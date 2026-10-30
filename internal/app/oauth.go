package app

import (
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/oauth"
)

// buildNativeOAuthVerifier constructs the verifier for NativeOAuthLogin
// (Google/Apple/Microsoft ID tokens from mobile SDKs), or returns nil when
// native login is disabled. A nil verifier leaves the RPC disabled
// (FailedPrecondition). The accepted audiences are resolved per-request from
// the project scope (env seed for the default project, config_json for others),
// so the verifier itself holds only the shared JWKS caches — no audiences are
// baked in at construction.
func buildNativeOAuthVerifier(cfg *config.Config, logger *zap.Logger) *oauth.NativeVerifier {
	if logger == nil {
		logger = zap.NewNop()
	}
	if !cfg.NativeOAuthEnabled {
		return nil
	}
	logger.Info(
		"native_oauth_enabled",
		zap.Int("default_project_google_audiences", len(cfg.NativeOAuthGoogleAudienceList())),
		zap.Int("default_project_apple_audiences", len(cfg.NativeOAuthAppleAudienceList())),
		zap.Int("default_project_microsoft_audiences", len(cfg.NativeOAuthMicrosoftAudienceList())),
	)
	return oauth.NewNativeVerifier(oauth.NativeVerifierConfig{})
}

// buildOAuthRegistry constructs an oauth.Registry from the gateway
// configuration: each provider newEnvOAuthProvider builds from it, signing in
// through its env client.
//
// The returned registry is never nil so the AuthService can call
// (*Registry).Len() unconditionally.
func buildOAuthRegistry(cfg *config.Config, logger *zap.Logger) *oauth.Registry {
	if logger == nil {
		logger = zap.NewNop()
	}
	r := oauth.NewRegistry()
	for _, p := range envOAuthProviders(cfg) {
		if e, ok := newEnvOAuthProvider(cfg, p, p.clientID, p.clientSecret); ok {
			r.Register(p.key, e)
		}
	}

	if r.Len() == 0 {
		logger.Warn(
			"oauth_disabled_no_providers_configured",
			zap.String("hint",
				"set GATEWAY_OAUTH_GOOGLE_CLIENT_ID/SECRET, GATEWAY_OAUTH_MICROSOFT_CLIENT_ID/SECRET, "+
					"GATEWAY_OAUTH_GITHUB_CLIENT_ID/SECRET, GATEWAY_OAUTH_APPLE_..., or "+
					"GATEWAY_OAUTH_OIDC_ENABLED + GATEWAY_OAUTH_OIDC_... to enable OAuth login"),
		)
	} else {
		logger.Info(
			"oauth_providers_enabled",
			zap.Strings("providers", r.Providers()),
		)
	}
	return r
}

// envOAuthProvider is one provider the env can configure: the key it
// registers under, its kind, and the env client it signs in through.
type envOAuthProvider struct{ key, kind, clientID, clientSecret string }

// envOAuthProviders lists the providers the env can configure. The generic
// OIDC provider is listed only when enabled, under its configured key, which
// cfg.Validate() then keeps from shadowing a built-in provider; its kind, not
// its key, says how it is built.
func envOAuthProviders(cfg *config.Config) []envOAuthProvider {
	providers := []envOAuthProvider{
		{"google", "google", cfg.GoogleClientID, cfg.GoogleClientSecret},
		{"microsoft", "microsoft", cfg.MicrosoftClientID, cfg.MicrosoftClientSecret},
		{"github", "github", cfg.GitHubClientID, cfg.GitHubClientSecret},
		{"apple", "apple", cfg.AppleClientID, ""},
	}
	if cfg.OIDCEnabled {
		providers = append(providers, envOAuthProvider{envOIDCKey(cfg), "oidc", cfg.OIDCClientID, cfg.OIDCClientSecret})
	}
	return providers
}

// envOAuthProviderBuilder rebuilds the env provider registered under a key
// with another client, for a host override (ADR-0019) whose base is an env
// provider.
func envOAuthProviderBuilder(cfg *config.Config) service.EnvOAuthProviderBuilder {
	return func(provider, clientID, clientSecret string) (oauth.Exchanger, bool) {
		for _, p := range envOAuthProviders(cfg) {
			if p.key == provider {
				return newEnvOAuthProvider(cfg, p, clientID, clientSecret)
			}
		}
		return nil, false
	}
}

// newEnvOAuthProvider builds env provider p signing in through clientID and
// clientSecret, or reports false when the env does not configure it. A
// provider is configured when its required env credentials are all set, so an
// operator disables one by leaving them unset: Apple requires the client id,
// team id, key id and private key, the others the client id and secret.
// buildOAuthRegistry passes the env client; a host override passes its own
// and keeps every other env setting. Apple has no client secret, so
// clientSecret is ignored for it.
func newEnvOAuthProvider(cfg *config.Config, p envOAuthProvider, clientID, clientSecret string) (oauth.Exchanger, bool) {
	switch p.kind {
	case "google":
		if p.clientID == "" || p.clientSecret == "" {
			return nil, false
		}
		return oauth.NewGoogle(oauth.GoogleConfig{
			ClientID:         clientID,
			ClientSecret:     clientSecret,
			Prompt:           cfg.OAuthPrompt,
			AuthorizationURL: cfg.GoogleAuthorizationURL,
			TokenURL:         cfg.GoogleTokenURL,
			JWKSURL:          cfg.GoogleJWKSURL,
			DiscoveryURL:     cfg.GoogleDiscoveryURL,
			UserinfoURL:      cfg.GoogleUserinfoURL,
			Issuer:           cfg.GoogleIssuer,
		}), true
	case "microsoft":
		if p.clientID == "" || p.clientSecret == "" {
			return nil, false
		}
		return oauth.NewMicrosoft(oauth.MicrosoftConfig{
			ClientID:       clientID,
			ClientSecret:   clientSecret,
			Prompt:         cfg.OAuthPrompt,
			TenantID:       cfg.MicrosoftTenantID,
			AllowedTenants: cfg.MicrosoftAllowedTenantList(),
		}), true
	case "github":
		if p.clientID == "" || p.clientSecret == "" {
			return nil, false
		}
		return oauth.NewGitHub(oauth.GitHubConfig{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}), true
	case "apple":
		if p.clientID == "" || cfg.AppleTeamID == "" || cfg.AppleKeyID == "" || cfg.ApplePrivateKey == "" {
			return nil, false
		}
		return oauth.NewApple(oauth.AppleConfig{
			ClientID:   clientID,
			TeamID:     cfg.AppleTeamID,
			KeyID:      cfg.AppleKeyID,
			PrivateKey: cfg.ApplePrivateKey,
		}), true
	case "oidc":
		// Generic, config-driven OIDC provider: an arbitrary
		// standards-compliant IdP (Okta, Auth0, Keycloak, a self-hosted
		// issuer) under its configured key. It is listed only when enabled,
		// and cfg.Validate() then guarantees the key and credentials.
		return oauth.NewOIDC(oauth.GenericOIDCConfig{
			ProviderKey:  p.key,
			IssuerURL:    cfg.OIDCIssuer,
			DiscoveryURL: cfg.OIDCDiscoveryURL,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       cfg.OIDCScopeList(),
		}), true
	}
	return nil, false
}

// envOIDCKey is the key the env OIDC provider registers under: the same
// lowercased, trimmed form the service uses for lookups, so a config like
// PROVIDER_KEY="Okta" (or with stray whitespace) still resolves at login, even
// when a Config is constructed directly rather than via config.Load.
func envOIDCKey(cfg *config.Config) string {
	return strings.ToLower(strings.TrimSpace(cfg.OIDCProviderKey))
}
