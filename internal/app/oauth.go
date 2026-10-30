package app

import (
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
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
	for _, p := range []struct{ key, clientID, clientSecret string }{
		{"google", cfg.GoogleClientID, cfg.GoogleClientSecret},
		{"microsoft", cfg.MicrosoftClientID, cfg.MicrosoftClientSecret},
		{"github", cfg.GitHubClientID, cfg.GitHubClientSecret},
		{"apple", cfg.AppleClientID, ""},
		{envOIDCKey(cfg), cfg.OIDCClientID, cfg.OIDCClientSecret},
	} {
		if e, ok := newEnvOAuthProvider(cfg, p.key, p.clientID, p.clientSecret); ok {
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

// newEnvOAuthProvider builds the env-configured provider under key provider,
// signing in through clientID and clientSecret, or reports false when the env
// does not configure it. A provider is configured when its required env
// credentials are all set, so an operator disables one by leaving them unset:
// Apple requires the client id, team id, key id and private key, the others
// the client id and secret. buildOAuthRegistry passes the env client; a host
// override (ADR-0019) passes its own and keeps every other env setting. Apple
// has no client secret, so clientSecret is ignored for it.
func newEnvOAuthProvider(cfg *config.Config, provider, clientID, clientSecret string) (oauth.Exchanger, bool) {
	switch provider {
	case "google":
		if cfg.GoogleClientID == "" || cfg.GoogleClientSecret == "" {
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
		if cfg.MicrosoftClientID == "" || cfg.MicrosoftClientSecret == "" {
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
		if cfg.GitHubClientID == "" || cfg.GitHubClientSecret == "" {
			return nil, false
		}
		return oauth.NewGitHub(oauth.GitHubConfig{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}), true
	case "apple":
		if cfg.AppleClientID == "" || cfg.AppleTeamID == "" || cfg.AppleKeyID == "" || cfg.ApplePrivateKey == "" {
			return nil, false
		}
		return oauth.NewApple(oauth.AppleConfig{
			ClientID:   clientID,
			TeamID:     cfg.AppleTeamID,
			KeyID:      cfg.AppleKeyID,
			PrivateKey: cfg.ApplePrivateKey,
		}), true
	}
	// Generic, config-driven OIDC provider: an arbitrary standards-compliant
	// IdP (Okta, Auth0, Keycloak, a self-hosted issuer) under its configured
	// key. cfg.Validate() guarantees the key and credentials are present and
	// the key does not shadow a built-in provider.
	if cfg.OIDCEnabled && provider == envOIDCKey(cfg) {
		return oauth.NewOIDC(oauth.GenericOIDCConfig{
			ProviderKey:  provider,
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
