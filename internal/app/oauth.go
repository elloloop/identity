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
// configuration. A provider is registered only if its required credentials
// are non-empty; this lets operators leave a provider's credentials unset
// to disable it (rather than gating each provider behind its own boolean).
// Apple requires client ID, team ID, key ID, and private key. Others
// require client ID and client secret.
//
// The returned registry is never nil so the AuthService can call
// (*Registry).Len() unconditionally.
func buildOAuthRegistry(cfg *config.Config, logger *zap.Logger) *oauth.Registry {
	if logger == nil {
		logger = zap.NewNop()
	}
	r := oauth.NewRegistry()

	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" {
		r.Register("google", oauth.NewGoogle(oauth.GoogleConfig{
			ClientID:         cfg.GoogleClientID,
			ClientSecret:     cfg.GoogleClientSecret,
			Prompt:           cfg.OAuthPrompt,
			AuthorizationURL: cfg.GoogleAuthorizationURL,
			TokenURL:         cfg.GoogleTokenURL,
			JWKSURL:          cfg.GoogleJWKSURL,
			DiscoveryURL:     cfg.GoogleDiscoveryURL,
			UserinfoURL:      cfg.GoogleUserinfoURL,
			Issuer:           cfg.GoogleIssuer,
		}))
	}
	if cfg.MicrosoftClientID != "" && cfg.MicrosoftClientSecret != "" {
		r.Register("microsoft", oauth.NewMicrosoft(oauth.MicrosoftConfig{
			ClientID:       cfg.MicrosoftClientID,
			ClientSecret:   cfg.MicrosoftClientSecret,
			Prompt:         cfg.OAuthPrompt,
			TenantID:       cfg.MicrosoftTenantID,
			AllowedTenants: cfg.MicrosoftAllowedTenantList(),
		}))
	}
	if cfg.GitHubClientID != "" && cfg.GitHubClientSecret != "" {
		r.Register("github", oauth.NewGitHub(oauth.GitHubConfig{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
		}))
	}
	if cfg.AppleClientID != "" && cfg.AppleTeamID != "" && cfg.AppleKeyID != "" && cfg.ApplePrivateKey != "" {
		r.Register("apple", oauth.NewApple(oauth.AppleConfig{
			ClientID:   cfg.AppleClientID,
			TeamID:     cfg.AppleTeamID,
			KeyID:      cfg.AppleKeyID,
			PrivateKey: cfg.ApplePrivateKey,
		}))
	}
	// Generic, config-driven OIDC provider: registers an arbitrary
	// standards-compliant IdP (Okta, Auth0, Keycloak, a self-hosted issuer)
	// under its configured key. cfg.Validate() guarantees the key and
	// credentials are present and the key does not shadow a built-in provider.
	if cfg.OIDCEnabled {
		// Register under the same lowercased/trimmed key the service uses
		// for lookups, so a config like PROVIDER_KEY="Okta" (or with stray
		// whitespace) still resolves at login. Robust even when a Config is
		// constructed directly rather than via config.Load.
		oidcKey := strings.ToLower(strings.TrimSpace(cfg.OIDCProviderKey))
		r.Register(oidcKey, oauth.NewOIDC(oauth.GenericOIDCConfig{
			ProviderKey:  oidcKey,
			IssuerURL:    cfg.OIDCIssuer,
			DiscoveryURL: cfg.OIDCDiscoveryURL,
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			Scopes:       cfg.OIDCScopeList(),
		}))
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
