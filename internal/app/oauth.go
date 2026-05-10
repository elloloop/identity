package app

import (
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/oauth"
)

// buildOAuthRegistry constructs an oauth.Registry from the gateway
// configuration. A provider is registered only if BOTH the client ID
// and client secret are non-empty for that provider; this lets
// operators leave a provider's credentials unset to disable it (rather
// than gating each provider behind its own boolean).
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
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
		}))
	}
	if cfg.MicrosoftClientID != "" && cfg.MicrosoftClientSecret != "" {
		r.Register("microsoft", oauth.NewMicrosoft(oauth.MicrosoftConfig{
			ClientID:     cfg.MicrosoftClientID,
			ClientSecret: cfg.MicrosoftClientSecret,
			TenantID:     cfg.MicrosoftTenantID,
		}))
	}
	if cfg.GitHubClientID != "" && cfg.GitHubClientSecret != "" {
		r.Register("github", oauth.NewGitHub(oauth.GitHubConfig{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
		}))
	}

	if r.Len() == 0 {
		logger.Warn(
			"oauth_disabled_no_providers_configured",
			zap.String("hint",
				"set GATEWAY_GOOGLE_CLIENT_ID/SECRET, GATEWAY_MICROSOFT_CLIENT_ID/SECRET, "+
					"or GATEWAY_GITHUB_CLIENT_ID/SECRET to enable OAuth login"),
		)
	} else {
		logger.Info(
			"oauth_providers_enabled",
			zap.Strings("providers", r.Providers()),
		)
	}
	return r
}
