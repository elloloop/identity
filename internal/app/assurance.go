package app

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/assurance"
	"github.com/elloloop/identity/pkg/assurance/appattest"
	"github.com/elloloop/identity/pkg/assurance/playintegrity"
)

// buildWebAssuranceVerifier constructs the deployment-global web
// (captcha) verifier selected by config, or nil when no web provider is
// configured — a mobile-attestation-only deployment. Config.Validate has
// already guaranteed the provider/secret/threshold invariants, so an
// error here indicates a validation gap.
func buildWebAssuranceVerifier(cfg *config.Config, logger *zap.Logger) (assurance.Verifier, error) {
	if !cfg.AssuranceEnabled || cfg.AssuranceWebProvider == "" {
		logger.Info("assurance_web_disabled")
		return nil, nil
	}
	switch cfg.AssuranceWebProvider {
	case assurance.ProviderTurnstile:
		v, err := assurance.NewTurnstileVerifier(assurance.TurnstileConfig{
			Secret: cfg.AssuranceTurnstileSecret,
		})
		if err != nil {
			return nil, fmt.Errorf("turnstile: %w", err)
		}
		logger.Info("assurance_web_provider_loaded", zap.String("provider", assurance.ProviderTurnstile))
		return v, nil
	case assurance.ProviderRecaptchaV3:
		v, err := assurance.NewRecaptchaV3Verifier(assurance.RecaptchaConfig{
			Secret:         cfg.AssuranceRecaptchaSecret,
			ScoreThreshold: cfg.AssuranceRecaptchaScoreThreshold,
		})
		if err != nil {
			return nil, fmt.Errorf("recaptcha_v3: %w", err)
		}
		logger.Info(
			"assurance_web_provider_loaded",
			zap.String("provider", assurance.ProviderRecaptchaV3),
			zap.Float64("score_threshold", cfg.AssuranceRecaptchaScoreThreshold),
		)
		return v, nil
	default:
		return nil, fmt.Errorf("unknown web assurance provider %q", cfg.AssuranceWebProvider)
	}
}

// buildAssuranceResolver constructs the per-project attestation resolver
// whose defaults are the env-configured app identity for the DEFAULT
// project. Returns nil when assurance is disabled.
func buildAssuranceResolver(cfg *config.Config, secretsKey []byte, logger *zap.Logger) (*service.AssuranceResolver, error) {
	if !cfg.AssuranceEnabled {
		return nil, nil
	}
	var defaults service.AssuranceProviders
	if cfg.AssuranceIOSTeamID != "" {
		v, err := appattest.New(appattest.Config{
			TeamID:   cfg.AssuranceIOSTeamID,
			BundleID: cfg.AssuranceIOSBundleID,
			Env:      cfg.AssuranceIOSEnv,
		})
		if err != nil {
			return nil, fmt.Errorf("app attest: %w", err)
		}
		defaults.AppAttest = v
		logger.Info("assurance_ios_loaded", zap.String("bundle_id", cfg.AssuranceIOSBundleID))
	}
	if cfg.AssuranceAndroidPackageName != "" {
		v, err := playintegrity.New(playintegrity.Config{
			PackageName:        cfg.AssuranceAndroidPackageName,
			CertSHA256Digests:  cfg.AssuranceAndroidCertDigestList(),
			ServiceAccountJSON: []byte(cfg.AssuranceAndroidSAKeyJSON),
		})
		if err != nil {
			return nil, fmt.Errorf("play integrity: %w", err)
		}
		defaults.PlayIntegrity = v
		logger.Info("assurance_android_loaded", zap.String("package", cfg.AssuranceAndroidPackageName))
	}
	return service.NewAssuranceResolver(cfg.DefaultProjectID, defaults, secretsKey, logger), nil
}

// wireAssurance builds the web verifier (unless the caller injected one)
// and the per-project attestation resolver, and attaches both to the
// auth service. A disabled deployment wires nothing — every assurance
// RPC then reports ErrAssuranceDisabled.
func wireAssurance(deps Deps, authSvc *service.AuthService, logger *zap.Logger) error {
	webAssurance := deps.AssuranceWebVerifier
	if webAssurance == nil {
		var err error
		webAssurance, err = buildWebAssuranceVerifier(deps.Config, logger)
		if err != nil {
			return fmt.Errorf("web assurance verifier: %w", err)
		}
	}
	resolver, err := buildAssuranceResolver(deps.Config, deps.ProjectSecretsKey, logger)
	if err != nil {
		return fmt.Errorf("assurance resolver: %w", err)
	}
	// An operator who opted into a per-project-only deployment gets one loud
	// line at boot: any project without its own assurance block cannot mint a
	// token, so its gated endpoints deny. Mirrors the
	// default_project_access_closed warning.
	if resolver != nil && webAssurance == nil &&
		deps.Config.AssuranceIOSTeamID == "" && deps.Config.AssuranceAndroidPackageName == "" {
		logger.Warn("assurance_enabled_no_env_arm",
			zap.String("detail", "assurance is enabled with no deployment-level arm; only projects with their own config_json assurance block can obtain a token, and the web arm is unavailable to every project"))
	}
	if resolver != nil {
		authSvc.WithAssurance(resolver, webAssurance)
	}
	return nil
}
