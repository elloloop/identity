package app

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/captcha"
)

// buildCaptchaVerifier constructs the captcha.Verifier selected by config.
// When CAPTCHA is disabled (or no provider is set) it returns the no-op
// verifier, so the handler can call Verify unconditionally. Config.Validate
// has already guaranteed the provider/secret/threshold invariants by the
// time this runs, so the only error here is a provider constructor
// rejecting its inputs (which would indicate a validation gap).
func buildCaptchaVerifier(cfg *config.Config, logger *zap.Logger) (captcha.Verifier, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	if !cfg.CaptchaEnabled || cfg.CaptchaProvider == "" {
		logger.Info("captcha_disabled")
		return captcha.NewNoopVerifier(), nil
	}

	switch cfg.CaptchaProvider {
	case captcha.ProviderTurnstile:
		v, err := captcha.NewTurnstileVerifier(captcha.TurnstileConfig{
			Secret: cfg.CaptchaTurnstileSecret,
		})
		if err != nil {
			return nil, fmt.Errorf("turnstile: %w", err)
		}
		logger.Info("captcha_provider_loaded", zap.String("provider", captcha.ProviderTurnstile))
		return v, nil
	case captcha.ProviderRecaptchaV3:
		v, err := captcha.NewRecaptchaV3Verifier(captcha.RecaptchaConfig{
			Secret:         cfg.CaptchaRecaptchaSecret,
			ScoreThreshold: cfg.CaptchaRecaptchaScoreThreshold,
		})
		if err != nil {
			return nil, fmt.Errorf("recaptcha_v3: %w", err)
		}
		logger.Info(
			"captcha_provider_loaded",
			zap.String("provider", captcha.ProviderRecaptchaV3),
			zap.Float64("score_threshold", cfg.CaptchaRecaptchaScoreThreshold),
		)
		return v, nil
	default:
		return nil, fmt.Errorf("unknown captcha provider %q", cfg.CaptchaProvider)
	}
}
