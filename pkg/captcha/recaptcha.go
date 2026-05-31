package captcha

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// recaptchaVerifyURL is the Google reCAPTCHA v3 siteverify endpoint.
const recaptchaVerifyURL = "https://www.google.com/recaptcha/api/siteverify"

// RecaptchaConfig configures a RecaptchaV3Verifier. Secret is the
// reCAPTCHA secret key. ScoreThreshold is the inclusive lower bound a
// response score must meet to pass (reCAPTCHA v3 returns a 0.0–1.0 risk
// score; lower is more likely a bot).
type RecaptchaConfig struct {
	Secret         string
	ScoreThreshold float64
	HTTPClient     *http.Client // optional override for tests
	VerifyURL      string       // optional override for tests; defaults to recaptchaVerifyURL
}

// RecaptchaV3Verifier implements Verifier against Google reCAPTCHA v3.
//
// API reference:
//
//	POST https://www.google.com/recaptcha/api/siteverify
//	form: secret, response, [remoteip]
//	resp: { success, score, action, error-codes }
type RecaptchaV3Verifier struct {
	secret         string
	scoreThreshold float64
	client         *http.Client
	verifyURL      string
}

// NewRecaptchaV3Verifier returns a RecaptchaV3Verifier. Secret is
// required and ScoreThreshold must be in [0,1]; the HTTP client and verify
// URL fall back to sensible defaults.
func NewRecaptchaV3Verifier(cfg RecaptchaConfig) (*RecaptchaV3Verifier, error) {
	if cfg.Secret == "" {
		return nil, errors.New("captcha/recaptcha: secret required")
	}
	if cfg.ScoreThreshold < 0 || cfg.ScoreThreshold > 1 {
		return nil, fmt.Errorf("captcha/recaptcha: score threshold %v out of range [0,1]", cfg.ScoreThreshold)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultVerifyTimeout}
	}
	verifyURL := cfg.VerifyURL
	if verifyURL == "" {
		verifyURL = recaptchaVerifyURL
	}
	return &RecaptchaV3Verifier{
		secret:         cfg.Secret,
		scoreThreshold: cfg.ScoreThreshold,
		client:         client,
		verifyURL:      verifyURL,
	}, nil
}

// Name implements Verifier.
func (v *RecaptchaV3Verifier) Name() string { return ProviderRecaptchaV3 }

// Verify implements Verifier. It rejects when the provider reports
// success=false OR the returned score falls below the configured
// threshold.
func (v *RecaptchaV3Verifier) Verify(ctx context.Context, token, remoteip string) error {
	if token == "" {
		return ErrVerificationFailed
	}

	form := url.Values{}
	form.Set("secret", v.secret)
	form.Set("response", token)
	if remoteip != "" {
		form.Set("remoteip", remoteip)
	}

	var out struct {
		Success    bool     `json:"success"`
		Score      float64  `json:"score"`
		Action     string   `json:"action"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := postSiteVerify(ctx, v.client, v.verifyURL, form, &out); err != nil {
		return err
	}

	if !out.Success {
		return fmt.Errorf("%w: recaptcha error-codes %v", ErrVerificationFailed, out.ErrorCodes)
	}
	if out.Score < v.scoreThreshold {
		return fmt.Errorf("%w: recaptcha score %.2f below threshold %.2f", ErrVerificationFailed, out.Score, v.scoreThreshold)
	}
	return nil
}
