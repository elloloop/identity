package config

import (
	"strings"
	"testing"
)

// captchaConfig returns a minimal valid Config with CAPTCHA enabled for the
// given provider, ready for a test to perturb a single field. RevocationMode
// is left empty so Validate fills the default; everything else is the zero
// value, which Validate tolerates outside the CAPTCHA block.
func captchaConfig(provider string) *Config {
	return &Config{
		CaptchaEnabled:                 true,
		CaptchaProvider:                provider,
		CaptchaTurnstileSecret:         "ts-secret",
		CaptchaTurnstileSiteKey:        "ts-sitekey",
		CaptchaRecaptchaSecret:         "rc-secret",
		CaptchaRecaptchaScoreThreshold: 0.5,
	}
}

func TestValidate_Captcha(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name:   "disabled needs no provider or secret",
			mutate: func(c *Config) { *c = Config{CaptchaEnabled: false} },
		},
		{
			name:   "turnstile happy path",
			mutate: func(c *Config) { *c = *captchaConfig(CaptchaProviderTurnstile) },
		},
		{
			name:   "recaptcha happy path",
			mutate: func(c *Config) { *c = *captchaConfig(CaptchaProviderRecaptchaV3) },
		},
		{
			name:    "enabled without provider",
			mutate:  func(c *Config) { *c = *captchaConfig(""); c.CaptchaProvider = "" },
			wantErr: true,
		},
		{
			name:    "enabled with unknown provider",
			mutate:  func(c *Config) { *c = *captchaConfig("hcaptcha") },
			wantErr: true,
		},
		{
			name:    "turnstile without secret",
			mutate:  func(c *Config) { *c = *captchaConfig(CaptchaProviderTurnstile); c.CaptchaTurnstileSecret = "" },
			wantErr: true,
		},
		{
			name:    "turnstile without site key",
			mutate:  func(c *Config) { *c = *captchaConfig(CaptchaProviderTurnstile); c.CaptchaTurnstileSiteKey = "" },
			wantErr: true,
		},
		{
			name:    "recaptcha without secret",
			mutate:  func(c *Config) { *c = *captchaConfig(CaptchaProviderRecaptchaV3); c.CaptchaRecaptchaSecret = "" },
			wantErr: true,
		},
		{
			name: "recaptcha threshold above one",
			mutate: func(c *Config) {
				*c = *captchaConfig(CaptchaProviderRecaptchaV3)
				c.CaptchaRecaptchaScoreThreshold = 1.5
			},
			wantErr: true,
		},
		{
			name: "recaptcha threshold below zero",
			mutate: func(c *Config) {
				*c = *captchaConfig(CaptchaProviderRecaptchaV3)
				c.CaptchaRecaptchaScoreThreshold = -0.01
			},
			wantErr: true,
		},
		{
			name:   "recaptcha threshold at boundaries valid",
			mutate: func(c *Config) { *c = *captchaConfig(CaptchaProviderRecaptchaV3); c.CaptchaRecaptchaScoreThreshold = 0 },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			tc.mutate(cfg)
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("Validate() = nil; want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v; want nil", err)
			}
		})
	}
}

// TestValidate_CaptchaDisabledIgnoresProviderFields documents that a
// disabled deployment is never rejected for an unset provider/secret —
// the no-op verifier is wired regardless.
func TestValidate_CaptchaDisabledIgnoresProviderFields(t *testing.T) {
	cfg := &Config{CaptchaEnabled: false, CaptchaProvider: "garbage"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v; want nil when CAPTCHA disabled", err)
	}
}

func TestValidateCaptcha_ErrorMentionsProvider(t *testing.T) {
	cfg := captchaConfig(CaptchaProviderTurnstile)
	cfg.CaptchaTurnstileSecret = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	// Sanity: the rejection names the missing secret, not a different
	// invariant.
	if !strings.Contains(err.Error(), "GATEWAY_CAPTCHA_TURNSTILE_SECRET") {
		t.Fatalf("unexpected error: %v", err)
	}
}
