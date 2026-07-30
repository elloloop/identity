package config

import (
	"strings"
	"testing"
)

// assuranceConfig returns a minimal valid Config with assurance enabled for
// the given web provider, ready for a test to perturb a single field.
// RevocationMode is left empty so Validate fills the default; everything else
// is the zero value, which Validate tolerates outside the assurance block.
func assuranceConfig(provider string) *Config {
	return &Config{
		AssuranceEnabled:                 true,
		AssuranceWebProvider:             provider,
		AssuranceTurnstileSecret:         "ts-secret",
		AssuranceTurnstileSiteKey:        "ts-sitekey",
		AssuranceRecaptchaSecret:         "rc-secret",
		AssuranceRecaptchaScoreThreshold: 0.5,
		AssuranceChallengeTTLSeconds:     300,
		AssuranceTokenTTLSeconds:         3600,
	}
}

func TestValidate_Assurance(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name:   "disabled needs no provider or secret",
			mutate: func(c *Config) { *c = Config{AssuranceEnabled: false} },
		},
		{
			name:   "turnstile happy path",
			mutate: func(c *Config) { *c = *assuranceConfig(AssuranceWebProviderTurnstile) },
		},
		{
			name:   "recaptcha happy path",
			mutate: func(c *Config) { *c = *assuranceConfig(AssuranceWebProviderRecaptchaV3) },
		},
		{
			// No web provider while enabled is a mobile-attestation-only
			// deployment — valid, web assurance simply unavailable.
			name:   "enabled without web provider",
			mutate: func(c *Config) { *c = *assuranceConfig("") },
		},
		{
			name: "enabled with zero challenge TTL",
			mutate: func(c *Config) {
				*c = *assuranceConfig(AssuranceWebProviderTurnstile)
				c.AssuranceChallengeTTLSeconds = 0
			},
			wantErr: true,
		},
		{
			name:    "enabled with zero token TTL",
			mutate:  func(c *Config) { *c = *assuranceConfig(AssuranceWebProviderTurnstile); c.AssuranceTokenTTLSeconds = 0 },
			wantErr: true,
		},
		{
			name:    "ios team without bundle",
			mutate:  func(c *Config) { *c = *assuranceConfig(""); c.AssuranceIOSTeamID = "TEAM123456" },
			wantErr: true,
		},
		{
			name: "ios pair with bad env",
			mutate: func(c *Config) {
				*c = *assuranceConfig("")
				c.AssuranceIOSTeamID = "TEAM123456"
				c.AssuranceIOSBundleID = "com.example.app"
				c.AssuranceIOSEnv = "staging"
			},
			wantErr: true,
		},
		{
			name: "android package without digests",
			mutate: func(c *Config) {
				*c = *assuranceConfig("")
				c.AssuranceAndroidPackageName = "com.example.app"
				c.AssuranceAndroidSAKeyJSON = "{}"
			},
			wantErr: true,
		},
		{
			name: "android package without SA key",
			mutate: func(c *Config) {
				*c = *assuranceConfig("")
				c.AssuranceAndroidPackageName = "com.example.app"
				c.AssuranceAndroidCertDigests = "ZGlnZXN0"
			},
			wantErr: true,
		},
		{
			name:    "enabled with unknown provider",
			mutate:  func(c *Config) { *c = *assuranceConfig("hcaptcha") },
			wantErr: true,
		},
		{
			name:    "turnstile without secret",
			mutate:  func(c *Config) { *c = *assuranceConfig(AssuranceWebProviderTurnstile); c.AssuranceTurnstileSecret = "" },
			wantErr: true,
		},
		{
			name: "turnstile without site key",
			mutate: func(c *Config) {
				*c = *assuranceConfig(AssuranceWebProviderTurnstile)
				c.AssuranceTurnstileSiteKey = ""
			},
			wantErr: true,
		},
		{
			name: "recaptcha without secret",
			mutate: func(c *Config) {
				*c = *assuranceConfig(AssuranceWebProviderRecaptchaV3)
				c.AssuranceRecaptchaSecret = ""
			},
			wantErr: true,
		},
		{
			name: "recaptcha threshold above one",
			mutate: func(c *Config) {
				*c = *assuranceConfig(AssuranceWebProviderRecaptchaV3)
				c.AssuranceRecaptchaScoreThreshold = 1.5
			},
			wantErr: true,
		},
		{
			name: "recaptcha threshold below zero",
			mutate: func(c *Config) {
				*c = *assuranceConfig(AssuranceWebProviderRecaptchaV3)
				c.AssuranceRecaptchaScoreThreshold = -0.01
			},
			wantErr: true,
		},
		{
			name: "recaptcha threshold at boundaries valid",
			mutate: func(c *Config) {
				*c = *assuranceConfig(AssuranceWebProviderRecaptchaV3)
				c.AssuranceRecaptchaScoreThreshold = 0
			},
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

// TestValidate_AssuranceDisabledIgnoresProviderFields documents that a
// disabled deployment is never rejected for an unset provider/secret —
// the whole block is ignored.
func TestValidate_AssuranceDisabledIgnoresProviderFields(t *testing.T) {
	cfg := &Config{AssuranceEnabled: false, AssuranceWebProvider: "garbage"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v; want nil when assurance disabled", err)
	}
}

func TestValidateAssurance_ErrorMentionsProvider(t *testing.T) {
	cfg := assuranceConfig(AssuranceWebProviderTurnstile)
	cfg.AssuranceTurnstileSecret = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	// Sanity: the rejection names the missing secret, not a different
	// invariant.
	if !strings.Contains(err.Error(), "GATEWAY_ASSURANCE_TURNSTILE_SECRET") {
		t.Fatalf("unexpected error: %v", err)
	}
}
