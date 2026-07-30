package config

import (
	"encoding/base64"
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
			// deployment: valid ONLY when a mobile arm is configured. With
			// no arm at all the enforce toggles would deny every auth
			// endpoint while no token could be minted, so boot must fail.
			name: "enabled without web provider but with an iOS arm",
			mutate: func(c *Config) {
				*c = *assuranceConfig("")
				c.AssuranceIOSTeamID = "TEAM123456"
				c.AssuranceIOSBundleID = "com.example.app"
			},
		},
		{
			name:    "enabled with no arm at all",
			mutate:  func(c *Config) { *c = *assuranceConfig("") },
			wantErr: true,
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

// TestValidate_RemovedCaptchaEnvVarsFailBoot pins the v4.0.0 upgrade
// safety net: the GATEWAY_CAPTCHA_* rename must not take effect silently.
// An operator who pulls v4 while still setting the old variables would
// otherwise boot with assurance disabled and lose the anti-automation
// gate on six auth endpoints with no signal.
func TestValidate_RemovedCaptchaEnvVarsFailBoot(t *testing.T) {
	for _, tc := range []struct {
		envVar string
		want   string
	}{
		{"GATEWAY_CAPTCHA_ENABLED", "GATEWAY_ASSURANCE_ENABLED"},
		{"GATEWAY_CAPTCHA_PROVIDER", "GATEWAY_ASSURANCE_WEB_PROVIDER"},
		{"GATEWAY_CAPTCHA_TURNSTILE_SECRET", "GATEWAY_ASSURANCE_TURNSTILE_SECRET"},
		{"GATEWAY_CAPTCHA_ENFORCE_PASSWORD_LOGIN", "GATEWAY_ASSURANCE_ENFORCE_PASSWORD_LOGIN"},
	} {
		t.Run(tc.envVar, func(t *testing.T) {
			t.Setenv(tc.envVar, "true")
			cfg := &Config{}
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate() = nil; want a boot failure naming the removed var")
			}
			if !strings.Contains(err.Error(), tc.envVar) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error must name both the removed var and its replacement: %v", err)
			}
		})
	}
}

// TestValidate_AssuranceEnabledWithNoArm pins that enabling assurance with
// nothing configured fails boot rather than silently denying every auth
// endpoint (the enforce toggles default true while no token can be minted).
func TestValidate_AssuranceEnabledWithNoArm(t *testing.T) {
	cfg := &Config{
		AssuranceEnabled:             true,
		AssuranceChallengeTTLSeconds: 300,
		AssuranceTokenTTLSeconds:     3600,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil; want failure when assurance is enabled with no arm")
	}
	for _, want := range []string{"GATEWAY_ASSURANCE_WEB_PROVIDER", "GATEWAY_ASSURANCE_IOS_TEAM_ID", "GATEWAY_ASSURANCE_ANDROID_PACKAGE_NAME"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %s as an option: %v", want, err)
		}
	}

	t.Run("ios-only arm is valid", func(t *testing.T) {
		c := &Config{
			AssuranceEnabled:             true,
			AssuranceChallengeTTLSeconds: 300,
			AssuranceTokenTTLSeconds:     3600,
			AssuranceIOSTeamID:           "TEAM123456",
			AssuranceIOSBundleID:         "com.example.app",
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() = %v; want nil for a mobile-only deployment", err)
		}
	})
	t.Run("android-only arm is valid", func(t *testing.T) {
		c := &Config{
			AssuranceEnabled:             true,
			AssuranceChallengeTTLSeconds: 300,
			AssuranceTokenTTLSeconds:     3600,
			AssuranceAndroidPackageName:  "com.example.app",
			AssuranceAndroidCertDigests:  "ZGlnZXN0",
			AssuranceAndroidSAKeyJSON:    "{}",
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() = %v; want nil for an android-only deployment", err)
		}
	})
}

// TestValidate_AssuranceTTLCaps pins the upper bounds: an unbounded
// assurance TTL would be an unrevocable permanent bearer credential.
func TestValidate_AssuranceTTLCaps(t *testing.T) {
	base := func() *Config {
		return &Config{
			AssuranceEnabled:             true,
			AssuranceWebProvider:         AssuranceWebProviderTurnstile,
			AssuranceTurnstileSecret:     "s",
			AssuranceTurnstileSiteKey:    "k",
			AssuranceChallengeTTLSeconds: 300,
			AssuranceTokenTTLSeconds:     3600,
		}
	}
	t.Run("token TTL over cap", func(t *testing.T) {
		c := base()
		c.AssuranceTokenTTLSeconds = MaxAssuranceTokenTTLSeconds + 1
		if err := c.Validate(); err == nil {
			t.Fatal("Validate() = nil; want failure above the token TTL cap")
		}
	})
	t.Run("challenge TTL over cap", func(t *testing.T) {
		c := base()
		c.AssuranceChallengeTTLSeconds = MaxAssuranceChallengeTTLSeconds + 1
		if err := c.Validate(); err == nil {
			t.Fatal("Validate() = nil; want failure above the challenge TTL cap")
		}
	})
	t.Run("at the caps is valid", func(t *testing.T) {
		c := base()
		c.AssuranceTokenTTLSeconds = MaxAssuranceTokenTTLSeconds
		c.AssuranceChallengeTTLSeconds = MaxAssuranceChallengeTTLSeconds
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() = %v; want nil at the caps", err)
		}
	})
}

// TestValidate_AssuranceProjectOnlyDeployments pins the relaxation: a
// deployment whose app identities all live in per-project config_json is
// legitimate, so the env-arm requirement applies only where no control
// plane can carry that config — or when the operator opts out explicitly.
func TestValidate_AssuranceProjectOnlyDeployments(t *testing.T) {
	base := func() *Config {
		return &Config{
			AssuranceEnabled:             true,
			AssuranceChallengeTTLSeconds: 300,
			AssuranceTokenTTLSeconds:     3600,
		}
	}
	t.Run("postgres control plane may carry identities per project", func(t *testing.T) {
		c := base()
		c.RepoDriver = "postgres"
		// Unrelated postgres invariant: the driver requires the secrets key
		// that encrypts per-project provider secrets at rest.
		c.ProjectSecretsKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() = %v; want nil (per-project config can supply the arm)", err)
		}
	})
	t.Run("explicit opt-out is honoured without a control plane", func(t *testing.T) {
		c := base()
		c.RepoDriver = "memory"
		c.AssuranceAllowProjectOnly = true
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() = %v; want nil with the explicit opt-out", err)
		}
	})
	t.Run("no control plane and no opt-out still fails", func(t *testing.T) {
		c := base()
		c.RepoDriver = "memory"
		err := c.Validate()
		if err == nil {
			t.Fatal("Validate() = nil; want failure — nothing could ever mint a token")
		}
		if !strings.Contains(err.Error(), "GATEWAY_ASSURANCE_ALLOW_PROJECT_ONLY") {
			t.Errorf("error should name the opt-out: %v", err)
		}
	})
}
