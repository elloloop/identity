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
				// No provider means no web secrets either — a secret without
				// a provider is now itself an error (see below).
				c.AssuranceTurnstileSecret = ""
				c.AssuranceTurnstileSiteKey = ""
				c.AssuranceRecaptchaSecret = ""
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
			// Half-configured arms must not be silently ignored: the
			// operator believes the arm is on and the server disagrees.
			name: "android secrets without a package name",
			mutate: func(c *Config) {
				*c = *assuranceConfig(AssuranceWebProviderTurnstile)
				c.AssuranceAndroidSAKeyJSON = "{}"
				c.AssuranceAndroidCertDigests = "ZGlnZXN0"
			},
			wantErr: true,
		},
		{
			name: "web secret without a provider",
			mutate: func(c *Config) {
				*c = *assuranceConfig("")
				c.AssuranceIOSTeamID = "TEAM123456"
				c.AssuranceIOSBundleID = "com.example.app"
				c.AssuranceTurnstileSecret = "orphaned"
			},
			wantErr: true,
		},
		{
			name: "retention beyond the overflow bound",
			mutate: func(c *Config) {
				*c = *assuranceConfig(AssuranceWebProviderTurnstile)
				c.AssuranceDeviceRetentionDays = MaxAssuranceDeviceRetentionDays + 1
			},
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
			// Through the BOOT path: Load reads the environment, Validate
			// reports what it found. A hand-built Config is deliberately
			// exempt — see the embedder test below.
			err := Load().Validate()
			if err == nil {
				t.Fatal("Load().Validate() = nil; want a boot failure naming the removed var")
			}
			if !strings.Contains(err.Error(), tc.envVar) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error must name both the removed var and its replacement: %v", err)
			}
		})
	}

	// Presence is what fails, not truthiness: a leftover
	// GATEWAY_CAPTCHA_ENABLED=false in a compose file or Helm values
	// template must still be caught, or the operator keeps a dead setting
	// they believe is doing something.
	t.Run("present but false still fails", func(t *testing.T) {
		t.Setenv("GATEWAY_CAPTCHA_ENABLED", "false")
		if err := Load().Validate(); err == nil {
			t.Fatal("a removed variable set to false was accepted")
		}
	})
}

// TestValidate_RemovedEnvVarsDoNotAffectAnEmbeddedConfig pins the boundary
// the check must not cross. internal/config is imported by hosts that build
// a Config in code and never consult the environment; judging such a config
// on an ambient variable it never passed would fail a boot for a reason its
// author cannot see or control. Validate is therefore a pure function of
// its receiver, and the environment is read once, in Load.
func TestValidate_RemovedEnvVarsDoNotAffectAnEmbeddedConfig(t *testing.T) {
	t.Setenv("GATEWAY_CAPTCHA_ENABLED", "true")

	cfg := &Config{} // built in code, never through Load
	if err := cfg.Validate(); err != nil && strings.Contains(err.Error(), "GATEWAY_CAPTCHA_ENABLED") {
		t.Fatalf("an ambient environment variable failed a hand-built config: %v", err)
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

// TestValidate_AssuranceProjectOnlyDeployments pins that a
// per-project-only deployment must ACKNOWLEDGE itself. Exempting the
// control-plane drivers automatically would be unsound: the default
// driver is postgres, so the invariant would never fire by default, and
// the web arm is deployment-global — no per-project config can restore a
// missing web provider.
func TestValidate_AssuranceProjectOnlyDeployments(t *testing.T) {
	base := func(driver string) *Config {
		c := &Config{
			AssuranceEnabled:             true,
			AssuranceChallengeTTLSeconds: 300,
			AssuranceTokenTTLSeconds:     3600,
			RepoDriver:                   driver,
		}
		if driver == "postgres" {
			// Unrelated postgres invariant: the driver requires the secrets
			// key that encrypts per-project provider secrets at rest.
			c.ProjectSecretsKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
		}
		return c
	}

	// The control plane does NOT buy an exemption — postgres is the default
	// driver, so that would disable the invariant for almost everyone.
	for _, driver := range []string{"postgres", "sqlite", "memory"} {
		t.Run(driver+" without an arm or the opt-out fails", func(t *testing.T) {
			err := base(driver).Validate()
			if err == nil {
				t.Fatal("Validate() = nil; want failure — nothing could ever mint a token")
			}
			if !strings.Contains(err.Error(), "GATEWAY_ASSURANCE_ALLOW_PROJECT_ONLY") {
				t.Errorf("error should name the opt-out: %v", err)
			}
		})
		t.Run(driver+" with the explicit opt-out boots", func(t *testing.T) {
			c := base(driver)
			c.AssuranceAllowProjectOnly = true
			if err := c.Validate(); err != nil {
				t.Fatalf("Validate() = %v; want nil with the explicit opt-out", err)
			}
		})
	}
}

// TestValidate_AssuranceRetentionBoundAppliesWhenDisabled pins that the
// retention bound is checked even with assurance off: the sweeper is wired
// from the value regardless, and past the bound the cutoff duration
// overflows int64 and inverts, turning the sweep into a deleter of live
// device rows left over from a previously-enabled period.
func TestValidate_AssuranceRetentionBoundAppliesWhenDisabled(t *testing.T) {
	cfg := &Config{
		AssuranceEnabled:             false,
		AssuranceDeviceRetentionDays: MaxAssuranceDeviceRetentionDays + 1,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() = nil; the overflow bound must apply even when assurance is disabled")
	}
}

// TestAssuranceTTLAccessors covers the duration accessors, including the
// web arm's fallback to the global TTL when its own knob is unset.
func TestAssuranceTTLAccessors(t *testing.T) {
	c := &Config{AssuranceTokenTTLSeconds: 3600, AssuranceWebTokenTTLSeconds: 300}
	if got := c.AssuranceTokenTTL(); got.Seconds() != 3600 {
		t.Errorf("AssuranceTokenTTL = %v", got)
	}
	if got := c.AssuranceWebTokenTTL(); got.Seconds() != 300 {
		t.Errorf("AssuranceWebTokenTTL = %v", got)
	}
	c.AssuranceWebTokenTTLSeconds = 0
	if got := c.AssuranceWebTokenTTL(); got.Seconds() != 3600 {
		t.Errorf("AssuranceWebTokenTTL with the knob unset = %v; want the global 3600s", got)
	}
}

// TestValidateAssuranceLifetimeBounds walks every lifetime branch: each TTL
// floored and capped, and the web TTL's 0-means-inherit sentinel.
func TestValidateAssuranceLifetimeBounds(t *testing.T) {
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
	for _, tc := range []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"challenge TTL zero", func(c *Config) { c.AssuranceChallengeTTLSeconds = 0 }, true},
		{"challenge TTL negative", func(c *Config) { c.AssuranceChallengeTTLSeconds = -1 }, true},
		{"token TTL zero", func(c *Config) { c.AssuranceTokenTTLSeconds = 0 }, true},
		{"token TTL negative", func(c *Config) { c.AssuranceTokenTTLSeconds = -1 }, true},
		{"web TTL negative", func(c *Config) { c.AssuranceWebTokenTTLSeconds = -1 }, true},
		{"web TTL over cap", func(c *Config) { c.AssuranceWebTokenTTLSeconds = MaxAssuranceTokenTTLSeconds + 1 }, true},
		{"web TTL zero inherits", func(c *Config) { c.AssuranceWebTokenTTLSeconds = 0 }, false},
		{"web TTL at cap", func(c *Config) { c.AssuranceWebTokenTTLSeconds = MaxAssuranceTokenTTLSeconds }, false},
		{
			"retention shorter than the token TTL",
			func(c *Config) { c.AssuranceDeviceRetentionDays = 1; c.AssuranceTokenTTLSeconds = 86400 },
			true,
		},
		{"retention disabled skips the relation", func(c *Config) { c.AssuranceDeviceRetentionDays = 0 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			err := c.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("Validate() = nil; want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v; want nil", err)
			}
		})
	}
}

// TestValidateAssuranceArmBranches walks the remaining arm branches: the
// iOS pair, the iOS environment, and Android completeness in both
// directions.
func TestValidateAssuranceArmBranches(t *testing.T) {
	base := func() *Config {
		return &Config{
			AssuranceEnabled:             true,
			AssuranceChallengeTTLSeconds: 300,
			AssuranceTokenTTLSeconds:     3600,
			AssuranceAllowProjectOnly:    true,
		}
	}
	for _, tc := range []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"ios bundle without team", func(c *Config) { c.AssuranceIOSBundleID = "com.example.app" }, true},
		{"ios env development", func(c *Config) {
			c.AssuranceIOSTeamID, c.AssuranceIOSBundleID, c.AssuranceIOSEnv = "T", "b", "development"
		}, false},
		{"android package without digests", func(c *Config) {
			c.AssuranceAndroidPackageName, c.AssuranceAndroidSAKeyJSON = "com.example.app", "{}"
		}, true},
		{"android package without key", func(c *Config) {
			c.AssuranceAndroidPackageName, c.AssuranceAndroidCertDigests = "com.example.app", "ZGln"
		}, true},
		{"android complete", func(c *Config) {
			c.AssuranceAndroidPackageName = "com.example.app"
			c.AssuranceAndroidCertDigests = "ZGln"
			c.AssuranceAndroidSAKeyJSON = "{}"
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			err := c.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("Validate() = nil; want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v; want nil", err)
			}
		})
	}
}

// TestIsDefaultProject pins the single source of the default/non-default
// rule that the OAuth and assurance resolvers both consult: an unset
// default id, or an unset request id, means "default", so env settings
// apply exactly as they did before per-project config existed.
func TestIsDefaultProject(t *testing.T) {
	for _, tc := range []struct {
		defaultID, id string
		want          bool
	}{
		{"", "anything", true},
		{"proj-default", "", true},
		{"proj-default", "proj-default", true},
		{"proj-default", "proj-other", false},
	} {
		if got := IsDefaultProject(tc.defaultID, tc.id); got != tc.want {
			t.Errorf("IsDefaultProject(%q, %q) = %v, want %v", tc.defaultID, tc.id, got, tc.want)
		}
		c := &Config{DefaultProjectID: tc.defaultID}
		if got := c.IsDefaultProject(tc.id); got != tc.want {
			t.Errorf("Config.IsDefaultProject(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}
