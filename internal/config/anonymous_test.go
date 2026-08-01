package config

import (
	"strings"
	"testing"
)

// anonymousConfig returns a minimal Config with anonymous sign-in enabled and
// a retention window comfortably clear of the refresh lifetime, ready for a
// test to perturb one field.
func anonymousConfig() *Config {
	return &Config{
		AnonymousEnabled:       true,
		AnonymousRetentionDays: DefaultAnonymousRetentionDays,
		RefreshExpirySeconds:   7 * 24 * 3600, // 7 days
	}
}

func TestValidateAnonymous(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string // substring; empty means the config must validate
	}{
		{
			name:   "defaults are coherent",
			mutate: func(*Config) {},
		},
		{
			name:   "disabled needs nothing",
			mutate: func(c *Config) { *c = Config{} },
		},
		{
			// The window is checked regardless of the enable flag: the
			// sweeper is wired from it either way, and past the cap the
			// nanosecond cutoff duration overflows int64 and INVERTS, which
			// turns the sweep into a deleter of live accounts.
			name: "retention beyond the cap fails even while disabled",
			mutate: func(c *Config) {
				*c = Config{AnonymousEnabled: false, AnonymousRetentionDays: MaxAnonymousRetentionDays + 1}
			},
			wantErr: "GATEWAY_ANONYMOUS_RETENTION_DAYS",
		},
		{
			name:    "retention beyond the cap fails while enabled",
			mutate:  func(c *Config) { c.AnonymousRetentionDays = MaxAnonymousRetentionDays + 1 },
			wantErr: "GATEWAY_ANONYMOUS_RETENTION_DAYS",
		},
		{
			name:   "retention exactly at the cap is allowed",
			mutate: func(c *Config) { c.AnonymousRetentionDays = MaxAnonymousRetentionDays },
		},
		{
			// A refresh token is an anonymous account's ONLY credential.
			// Reaping the user before that token expires destroys a session
			// the client still holds and cannot re-establish.
			name: "retention shorter than the refresh lifetime fails",
			mutate: func(c *Config) {
				c.AnonymousRetentionDays = 1
				c.RefreshExpirySeconds = 30 * 24 * 3600
			},
			wantErr: "must exceed GATEWAY_REFRESH_EXPIRY",
		},
		{
			name: "retention equal to the refresh lifetime fails",
			mutate: func(c *Config) {
				c.AnonymousRetentionDays = 7
				c.RefreshExpirySeconds = 7 * 24 * 3600
			},
			wantErr: "must exceed GATEWAY_REFRESH_EXPIRY",
		},
		{
			name: "retention disabled skips the refresh comparison",
			// 0 keeps anonymous users forever — nothing to outlive.
			mutate: func(c *Config) {
				c.AnonymousRetentionDays = 0
				c.RefreshExpirySeconds = 30 * 24 * 3600
			},
		},
		{
			// Otherwise the RPC demands a token no arm can issue, denying
			// 100% of anonymous sign-ins with no way to obtain one.
			name: "require-assurance without the assurance layer fails",
			mutate: func(c *Config) {
				c.AnonymousRequireAssurance = true
				c.AssuranceEnabled = false
			},
			wantErr: "GATEWAY_ANONYMOUS_REQUIRE_ASSURANCE",
		},
		{
			name: "require-assurance with the assurance layer on is fine",
			mutate: func(c *Config) {
				c.AnonymousRequireAssurance = true
				c.AssuranceEnabled = true
			},
		},
		{
			// NOT inert — this was the fail-open. requireAssurance
			// short-circuits to ALLOW when the layer is off, so a project
			// enabling anonymous in config_json would be served unenforced
			// while the environment claims the opposite.
			name: "require-assurance while anonymous is off still fails",
			mutate: func(c *Config) {
				*c = Config{AnonymousEnabled: false, AnonymousRequireAssurance: true}
			},
			wantErr: "GATEWAY_ANONYMOUS_REQUIRE_ASSURANCE",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := anonymousConfig()
			tc.mutate(c)
			err := c.validateAnonymous()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("validateAnonymous() = %v, want nil", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("validateAnonymous() = nil, want an error naming %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("validateAnonymous() = %v, want an error naming %q", err, tc.wantErr)
			}
		})
	}
}

// The feature must be off unless an operator says otherwise: an
// unconfigured deployment cannot start handing out accounts.
func TestLoad_AnonymousDefaultsOff(t *testing.T) {
	t.Setenv("GATEWAY_JWT_SECRET", strings.Repeat("x", 32))
	c := Load()
	if c.AnonymousEnabled {
		t.Error("GATEWAY_ANONYMOUS_ENABLED defaulted to true")
	}
	if c.AnonymousRequireAssurance {
		t.Error("GATEWAY_ANONYMOUS_REQUIRE_ASSURANCE defaulted to true")
	}
	if c.AnonymousRetentionDays != DefaultAnonymousRetentionDays {
		t.Errorf("AnonymousRetentionDays = %d, want %d", c.AnonymousRetentionDays, DefaultAnonymousRetentionDays)
	}
}

func TestLoad_AnonymousReadsEnv(t *testing.T) {
	t.Setenv("GATEWAY_JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("GATEWAY_ANONYMOUS_ENABLED", "true")
	t.Setenv("GATEWAY_ANONYMOUS_RETENTION_DAYS", "45")
	t.Setenv("GATEWAY_ANONYMOUS_REQUIRE_ASSURANCE", "true")

	c := Load()
	if !c.AnonymousEnabled || c.AnonymousRetentionDays != 45 || !c.AnonymousRequireAssurance {
		t.Fatalf("anonymous env not read: enabled=%v retention=%d requireAssurance=%v",
			c.AnonymousEnabled, c.AnonymousRetentionDays, c.AnonymousRequireAssurance)
	}
}

// The default retention window must outlive the default refresh lifetime,
// or a stock deployment that enables anonymous sign-in fails to boot.
func TestAnonymousDefaults_AreMutuallyConsistent(t *testing.T) {
	t.Setenv("GATEWAY_JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("GATEWAY_ANONYMOUS_ENABLED", "true")

	c := Load()
	if err := c.validateAnonymous(); err != nil {
		t.Fatalf("stock defaults with anonymous enabled fail to boot: %v", err)
	}
}
