package config

import (
	"testing"
)

func baseSSOConfig() *Config {
	c := Load()
	c.RevocationMode = RevocationModeTTL
	return c
}

func TestValidateSSO_DisabledIsAlwaysValid(t *testing.T) {
	c := baseSSOConfig()
	c.SSOEnabled = false
	c.OAuthAllowedReturnURLs = ""
	c.SSOSessionTTLSeconds = 0 // unused when disabled
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled SSO must validate: %v", err)
	}
}

func TestValidateSSO_EnabledRequiresReturnAllowlist(t *testing.T) {
	c := baseSSOConfig()
	c.SSOEnabled = true
	c.SSOSessionTTLSeconds = DefaultSSOSessionTTLSeconds
	c.OAuthAllowedReturnURLs = ""
	if err := c.Validate(); err == nil {
		t.Fatal("enabled SSO with no return allowlist must fail (continue-as validates return_to against it)")
	}
	c.OAuthAllowedReturnURLs = "https://product-a.example.com/callback"
	if err := c.Validate(); err != nil {
		t.Fatalf("enabled SSO with an allowlist must validate: %v", err)
	}
}

func TestValidateSSO_EnabledRequiresPositiveTTL(t *testing.T) {
	c := baseSSOConfig()
	c.SSOEnabled = true
	c.OAuthAllowedReturnURLs = "https://product-a.example.com/callback"
	c.SSOSessionTTLSeconds = 0
	if err := c.Validate(); err == nil {
		t.Fatal("enabled SSO with a zero TTL must fail (sessions would never expire)")
	}
	c.SSOSessionTTLSeconds = -5
	if err := c.Validate(); err == nil {
		t.Fatal("enabled SSO with a negative TTL must fail")
	}
	c.SSOSessionTTLSeconds = DefaultSSOSessionTTLSeconds
	if err := c.Validate(); err != nil {
		t.Fatalf("enabled SSO with the default TTL must validate: %v", err)
	}
}

func TestValidateSSO_ContinueMode(t *testing.T) {
	c := baseSSOConfig()
	// Empty normalizes to the silent default, like Load() produces.
	c.SSOContinueMode = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("empty continue mode must normalize and validate: %v", err)
	}
	if c.SSOContinueMode != SSOContinueModeSilent {
		t.Fatalf("continue mode = %q, want %q", c.SSOContinueMode, SSOContinueModeSilent)
	}
	c.SSOContinueMode = "magic"
	if err := c.Validate(); err == nil {
		t.Fatal("an unrecognized continue mode must fail closed")
	}
	c.SSOContinueMode = SSOContinueModeOneTap
	if err := c.Validate(); err != nil {
		t.Fatalf("one_tap continue mode must validate: %v", err)
	}
}

func TestLoadSSODefaults(t *testing.T) {
	t.Setenv("GATEWAY_SSO_ENABLED", "")
	t.Setenv("GATEWAY_SSO_SESSION_TTL_SECONDS", "")
	t.Setenv("GATEWAY_SSO_CONTINUE_MODE", "")
	c := Load()
	if c.SSOEnabled {
		t.Fatal("SSO must default to disabled")
	}
	if c.SSOSessionTTLSeconds != DefaultSSOSessionTTLSeconds {
		t.Fatalf("SSO session TTL default = %d, want %d", c.SSOSessionTTLSeconds, DefaultSSOSessionTTLSeconds)
	}
	if c.SSOContinueMode != SSOContinueModeSilent {
		t.Fatalf("SSO continue mode default = %q, want %q", c.SSOContinueMode, SSOContinueModeSilent)
	}
}
