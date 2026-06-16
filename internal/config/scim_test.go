package config

import "testing"

func baseSCIMConfig() *Config {
	c := Load()
	c.RevocationMode = RevocationModeTTL
	return c
}

func TestValidateSCIM_DisabledIsAlwaysValid(t *testing.T) {
	c := baseSCIMConfig()
	c.SCIMEnabled = false
	c.SCIMBearerToken = "" // no token needed when disabled
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled SCIM must validate: %v", err)
	}
}

func TestValidateSCIM_EnabledRequiresToken(t *testing.T) {
	c := baseSCIMConfig()
	c.SCIMEnabled = true
	c.SCIMBearerToken = ""
	if err := c.Validate(); err == nil {
		t.Fatal("enabled SCIM with no bearer token must fail")
	}
	c.SCIMBearerToken = "a-secret"
	if err := c.Validate(); err != nil {
		t.Fatalf("enabled SCIM with a token must validate: %v", err)
	}
}

func TestLoadSCIMDefaults(t *testing.T) {
	t.Setenv("GATEWAY_SCIM_ENABLED", "")
	t.Setenv("GATEWAY_SCIM_BEARER_TOKEN", "")
	c := Load()
	if c.SCIMEnabled {
		t.Fatal("SCIM must default to disabled")
	}
	if c.SCIMBearerToken != "" {
		t.Fatalf("SCIM bearer token default = %q, want empty", c.SCIMBearerToken)
	}
}
