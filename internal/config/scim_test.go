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
	c.SCIMBearerToken = "" // no token or project id needed when disabled
	c.SCIMProjectID = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled SCIM must validate: %v", err)
	}
}

func TestValidateSCIM_EnabledRequiresToken(t *testing.T) {
	c := baseSCIMConfig()
	c.SCIMEnabled = true
	c.SCIMBearerToken = ""
	c.SCIMProjectID = "proj-1"
	if err := c.Validate(); err == nil {
		t.Fatal("enabled SCIM with no bearer token must fail")
	}
	c.SCIMBearerToken = "a-secret"
	if err := c.Validate(); err != nil {
		t.Fatalf("enabled SCIM with a token and project id must validate: %v", err)
	}
}

func TestValidateSCIM_EnabledRequiresProjectID(t *testing.T) {
	c := baseSCIMConfig()
	c.SCIMEnabled = true
	c.SCIMBearerToken = "a-secret"
	c.SCIMProjectID = ""
	if err := c.Validate(); err == nil {
		t.Fatal("enabled SCIM with no project id must fail (the token must be scoped to one project)")
	}
	c.SCIMProjectID = "proj-1"
	if err := c.Validate(); err != nil {
		t.Fatalf("enabled SCIM with a token and project id must validate: %v", err)
	}
}

func TestLoadSCIMDefaults(t *testing.T) {
	t.Setenv("GATEWAY_SCIM_ENABLED", "")
	t.Setenv("GATEWAY_SCIM_BEARER_TOKEN", "")
	t.Setenv("GATEWAY_SCIM_PROJECT_ID", "")
	c := Load()
	if c.SCIMEnabled {
		t.Fatal("SCIM must default to disabled")
	}
	if c.SCIMBearerToken != "" {
		t.Fatalf("SCIM bearer token default = %q, want empty", c.SCIMBearerToken)
	}
	if c.SCIMProjectID != "" {
		t.Fatalf("SCIM project id default = %q, want empty", c.SCIMProjectID)
	}
}
