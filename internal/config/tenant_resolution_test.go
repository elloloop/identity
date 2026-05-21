package config

import (
	"strings"
	"testing"
)

func baseMultiConfig() *Config {
	return &Config{
		JWTExpirySeconds:        900,
		IdentityMode:            IdentityModeMulti,
		TenantResolutionSources: "host,jwt",
		TenantHostBaseDomain:    "glassa.work",
	}
}

func TestTenantResolutionSourceList_ParsesAndDedups(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"host,jwt", []string{"host", "jwt"}},
		{"jwt,host", []string{"jwt", "host"}},
		{" HOST , JWT ", []string{"host", "jwt"}},
		{"host,host,jwt", []string{"host", "jwt"}},
		{"host,bogus,jwt", []string{"host", "jwt"}},
		{"bogus", nil},
		{"", nil},
	}
	for _, c := range cases {
		cfg := &Config{TenantResolutionSources: c.in}
		got := cfg.TenantResolutionSourceList()
		if len(got) != len(c.want) {
			t.Fatalf("%q: got %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%q: got %v, want %v", c.in, got, c.want)
			}
		}
	}
}

func TestValidate_Multi_OK(t *testing.T) {
	if err := baseMultiConfig().Validate(); err != nil {
		t.Fatalf("Validate multi: %v", err)
	}
}

func TestValidate_Multi_EmptySources_FailsClosed(t *testing.T) {
	cfg := baseMultiConfig()
	cfg.TenantResolutionSources = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "TENANT_RESOLUTION_SOURCES") {
		t.Fatalf("expected TENANT_RESOLUTION_SOURCES error, got %v", err)
	}
}

func TestValidate_Multi_HostSourceWithoutBaseDomain_Fails(t *testing.T) {
	cfg := baseMultiConfig()
	cfg.TenantHostBaseDomain = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "TENANT_HOST_BASE_DOMAIN") {
		t.Fatalf("expected TENANT_HOST_BASE_DOMAIN error, got %v", err)
	}
}

func TestValidate_Multi_JWTOnly_NoBaseDomainRequired(t *testing.T) {
	cfg := baseMultiConfig()
	cfg.TenantResolutionSources = "jwt"
	cfg.TenantHostBaseDomain = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate jwt-only: %v", err)
	}
}

func TestValidate_Multi_SessionRevocation_Rejected(t *testing.T) {
	cfg := baseMultiConfig()
	cfg.RevocationMode = RevocationModeSession
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "session is not supported") {
		t.Fatalf("expected session-unsupported error, got %v", err)
	}
}

func TestValidate_Single_IgnoresResolutionConfig(t *testing.T) {
	cfg := &Config{
		JWTExpirySeconds:        900,
		IdentityMode:            IdentityModeSingle,
		TenantResolutionSources: "", // empty is fine in single mode
		TenantHostBaseDomain:    "",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate single: %v", err)
	}
}
