package config

import "testing"

func TestMicrosoftAllowedTenantList(t *testing.T) {
	c := Config{MicrosoftAllowedTenants: " 11111111-1111-1111-1111-111111111111 , ,contoso.onmicrosoft.com "}
	got := c.MicrosoftAllowedTenantList()
	if len(got) != 2 || got[0] != "11111111-1111-1111-1111-111111111111" || got[1] != "contoso.onmicrosoft.com" {
		t.Fatalf("allowed tenant list: %v", got)
	}
	var zero Config
	if empty := zero.MicrosoftAllowedTenantList(); empty != nil {
		t.Fatalf("empty config should yield nil, got %v", empty)
	}
}

func TestValidMicrosoftTenant(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"11111111-1111-1111-1111-111111111111", true},
		{"AAAABBBB-CCCC-DDDD-EEEE-FFFF00001111", true},
		{"contoso.onmicrosoft.com", true},
		{"example.co", true},
		{"", false},
		{"common", false},        // a meta segment is not a concrete tenant
		{"organizations", false}, // ditto
		{"not a tenant", false},  // embedded whitespace
		{" leading.space.com", false},
		{"nodot", false},
		{"-", false},
	}
	for _, c := range cases {
		if got := ValidMicrosoftTenant(c.in); got != c.want {
			t.Fatalf("ValidMicrosoftTenant(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestValidateMicrosoftAllowedTenants(t *testing.T) {
	if err := (&Config{MicrosoftAllowedTenants: "11111111-1111-1111-1111-111111111111,contoso.com"}).validateMicrosoftAllowedTenants(); err != nil {
		t.Fatalf("well-formed allow-list should pass: %v", err)
	}
	if err := (&Config{MicrosoftAllowedTenants: "common"}).validateMicrosoftAllowedTenants(); err == nil {
		t.Fatal("a meta tenant in the allow-list should be rejected")
	}
	if err := (&Config{}).validateMicrosoftAllowedTenants(); err != nil {
		t.Fatalf("empty allow-list should pass: %v", err)
	}
}

// TestValidate_MicrosoftAllowedTenants_ThroughValidate exercises the validator
// via the top-level Validate so the wiring is covered.
func TestValidate_MicrosoftAllowedTenants_ThroughValidate(t *testing.T) {
	base := &Config{MicrosoftAllowedTenants: "11111111-1111-1111-1111-111111111111"}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid allow-list should pass Validate: %v", err)
	}
	bad := &Config{MicrosoftAllowedTenants: "totally-bogus"}
	if err := bad.Validate(); err == nil {
		t.Fatal("a malformed allow-list should fail Validate")
	}
}
