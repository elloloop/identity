package config

import "testing"

func TestMicrosoftAllowedTenantList(t *testing.T) {
	c := Config{MicrosoftAllowedTenants: " 11111111-1111-1111-1111-111111111111 , ,22222222-2222-2222-2222-222222222222 "}
	got := c.MicrosoftAllowedTenantList()
	if len(got) != 2 || got[0] != "11111111-1111-1111-1111-111111111111" || got[1] != "22222222-2222-2222-2222-222222222222" {
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
		{"AAAABBBB-CCCC-DDDD-EEEE-FFFF00001111", true}, // GUIDs are case-insensitive
		{"contoso.onmicrosoft.com", false},             // domain-form never matches a token's tid
		{"example.co", false},
		{"", false},
		{"common", false},        // a meta segment is not a concrete tenant
		{"organizations", false}, // ditto
		{"not a tenant", false},
		{" 11111111-1111-1111-1111-111111111111", false}, // leading whitespace
		{"nodot", false},
		{"-", false},
	}
	for _, c := range cases {
		if got := ValidMicrosoftTenant(c.in); got != c.want {
			t.Fatalf("ValidMicrosoftTenant(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestValidMicrosoftTenantPin(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", true},              // no pin
		{"common", true},        // meta = multi-tenant
		{"organizations", true}, // meta
		{"consumers", true},     // meta
		{"COMMON", true},        // meta, case-insensitive
		{"11111111-1111-1111-1111-111111111111", true},   // GUID
		{"AAAABBBB-CCCC-DDDD-EEEE-FFFF00001111", true},   // GUID, case-insensitive
		{"contoso.onmicrosoft.com", false},               // domain-form is NOT a valid pin
		{"example.co", false},                            // domain-form
		{" 11111111-1111-1111-1111-111111111111", false}, // whitespace
		{"nonsense", false},
	}
	for _, c := range cases {
		if got := ValidMicrosoftTenantPin(c.in); got != c.want {
			t.Fatalf("ValidMicrosoftTenantPin(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestValidateMicrosoftTenants(t *testing.T) {
	if err := (&Config{MicrosoftAllowedTenants: "11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222"}).validateMicrosoftTenants(); err != nil {
		t.Fatalf("well-formed allow-list should pass: %v", err)
	}
	if err := (&Config{MicrosoftAllowedTenants: "contoso.onmicrosoft.com"}).validateMicrosoftTenants(); err == nil {
		t.Fatal("a domain-form tenant in the allow-list should be rejected")
	}
	if err := (&Config{MicrosoftAllowedTenants: "common"}).validateMicrosoftTenants(); err == nil {
		t.Fatal("a meta tenant in the allow-list should be rejected")
	}
	// tenant_id pin: empty / meta / GUID pass; domain-form is rejected.
	if err := (&Config{MicrosoftTenantID: "common"}).validateMicrosoftTenants(); err != nil {
		t.Fatalf("meta tenant_id should pass: %v", err)
	}
	if err := (&Config{MicrosoftTenantID: "11111111-1111-1111-1111-111111111111"}).validateMicrosoftTenants(); err != nil {
		t.Fatalf("GUID tenant_id should pass: %v", err)
	}
	if err := (&Config{MicrosoftTenantID: "contoso.onmicrosoft.com"}).validateMicrosoftTenants(); err == nil {
		t.Fatal("a domain-form tenant_id must be rejected (would break every login)")
	}
	if err := (&Config{}).validateMicrosoftTenants(); err != nil {
		t.Fatalf("empty config should pass: %v", err)
	}
}

// TestValidate_MicrosoftTenants_ThroughValidate exercises the validator via the
// top-level Validate so the wiring is covered.
func TestValidate_MicrosoftTenants_ThroughValidate(t *testing.T) {
	base := &Config{MicrosoftAllowedTenants: "11111111-1111-1111-1111-111111111111"}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid allow-list should pass Validate: %v", err)
	}
	if err := (&Config{MicrosoftAllowedTenants: "totally-bogus"}).Validate(); err == nil {
		t.Fatal("a malformed allow-list should fail Validate")
	}
	if err := (&Config{MicrosoftTenantID: "contoso.onmicrosoft.com"}).Validate(); err == nil {
		t.Fatal("a domain-form tenant_id should fail Validate")
	}
}
