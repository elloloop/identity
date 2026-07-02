package config

import "testing"

func TestValidateNativeOAuth(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "disabled needs nothing",
			cfg:  Config{NativeOAuthEnabled: false},
		},
		{
			name: "enabled with google audiences",
			cfg:  Config{NativeOAuthEnabled: true, NativeOAuthGoogleAudiences: "web-client"},
		},
		{
			name: "enabled with apple audiences",
			cfg:  Config{NativeOAuthEnabled: true, NativeOAuthAppleAudiences: "dev.easyloops.app"},
		},
		{
			name: "enabled with microsoft audiences",
			cfg:  Config{NativeOAuthEnabled: true, NativeOAuthMicrosoftAudiences: "ms-client"},
		},
		{
			// With native audiences now per-project (config_json), an enabled
			// deployment with NO env audiences is valid — the default project just
			// has no native seed, non-default projects carry their own.
			name: "enabled with no env audiences is valid (per-project config)",
			cfg:  Config{NativeOAuthEnabled: true},
		},
		{
			name: "enabled with well-formed product map",
			cfg: Config{
				NativeOAuthEnabled:         true,
				NativeOAuthGoogleAudiences: "web-client",
				NativeOAuthProductProjects: "easyloops=proj_a, tortoise=proj_b",
			},
		},
		{
			name: "malformed product map entry (no =)",
			cfg: Config{
				NativeOAuthEnabled:         true,
				NativeOAuthGoogleAudiences: "web-client",
				NativeOAuthProductProjects: "easyloops",
			},
			wantErr: true,
		},
		{
			name: "malformed product map entry (empty value)",
			cfg: Config{
				NativeOAuthEnabled:         true,
				NativeOAuthGoogleAudiences: "web-client",
				NativeOAuthProductProjects: "easyloops=",
			},
			wantErr: true,
		},
		{
			name: "blank product map entries are skipped",
			cfg: Config{
				NativeOAuthEnabled:         true,
				NativeOAuthGoogleAudiences: "web-client",
				NativeOAuthProductProjects: " , easyloops=proj_a , ",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validateNativeOAuth()
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNativeOAuthDefaultEnabled(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"none", []string{"", "", ""}, false},
		{"google", []string{"web-client", "", ""}, true},
		{"apple", []string{"", "bundle-id", ""}, true},
		{"microsoft", []string{"", "", "ms-client"}, true},
		{"all whitespace", []string{"  ", "  ", "  "}, false},
	}
	for _, c := range cases {
		if got := nativeOAuthDefaultEnabled(c.args...); got != c.want {
			t.Fatalf("%s: nativeOAuthDefaultEnabled(%q)=%v want %v", c.name, c.args, got, c.want)
		}
	}
}

func TestNativeOAuthProductProjectMap(t *testing.T) {
	c := Config{NativeOAuthProductProjects: "EasyLoops=proj_a, tortoise = proj_b , junk, k=, =v, "}
	m := c.NativeOAuthProductProjectMap()
	if len(m) != 2 {
		t.Fatalf("want 2 valid entries, got %d: %v", len(m), m)
	}
	if m["easyloops"] != "proj_a" {
		t.Fatalf("product key not lower-cased/trimmed: %v", m)
	}
	if m["tortoise"] != "proj_b" {
		t.Fatalf("value not trimmed: %v", m)
	}
}

func TestNativeOAuthAudienceLists(t *testing.T) {
	c := Config{
		NativeOAuthGoogleAudiences:    " a , ,b ",
		NativeOAuthAppleAudiences:     "",
		NativeOAuthMicrosoftAudiences: " ms1 ,ms2",
	}
	g := c.NativeOAuthGoogleAudienceList()
	if len(g) != 2 || g[0] != "a" || g[1] != "b" {
		t.Fatalf("google audience list: %v", g)
	}
	if a := c.NativeOAuthAppleAudienceList(); a != nil {
		t.Fatalf("empty apple audiences should yield nil, got %v", a)
	}
	if m := c.NativeOAuthMicrosoftAudienceList(); len(m) != 2 || m[0] != "ms1" || m[1] != "ms2" {
		t.Fatalf("microsoft audience list: %v", m)
	}
}

func TestNativeOAuthAudienceList_ByProvider(t *testing.T) {
	c := Config{
		NativeOAuthGoogleAudiences:    "g",
		NativeOAuthAppleAudiences:     "a",
		NativeOAuthMicrosoftAudiences: "m",
	}
	for provider, want := range map[string]string{"google": "g", "apple": "a", "microsoft": "m"} {
		if got := c.NativeOAuthAudienceList(provider); len(got) != 1 || got[0] != want {
			t.Fatalf("provider %q: got %v want [%q]", provider, got, want)
		}
	}
	if got := c.NativeOAuthAudienceList("github"); got != nil {
		t.Fatalf("unknown provider should yield nil, got %v", got)
	}
}

// TestValidate_NativeOAuth_ThroughValidate exercises validateNativeOAuth via
// the top-level Validate so the wiring (not just the function) is covered.
func TestValidate_NativeOAuth_ThroughValidate(t *testing.T) {
	base := func() *Config {
		// A minimally-valid config so Validate reaches validateNativeOAuth
		// without tripping an earlier validator.
		return &Config{
			NativeOAuthEnabled:         true,
			NativeOAuthGoogleAudiences: "web-client",
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid native config should pass Validate: %v", err)
	}
	bad := base()
	bad.NativeOAuthProductProjects = "malformed-no-equals"
	if err := bad.Validate(); err == nil {
		t.Fatal("enabled native oauth with a malformed product map should fail Validate")
	}
}
