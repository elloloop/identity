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
			name:    "enabled but no audiences",
			cfg:     Config{NativeOAuthEnabled: true},
			wantErr: true,
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
		{
			name: "enabled with only per-product google audiences",
			cfg: Config{
				NativeOAuthEnabled:                  true,
				NativeOAuthGoogleAudiencesByProduct: "easyloops=web.easyloops.app ios.easyloops.app",
			},
		},
		{
			name: "enabled with only per-product apple audiences",
			cfg: Config{
				NativeOAuthEnabled:                 true,
				NativeOAuthAppleAudiencesByProduct: "tortoise=com.tortoise.app",
			},
		},
		{
			name: "malformed per-product google audiences (no =)",
			cfg: Config{
				NativeOAuthEnabled:                  true,
				NativeOAuthGoogleAudiences:          "web-client",
				NativeOAuthGoogleAudiencesByProduct: "easyloops",
			},
			wantErr: true,
		},
		{
			name: "malformed per-product apple audiences (empty audience list)",
			cfg: Config{
				NativeOAuthEnabled:                 true,
				NativeOAuthGoogleAudiences:         "web-client",
				NativeOAuthAppleAudiencesByProduct: "tortoise=  ",
			},
			wantErr: true,
		},
		{
			name: "blank per-product audience entries are skipped",
			cfg: Config{
				NativeOAuthEnabled:                  true,
				NativeOAuthGoogleAudiencesByProduct: " , easyloops=web.easyloops.app , ",
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
		{"none", []string{"", "", "", ""}, false},
		{"global google", []string{"web-client", "", "", ""}, true},
		{"global apple", []string{"", "bundle-id", "", ""}, true},
		{"per-product google", []string{"", "", "easyloops=web.easyloops.app", ""}, true},
		{"per-product apple", []string{"", "", "", "tortoise=com.tortoise.app"}, true},
		{"all whitespace", []string{"  ", "  ", "  ", "  "}, false},
	}
	for _, c := range cases {
		if got := nativeOAuthDefaultEnabled(c.args...); got != c.want {
			t.Fatalf("%s: nativeOAuthDefaultEnabled(%q)=%v want %v", c.name, c.args, got, c.want)
		}
	}
}

func TestNativeOAuthAudiencesByProductMap(t *testing.T) {
	c := Config{
		NativeOAuthGoogleAudiencesByProduct: "EasyLoops=web.easyloops.app ios.easyloops.app, tortoise = com.tortoise.app , junk, =v, k= , ",
	}
	m := c.NativeOAuthGoogleAudiencesByProductMap()
	if len(m) != 2 {
		t.Fatalf("want 2 valid entries, got %d: %v", len(m), m)
	}
	if got := m["easyloops"]; len(got) != 2 || got[0] != "web.easyloops.app" || got[1] != "ios.easyloops.app" {
		t.Fatalf("easyloops audiences not parsed/lower-cased key: %v", m)
	}
	if got := m["tortoise"]; len(got) != 1 || got[0] != "com.tortoise.app" {
		t.Fatalf("tortoise audiences not trimmed: %v", m)
	}
	// Empty config yields a non-nil empty map (mirrors NativeOAuthProductProjectMap).
	if empty := (&Config{}).NativeOAuthAppleAudiencesByProductMap(); empty == nil || len(empty) != 0 {
		t.Fatalf("empty per-product apple config should yield empty non-nil map, got %v", empty)
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
		NativeOAuthGoogleAudiences: " a , ,b ",
		NativeOAuthAppleAudiences:  "",
	}
	g := c.NativeOAuthGoogleAudienceList()
	if len(g) != 2 || g[0] != "a" || g[1] != "b" {
		t.Fatalf("google audience list: %v", g)
	}
	if a := c.NativeOAuthAppleAudienceList(); a != nil {
		t.Fatalf("empty apple audiences should yield nil, got %v", a)
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
	bad.NativeOAuthGoogleAudiences = ""
	if err := bad.Validate(); err == nil {
		t.Fatal("enabled native oauth with no audiences should fail Validate")
	}
}
