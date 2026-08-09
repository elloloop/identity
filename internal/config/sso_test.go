package config

import (
	"reflect"
	"testing"
)

func TestValidate_SSO(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "disabled needs no settings",
			cfg:  Config{SSOEnabled: false},
		},
		{
			// A disabled deployment is never rejected for nonsense it does
			// not act on, matching validateAgeGate.
			name: "disabled ignores an invalid mode",
			cfg:  Config{SSOEnabled: false, SSOContinueMode: "whatever", SSOSessionTTLSeconds: -1},
		},
		{
			name: "enabled happy path",
			cfg: Config{
				SSOEnabled:           true,
				SSOSessionTTLSeconds: DefaultSSOSessionTTLSeconds,
				SSOContinueMode:      SSOContinueModeTap,
			},
		},
		{
			name: "enabled silent mode",
			cfg: Config{
				SSOEnabled:           true,
				SSOSessionTTLSeconds: 3600,
				SSOContinueMode:      SSOContinueModeSilent,
			},
		},
		{
			// A zero TTL would expire every session the instant it is
			// created — fail the boot instead of behaving surprisingly.
			name: "zero ttl",
			cfg: Config{
				SSOEnabled:           true,
				SSOSessionTTLSeconds: 0,
				SSOContinueMode:      SSOContinueModeTap,
			},
			wantErr: true,
		},
		{
			name: "negative ttl",
			cfg: Config{
				SSOEnabled:           true,
				SSOSessionTTLSeconds: -1,
				SSOContinueMode:      SSOContinueModeTap,
			},
			wantErr: true,
		},
		{
			// An unrecognized mode must never fall back to the more
			// permissive of the two.
			name: "unknown continue mode",
			cfg: Config{
				SSOEnabled:           true,
				SSOSessionTTLSeconds: 3600,
				SSOContinueMode:      "auto",
			},
			wantErr: true,
		},
		{
			name: "empty continue mode",
			cfg: Config{
				SSOEnabled:           true,
				SSOSessionTTLSeconds: 3600,
				SSOContinueMode:      "",
			},
			wantErr: true,
		},
		{
			name: "hub origins happy path",
			cfg: Config{
				SSOEnabled:           true,
				SSOSessionTTLSeconds: 3600,
				SSOContinueMode:      SSOContinueModeTap,
				SSOHubOrigins:        "https://accounts.example.com, http://localhost:3020",
			},
		},
		{
			name: "hub origin with a path",
			cfg: Config{
				SSOEnabled:           true,
				SSOSessionTTLSeconds: 3600,
				SSOContinueMode:      SSOContinueModeTap,
				SSOHubOrigins:        "https://accounts.example.com/login",
			},
			wantErr: true,
		},
		{
			name: "hub origin wildcard",
			cfg: Config{
				SSOEnabled:           true,
				SSOSessionTTLSeconds: 3600,
				SSOContinueMode:      SSOContinueModeTap,
				SSOHubOrigins:        "*",
			},
			wantErr: true,
		},
		{
			name: "hub origin without a scheme",
			cfg: Config{
				SSOEnabled:           true,
				SSOSessionTTLSeconds: 3600,
				SSOContinueMode:      SSOContinueModeTap,
				SSOHubOrigins:        "accounts.example.com",
			},
			wantErr: true,
		},
		{
			name: "hub origin with credentials",
			cfg: Config{
				SSOEnabled:           true,
				SSOSessionTTLSeconds: 3600,
				SSOContinueMode:      SSOContinueModeTap,
				SSOHubOrigins:        "https://user:pass@accounts.example.com",
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validateSSO()
			if tc.wantErr && err == nil {
				t.Fatal("validateSSO: want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateSSO: want nil, got %v", err)
			}
		})
	}
}

func TestSSOHubOriginList(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty disables the endpoint", in: "", want: nil},
		{name: "blanks dropped", in: " , ,", want: nil},
		{
			name: "trimmed and split",
			in:   " https://accounts.example.com , http://localhost:3020 ",
			want: []string{"https://accounts.example.com", "http://localhost:3020"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := (&Config{SSOHubOrigins: tc.in}).SSOHubOriginList()
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("SSOHubOriginList: got %#v, want %#v", got, tc.want)
			}
		})
	}
}
