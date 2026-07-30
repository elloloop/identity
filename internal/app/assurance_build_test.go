package app

import (
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/assurance"
)

func TestBuildWebAssuranceVerifier(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
		// wantNil asserts the disabled path returns no verifier (the
		// service treats nil as "web assurance unavailable").
		wantNil bool
	}{
		{
			name:    "disabled returns nil",
			cfg:     &config.Config{AssuranceEnabled: false},
			wantNil: true,
		},
		{
			name:    "enabled but no web provider returns nil",
			cfg:     &config.Config{AssuranceEnabled: true, AssuranceWebProvider: ""},
			wantNil: true,
		},
		{
			name: "turnstile builds",
			cfg: &config.Config{
				AssuranceEnabled:         true,
				AssuranceWebProvider:     assurance.ProviderTurnstile,
				AssuranceTurnstileSecret: "secret",
			},
		},
		{
			name: "recaptcha_v3 builds",
			cfg: &config.Config{
				AssuranceEnabled:                 true,
				AssuranceWebProvider:             assurance.ProviderRecaptchaV3,
				AssuranceRecaptchaSecret:         "secret",
				AssuranceRecaptchaScoreThreshold: 0.5,
			},
		},
		{
			name: "turnstile without secret errors",
			cfg: &config.Config{
				AssuranceEnabled:     true,
				AssuranceWebProvider: assurance.ProviderTurnstile,
			},
			wantErr: true,
		},
		{
			name: "unknown provider errors",
			cfg: &config.Config{
				AssuranceEnabled:     true,
				AssuranceWebProvider: "nope",
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := buildWebAssuranceVerifier(tc.cfg, zap.NewNop())
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got verifier %#v", v)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantNil != (v == nil) {
				t.Fatalf("verifier = %#v; wantNil=%v", v, tc.wantNil)
			}
		})
	}
}

func TestBuildAssuranceResolver(t *testing.T) {
	t.Run("disabled returns nil", func(t *testing.T) {
		r, err := buildAssuranceResolver(&config.Config{AssuranceEnabled: false}, nil, zap.NewNop())
		if err != nil || r != nil {
			t.Fatalf("disabled: (%v, %v), want (nil, nil)", r, err)
		}
	})
	t.Run("enabled with no platforms still resolves", func(t *testing.T) {
		r, err := buildAssuranceResolver(&config.Config{AssuranceEnabled: true}, nil, zap.NewNop())
		if err != nil || r == nil {
			t.Fatalf("no platforms: (%v, %v)", r, err)
		}
	})
	t.Run("ios identity builds", func(t *testing.T) {
		r, err := buildAssuranceResolver(&config.Config{
			AssuranceEnabled:     true,
			AssuranceIOSTeamID:   "TEAM123456",
			AssuranceIOSBundleID: "com.example.app",
			AssuranceIOSEnv:      "production",
		}, nil, zap.NewNop())
		if err != nil || r == nil {
			t.Fatalf("ios: (%v, %v)", r, err)
		}
	})
	t.Run("bad ios env errors", func(t *testing.T) {
		_, err := buildAssuranceResolver(&config.Config{
			AssuranceEnabled:     true,
			AssuranceIOSTeamID:   "TEAM123456",
			AssuranceIOSBundleID: "com.example.app",
			AssuranceIOSEnv:      "staging",
		}, nil, zap.NewNop())
		if err == nil {
			t.Fatal("expected error for unknown ios env")
		}
	})
	t.Run("android without valid SA key errors", func(t *testing.T) {
		_, err := buildAssuranceResolver(&config.Config{
			AssuranceEnabled:            true,
			AssuranceAndroidPackageName: "com.example.app",
			AssuranceAndroidCertDigests: "ZGlnZXN0",
			AssuranceAndroidSAKeyJSON:   "not-json",
		}, nil, zap.NewNop())
		if err == nil {
			t.Fatal("expected error for malformed service-account key")
		}
	})
}
