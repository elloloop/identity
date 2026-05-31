package app

import (
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/captcha"
)

func TestBuildCaptchaVerifier(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
		// wantNoop asserts the disabled path returns the no-op verifier.
		wantNoop bool
	}{
		{
			name:     "disabled returns noop",
			cfg:      &config.Config{CaptchaEnabled: false},
			wantNoop: true,
		},
		{
			name:     "enabled but empty provider returns noop",
			cfg:      &config.Config{CaptchaEnabled: true, CaptchaProvider: ""},
			wantNoop: true,
		},
		{
			name: "turnstile builds",
			cfg: &config.Config{
				CaptchaEnabled:         true,
				CaptchaProvider:        captcha.ProviderTurnstile,
				CaptchaTurnstileSecret: "secret",
			},
		},
		{
			name: "recaptcha_v3 builds",
			cfg: &config.Config{
				CaptchaEnabled:                 true,
				CaptchaProvider:                captcha.ProviderRecaptchaV3,
				CaptchaRecaptchaSecret:         "secret",
				CaptchaRecaptchaScoreThreshold: 0.5,
			},
		},
		{
			name: "turnstile without secret errors",
			cfg: &config.Config{
				CaptchaEnabled:  true,
				CaptchaProvider: captcha.ProviderTurnstile,
			},
			wantErr: true,
		},
		{
			name: "unknown provider errors",
			cfg: &config.Config{
				CaptchaEnabled:  true,
				CaptchaProvider: "nope",
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := buildCaptchaVerifier(tc.cfg, zap.NewNop())
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got verifier %#v", v)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v == nil {
				t.Fatal("expected non-nil verifier")
			}
			_, isNoop := v.(captcha.NoopVerifier)
			if tc.wantNoop && !isNoop {
				t.Fatalf("expected no-op verifier, got %T", v)
			}
			if !tc.wantNoop && isNoop {
				t.Fatalf("expected a real provider verifier, got no-op")
			}
		})
	}
}

// TestBuildCaptchaVerifier_NilLogger ensures a nil logger is tolerated.
func TestBuildCaptchaVerifier_NilLogger(t *testing.T) {
	v, err := buildCaptchaVerifier(&config.Config{CaptchaEnabled: false}, nil)
	if err != nil || v == nil {
		t.Fatalf("nil logger: err=%v v=%v", err, v)
	}
}
