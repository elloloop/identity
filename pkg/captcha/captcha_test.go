package captcha_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/elloloop/identity/pkg/captcha"
)

// newServer returns an httptest server running handler, registered for
// cleanup. The server URL is fed to the verifier under test as VerifyURL,
// so no real network call is made and no literal URL appears in a test.
func newServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// assertForm fails the test unless the posted form carried the expected
// secret/response (and remoteip when expected).
func assertForm(t *testing.T, r *http.Request, wantSecret, wantResponse, wantRemoteIP string) {
	t.Helper()
	if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q", got)
	}
	if err := r.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	if got := r.PostForm.Get("secret"); got != wantSecret {
		t.Errorf("secret = %q; want %q", got, wantSecret)
	}
	if got := r.PostForm.Get("response"); got != wantResponse {
		t.Errorf("response = %q; want %q", got, wantResponse)
	}
	if got := r.PostForm.Get("remoteip"); got != wantRemoteIP {
		t.Errorf("remoteip = %q; want %q", got, wantRemoteIP)
	}
}

func TestNoopVerifier_AlwaysSucceeds(t *testing.T) {
	t.Parallel()
	v := captcha.NewNoopVerifier()
	if v.Name() != "noop" {
		t.Fatalf("Name = %q; want noop", v.Name())
	}
	if err := v.Verify(context.Background(), "", ""); err != nil {
		t.Fatalf("Verify empty token: %v", err)
	}
	if err := v.Verify(context.Background(), "anything", "1.2.3.4"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestNewTurnstileVerifier_RequiresSecret(t *testing.T) {
	t.Parallel()
	if _, err := captcha.NewTurnstileVerifier(captcha.TurnstileConfig{}); err == nil {
		t.Fatal("missing secret should error")
	}
}

func TestNewRecaptchaV3Verifier_RequiresSecretAndThresholdRange(t *testing.T) {
	t.Parallel()
	if _, err := captcha.NewRecaptchaV3Verifier(captcha.RecaptchaConfig{ScoreThreshold: 0.5}); err == nil {
		t.Fatal("missing secret should error")
	}
	if _, err := captcha.NewRecaptchaV3Verifier(captcha.RecaptchaConfig{Secret: "s", ScoreThreshold: 1.5}); err == nil {
		t.Fatal("threshold > 1 should error")
	}
	if _, err := captcha.NewRecaptchaV3Verifier(captcha.RecaptchaConfig{Secret: "s", ScoreThreshold: -0.1}); err == nil {
		t.Fatal("threshold < 0 should error")
	}
}

func TestTurnstileVerifier_Verify(t *testing.T) {
	t.Parallel()

	const secret = "ts-secret"

	tests := []struct {
		name     string
		token    string
		remoteIP string
		handler  http.HandlerFunc
		wantErr  error
	}{
		{
			name:     "success",
			token:    "good-token",
			remoteIP: "203.0.113.7",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assertForm(t, r, secret, "good-token", "203.0.113.7")
				_, _ = io.WriteString(w, `{"success":true,"challenge_ts":"2026-01-01T00:00:00Z","hostname":"example.com"}`)
			},
		},
		{
			name:  "no remoteip omitted from form",
			token: "good-token",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assertForm(t, r, secret, "good-token", "")
				_, _ = io.WriteString(w, `{"success":true}`)
			},
		},
		{
			name:  "provider rejects with error codes",
			token: "bad-token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"success":false,"error-codes":["invalid-input-response"]}`)
			},
			wantErr: captcha.ErrVerificationFailed,
		},
		{
			name:  "empty token rejected without a request",
			token: "",
			handler: func(http.ResponseWriter, *http.Request) {
				t.Error("verifier must not call siteverify for an empty token")
			},
			wantErr: captcha.ErrVerificationFailed,
		},
		{
			name:    "non-200 is provider unavailable",
			token:   "good-token",
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
			wantErr: captcha.ErrProviderUnavailable,
		},
		{
			name:    "malformed json is provider unavailable",
			token:   "good-token",
			handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{not json`) },
			wantErr: captcha.ErrProviderUnavailable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := newServer(t, tc.handler)
			v, err := captcha.NewTurnstileVerifier(captcha.TurnstileConfig{
				Secret:     secret,
				HTTPClient: srv.Client(),
				VerifyURL:  srv.URL,
			})
			if err != nil {
				t.Fatalf("NewTurnstileVerifier: %v", err)
			}
			if v.Name() != captcha.ProviderTurnstile {
				t.Fatalf("Name = %q", v.Name())
			}

			err = v.Verify(context.Background(), tc.token, tc.remoteIP)
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("Verify: unexpected error %v", err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("Verify err = %v; want %v", err, tc.wantErr)
			}
		})
	}
}

func TestRecaptchaV3Verifier_Verify(t *testing.T) {
	t.Parallel()

	const (
		secret    = "rc-secret"
		threshold = 0.5
	)

	scoreBody := func(score float64) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"success":true,"action":"login","score":`+strconv.FormatFloat(score, 'f', -1, 64)+`}`)
		}
	}

	tests := []struct {
		name    string
		token   string
		handler http.HandlerFunc
		wantErr error
	}{
		{
			name:    "score above threshold passes",
			token:   "good",
			handler: scoreBody(0.9),
		},
		{
			name:    "score equal to threshold passes (boundary)",
			token:   "good",
			handler: scoreBody(threshold),
		},
		{
			name:    "score below threshold rejected (boundary)",
			token:   "good",
			handler: scoreBody(0.49),
			wantErr: captcha.ErrVerificationFailed,
		},
		{
			name:  "success false rejected",
			token: "bad",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"success":false,"error-codes":["timeout-or-duplicate"]}`)
			},
			wantErr: captcha.ErrVerificationFailed,
		},
		{
			name:    "empty token rejected",
			token:   "",
			handler: func(http.ResponseWriter, *http.Request) { t.Error("must not call siteverify for empty token") },
			wantErr: captcha.ErrVerificationFailed,
		},
		{
			name:    "non-200 is provider unavailable",
			token:   "good",
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) },
			wantErr: captcha.ErrProviderUnavailable,
		},
		{
			name:    "malformed json is provider unavailable",
			token:   "good",
			handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `not-json`) },
			wantErr: captcha.ErrProviderUnavailable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := newServer(t, tc.handler)
			v, err := captcha.NewRecaptchaV3Verifier(captcha.RecaptchaConfig{
				Secret:         secret,
				ScoreThreshold: threshold,
				HTTPClient:     srv.Client(),
				VerifyURL:      srv.URL,
			})
			if err != nil {
				t.Fatalf("NewRecaptchaV3Verifier: %v", err)
			}
			if v.Name() != captcha.ProviderRecaptchaV3 {
				t.Fatalf("Name = %q", v.Name())
			}

			err = v.Verify(context.Background(), tc.token, "")
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("Verify: unexpected error %v", err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("Verify err = %v; want %v", err, tc.wantErr)
			}
		})
	}
}

// TestTurnstileVerifier_TransportError points the verifier at a server that
// has already been closed, so the dial fails fast with a connection error
// mapped to ErrProviderUnavailable. The server's own Client() is used so the
// failure is a transport error, not a TLS or routing surprise.
func TestTurnstileVerifier_TransportError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := srv.URL
	client := srv.Client()
	srv.Close()

	v, err := captcha.NewTurnstileVerifier(captcha.TurnstileConfig{
		Secret:     "s",
		VerifyURL:  closedURL,
		HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("NewTurnstileVerifier: %v", err)
	}
	if err := v.Verify(context.Background(), "token", ""); !errors.Is(err, captcha.ErrProviderUnavailable) {
		t.Fatalf("Verify err = %v; want ErrProviderUnavailable", err)
	}
}

// TestRecaptchaV3Verifier_ContextCanceled verifies that a context cancelled
// before the call surfaces as ErrProviderUnavailable. Using an already-dead
// context (rather than a blocking handler + timeout) keeps the test
// deterministic and instant.
func TestRecaptchaV3Verifier_ContextCanceled(t *testing.T) {
	t.Parallel()

	srv := newServer(t, func(http.ResponseWriter, *http.Request) {
		t.Error("must not reach the handler with a cancelled context")
	})
	v, err := captcha.NewRecaptchaV3Verifier(captcha.RecaptchaConfig{
		Secret:         "s",
		ScoreThreshold: 0.5,
		HTTPClient:     srv.Client(),
		VerifyURL:      srv.URL,
	})
	if err != nil {
		t.Fatalf("NewRecaptchaV3Verifier: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := v.Verify(ctx, "token", ""); !errors.Is(err, captcha.ErrProviderUnavailable) {
		t.Fatalf("Verify err = %v; want ErrProviderUnavailable", err)
	}
}
