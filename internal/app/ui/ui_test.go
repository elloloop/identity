package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elloloop/identity/internal/config"
)

// TestHandler_ServesEmbeddedIndex exercises the static UI handler: a GET
// under /auth/ resolves the embedded index.html and returns it. This is the
// only reachable path — the fs.Sub error branch cannot trigger because the
// static tree is embedded at build time.
func TestHandler_ServesEmbeddedIndex(t *testing.T) {
	h := Handler(&config.Config{PasswordSignupEnabled: true})

	// GET /auth/ serves the embedded index.html (FileServer renders a
	// directory's index). A bare /auth/index.html is canonicalised by
	// FileServer to /auth/ with a 301, so the directory form is the one to
	// assert.
	req := httptest.NewRequest(http.MethodGet, "/auth/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /auth/: status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("GET /auth/: empty body, want embedded index.html content")
	}
}

// TestHandler_InjectsServerConfig confirms the handler renders the server
// config into the page so the SPA can render conditionally (e.g. hide the
// signup option when password signup is disabled).
func TestHandler_InjectsServerConfig(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		h := Handler(&config.Config{PasswordSignupEnabled: enabled})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/", nil))

		body := rec.Body.String()
		want := `"passwordSignupEnabled":` + map[bool]string{true: "true", false: "false"}[enabled]
		if !strings.Contains(body, want) {
			t.Errorf("PasswordSignupEnabled=%v: rendered page missing injected %q", enabled, want)
		}
	}
}

// TestHandler_InjectsCaptchaConfig confirms the public CAPTCHA provider + site
// key reach the SPA only when CAPTCHA is enabled with a Turnstile site key —
// so the sign-up widget renders exactly when it should and never leaks a key
// while CAPTCHA is off.
func TestHandler_InjectsCaptchaConfig(t *testing.T) {
	t.Run("enabled with turnstile site key", func(t *testing.T) {
		h := Handler(&config.Config{
			CaptchaEnabled:          true,
			CaptchaProvider:         config.CaptchaProviderTurnstile,
			CaptchaTurnstileSiteKey: "0xSITEKEY",
		})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/", nil))
		body := rec.Body.String()

		for _, want := range []string{`"captchaProvider":"turnstile"`, `"captchaSiteKey":"0xSITEKEY"`} {
			if !strings.Contains(body, want) {
				t.Errorf("rendered page missing injected %q", want)
			}
		}
	})

	t.Run("disabled injects empty captcha config", func(t *testing.T) {
		h := Handler(&config.Config{
			CaptchaEnabled:          false,
			CaptchaProvider:         config.CaptchaProviderTurnstile,
			CaptchaTurnstileSiteKey: "0xSITEKEY",
		})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/", nil))
		body := rec.Body.String()

		if strings.Contains(body, "0xSITEKEY") {
			t.Error("site key leaked into the page while CAPTCHA is disabled")
		}
		if !strings.Contains(body, `"captchaProvider":""`) {
			t.Error("expected empty captchaProvider while CAPTCHA is disabled")
		}
	})
}
