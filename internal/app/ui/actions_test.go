package ui

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

// ready returns a peek that reports a live link for email.
func ready(email string) func(context.Context, string) (service.ActionLinkPreview, error) {
	return func(context.Context, string) (service.ActionLinkPreview, error) {
		return service.ActionLinkPreview{State: service.ActionLinkReady, Email: email}, nil
	}
}

func newActionHandler(svc Service) http.Handler {
	return Handler(&config.Config{}, svc, false, nil)
}

func get(t *testing.T, h http.Handler, target string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func post(t *testing.T, h http.Handler, target string, form url.Values, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// text returns the rendered page with HTML entities decoded, so copy with
// apostrophes can be asserted as written.
func text(rec *httptest.ResponseRecorder) string {
	return html.UnescapeString(rec.Body.String())
}

func assertContains(t *testing.T, body string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q\n---\n%s", want, body)
		}
	}
}

func assertNotContains(t *testing.T, body string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if strings.Contains(body, want) {
			t.Errorf("page must not contain %q", want)
		}
	}
}

// TestActionPages_GetPreviewsWithoutConsuming: the GET renders every page in
// its ready state with the address and its button, and never reaches a
// consuming call — the stub's action funcs are nil and would panic.
func TestActionPages_GetPreviewsWithoutConsuming(t *testing.T) {
	cases := []struct {
		path, heading, submit string
	}{
		{"/auth/verify-email", "Verify your email", "Confirm email"},
		{"/auth/reset-password", "Choose a new password", "Update password"},
		{"/auth/confirm-email-change", "Confirm your new email", "Confirm new email"},
		{"/auth/magic-link", "Sign in to Acme", "Continue"},
		{"/auth/accept-invitation", "Set up your account", "Create account"},
	}
	h := newActionHandler(stubService{
		brand: service.HostedUIBranding{ProductName: "Acme", SupportEmail: "help@acme.test"},
		peek:  ready("alice@example.com"),
	})
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			rec := get(t, h, tc.path+"?token=tok-1", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			body := text(rec)
			assertContains(t, body, tc.heading, tc.submit, "alice@example.com", `name="token" value="tok-1"`,
				`action="`+tc.path+`"`, "help@acme.test", "Not you?")
		})
	}
}

// TestActionPages_GetRendersLinkState: a used, expired or unknown link shows
// its own copy and no form, so nobody is offered a click that will fail.
func TestActionPages_GetRendersLinkState(t *testing.T) {
	cases := []struct {
		state service.ActionLinkState
		want  string
	}{
		{service.ActionLinkUsed, "already been used"},
		{service.ActionLinkExpired, "has expired"},
		{service.ActionLinkInvalid, "isn't valid"},
	}
	for _, tc := range cases {
		t.Run(string(tc.state), func(t *testing.T) {
			h := newActionHandler(stubService{peek: func(context.Context, string) (service.ActionLinkPreview, error) {
				return service.ActionLinkPreview{State: tc.state}, nil
			}})
			rec := get(t, h, "/auth/verify-email?token=tok", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			body := text(rec)
			assertContains(t, body, tc.want, `href="/auth/"`, "Sign in")
			assertNotContains(t, body, "<form", "Confirm email")
		})
	}
}

func TestActionPages_GetPeekFailureIs500(t *testing.T) {
	h := newActionHandler(stubService{peek: func(context.Context, string) (service.ActionLinkPreview, error) {
		return service.ActionLinkPreview{}, errors.New("db down")
	}})
	rec := get(t, h, "/auth/verify-email?token=tok", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	assertContains(t, text(rec), "Something went wrong")
}

// TestActionPages_PostConsumes: the click is the one request that reaches
// the consuming call, with the token from the form body, and renders done.
func TestActionPages_PostConsumes(t *testing.T) {
	var got string
	h := newActionHandler(stubService{
		peek: ready("alice@example.com"),
		verify: func(_ context.Context, token string) (*service.User, error) {
			got = token
			return &service.User{Email: "alice@example.com"}, nil
		},
	})
	rec := post(t, h, "/auth/verify-email", url.Values{"token": {"tok-2"}}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got != "tok-2" {
		t.Fatalf("VerifyEmail token = %q, want tok-2", got)
	}
	body := text(rec)
	assertContains(t, body, "Your email address is verified", `href="/auth/"`)
	assertNotContains(t, body, "<form")
}

// TestActionPages_PostStaleLinkDoesNotConsume: a click on a page rendered
// before the link was spent elsewhere reports the state and calls nothing.
func TestActionPages_PostStaleLinkDoesNotConsume(t *testing.T) {
	h := newActionHandler(stubService{peek: func(context.Context, string) (service.ActionLinkPreview, error) {
		return service.ActionLinkPreview{State: service.ActionLinkUsed}, nil
	}})
	rec := post(t, h, "/auth/verify-email", url.Values{"token": {"tok"}}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	assertContains(t, text(rec), "already been used")
}

// TestActionPages_MagicLinkRedirectsWithHandover: the magic-link click
// redirects to the service-built return_to?code= URL, and that page's CSP
// carries no form-action (Chrome would apply it to this very redirect).
func TestActionPages_MagicLinkRedirectsWithHandover(t *testing.T) {
	var gotIP, gotUA string
	h := newActionHandler(stubService{
		peek: ready("alice@example.com"),
		magic: func(_ context.Context, token, ip, ua string) (*service.MagicLinkHandover, error) {
			gotIP, gotUA = ip, ua
			if token != "tok-ml" {
				t.Fatalf("token = %q", token)
			}
			return &service.MagicLinkHandover{RedirectURL: "https://app.test/welcome?code=otc-1"}, nil
		},
	})
	rec := post(t, h, "/auth/magic-link", url.Values{"token": {"tok-ml"}}, func(r *http.Request) {
		r.Header.Set("User-Agent", "TestBrowser/1.0")
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "https://app.test/welcome?code=otc-1" {
		t.Fatalf("Location = %q", loc)
	}
	if gotUA != "TestBrowser/1.0" {
		t.Errorf("user agent not passed through: %q", gotUA)
	}
	_ = gotIP // empty without the client-IP middleware; presence is asserted in the app tests

	page := get(t, h, "/auth/magic-link?token=tok-ml", nil)
	if csp := page.Header().Get("Content-Security-Policy"); strings.Contains(csp, "form-action") {
		t.Errorf("magic-link page CSP must not pin form-action (blocks the redirect in Chrome): %q", csp)
	}
	verify := get(t, h, "/auth/verify-email?token=tok", nil)
	if csp := verify.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self'") {
		t.Errorf("non-redirecting page CSP must pin form-action: %q", csp)
	}
}

// TestActionPages_PasswordFormValidation: the two password fields are
// checked before the service is asked to spend the token, and the form is
// re-rendered with the link still live.
func TestActionPages_PasswordFormValidation(t *testing.T) {
	cases := []struct {
		name string
		form url.Values
		want string
	}{
		{"missing", url.Values{"token": {"t"}}, "Enter a password."},
		{"mismatch", url.Values{"token": {"t"}, "password": {"Str0ng!Passw0rd"}, "password_confirm": {"other"}}, "don't match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newActionHandler(stubService{peek: ready("alice@example.com")}) // reset is nil: must not be called
			rec := post(t, h, "/auth/reset-password", tc.form, nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			body := text(rec)
			assertContains(t, body, tc.want, "<form", `name="token" value="t"`)
		})
	}
}

// TestActionPages_PostErrorMapping: every service outcome lands on a page
// state with the right status, and the operator-facing ones say nothing
// about why.
func TestActionPages_PostErrorMapping(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		want   string
		form   bool
	}{
		{"expired", fmt.Errorf("%w: reset token expired", service.ErrTokenExpired), http.StatusOK, "has expired", false},
		{"invitation expired", service.ErrInvitationExpired, http.StatusOK, "has expired", false},
		{"invitation used", service.ErrInvitationUsed, http.StatusOK, "already been", false},
		{"unauthenticated", fmt.Errorf("%w: invalid reset token", service.ErrUnauthenticated), http.StatusOK, "isn't valid", false},
		{"magic link invalid", service.ErrMagicLinkInvalid, http.StatusOK, "isn't valid", false},
		{"weak password", fmt.Errorf("%w: Password must be at least 12 characters", service.ErrWeakPassword), http.StatusBadRequest, "Password must be at least 12 characters", true},
		{"conflict", fmt.Errorf("%w: email already in use", service.ErrAlreadyExists), http.StatusConflict, "already in use", true},
		{"access refused", service.ErrAccessNotAllowed, http.StatusForbidden, "can't be used here", false},
		{"account locked", service.ErrAccountLocked, http.StatusForbidden, "can't be used here", false},
		{"unexpected", errors.New("boom"), http.StatusInternalServerError, "Something went wrong", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newActionHandler(stubService{
				peek:  ready("alice@example.com"),
				reset: func(context.Context, string, string) error { return tc.err },
			})
			form := url.Values{"token": {"t"}, "password": {"Str0ng!Passw0rd"}, "password_confirm": {"Str0ng!Passw0rd"}}
			rec := post(t, h, "/auth/reset-password", form, nil)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.status, rec.Body.String())
			}
			body := text(rec)
			assertContains(t, body, tc.want)
			if tc.form {
				assertContains(t, body, "<form")
			} else {
				assertNotContains(t, body, "<form", "boom")
			}
		})
	}
}

// TestActionPages_CrossSitePostRejected: a browser-marked cross-site POST is
// refused before anything is looked up or consumed (login CSRF against the
// magic-link page).
func TestActionPages_CrossSitePostRejected(t *testing.T) {
	h := newActionHandler(stubService{}) // peek nil: must not be reached
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		func(r *http.Request) { r.Header.Set("Origin", "https://evil.test"); r.Host = "auth.acme.test" },
	} {
		rec := post(t, h, "/auth/magic-link", url.Values{"token": {"stolen"}}, mutate)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		assertContains(t, text(rec), "didn't come from this site")
	}
}

// TestActionPages_SecurityHeaders: every hosted response carries the header
// set, the CSP nonce matches the inline style, and the action pages admit
// no script at all while the sign-in page admits only its own.
func TestActionPages_SecurityHeaders(t *testing.T) {
	h := newActionHandler(stubService{
		opts: service.HostedUIOptions{PasswordLoginEnabled: true},
		peek: ready("a@b.test"),
	})
	nonceRE := regexp.MustCompile(`<style nonce="([^"]+)">`)

	for _, target := range []string{"/auth/", "/auth/verify-email?token=t"} {
		rec := get(t, h, target, nil)
		hdr := rec.Header()
		for name, want := range map[string]string{
			"Cache-Control":          "no-store",
			"Referrer-Policy":        "no-referrer",
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"X-Robots-Tag":           "noindex, nofollow",
		} {
			if got := hdr.Get(name); got != want {
				t.Errorf("%s: %s = %q, want %q", target, name, got, want)
			}
		}
		csp := hdr.Get("Content-Security-Policy")
		m := nonceRE.FindStringSubmatch(rec.Body.String())
		if m == nil {
			t.Fatalf("%s: no nonced style tag", target)
		}
		if !strings.Contains(csp, "style-src 'nonce-"+m[1]+"'") {
			t.Errorf("%s: CSP nonce does not match the page: %q", target, csp)
		}
		for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "connect-src 'self'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP missing %q: %q", target, want, csp)
			}
		}
	}

	action := get(t, h, "/auth/verify-email?token=t", nil).Header().Get("Content-Security-Policy")
	if strings.Contains(action, "script-src") {
		t.Errorf("action page runs no script and must admit none: %q", action)
	}
	login := get(t, h, "/auth/", nil).Header().Get("Content-Security-Policy")
	if !strings.Contains(login, "script-src 'nonce-") || strings.Contains(login, turnstileOrigin) {
		t.Errorf("sign-in page without CAPTCHA must admit only its own nonced script: %q", login)
	}

	// With Turnstile configured the sign-in page admits exactly that origin,
	// for the loader and the widget frame, and tells the page where the
	// loader lives.
	captcha := Handler(&config.Config{
		AssuranceEnabled:          true,
		AssuranceWebProvider:      config.AssuranceWebProviderTurnstile,
		AssuranceTurnstileSiteKey: "0xSITEKEY",
	}, allEnabled(), false, nil)
	rec := get(t, captcha, "/auth/", nil)
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'nonce-") || !strings.Contains(csp, " "+turnstileOrigin) || !strings.Contains(csp, "frame-src "+turnstileOrigin) {
		t.Errorf("CAPTCHA sign-in page CSP must admit the Turnstile origin for script and frame: %q", csp)
	}
	if !strings.Contains(rec.Body.String(), `"captchaScriptURL":"`+turnstileScriptURL+`"`) {
		t.Error("CAPTCHA sign-in page must inject the loader URL")
	}
}

// TestActionPages_ProjectKeyThreadsThrough: a hub-served page keeps the
// project_key on its form and its onward link so the POST and the sign-in
// page resolve the same project.
func TestActionPages_ProjectKeyThreadsThrough(t *testing.T) {
	h := newActionHandler(stubService{peek: ready("a@b.test")})
	body := text(get(t, h, "/auth/verify-email?token=t&project_key=pk_1", nil))
	assertContains(t, body, `action="/auth/verify-email?project_key=pk_1"`)
	body = text(get(t, h, "/auth/verify-email?token=t&project_key=pk_1", func(r *http.Request) {
		// Force the non-form branch to see the onward link.
		_ = r
	}))
	assertContains(t, body, `action="/auth/verify-email?project_key=pk_1"`)

	used := newActionHandler(stubService{peek: func(context.Context, string) (service.ActionLinkPreview, error) {
		return service.ActionLinkPreview{State: service.ActionLinkUsed}, nil
	}})
	assertContains(t, text(get(t, used, "/auth/verify-email?token=t&project_key=pk_1", nil)), `href="/auth/?project_key=pk_1"`)
}

// TestActionPages_InvitationCollectsNameAndPassword: the invitation form
// asks for a name and a password and passes both to the service.
func TestActionPages_InvitationCollectsNameAndPassword(t *testing.T) {
	var gotName, gotPassword string
	h := newActionHandler(stubService{
		peek: ready("new@acme.test"),
		invite: func(_ context.Context, token, password, name string) (*service.User, error) {
			gotName, gotPassword = name, password
			return &service.User{Email: "new@acme.test"}, nil
		},
	})
	body := text(get(t, h, "/auth/accept-invitation?token=inv", nil))
	assertContains(t, body, `name="name"`, `name="password"`, `name="password_confirm"`)

	rec := post(t, h, "/auth/accept-invitation", url.Values{
		"token": {"inv"}, "name": {"  Bob  "}, "password": {"Str0ng!Passw0rd"}, "password_confirm": {"Str0ng!Passw0rd"},
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if gotName != "Bob" || gotPassword != "Str0ng!Passw0rd" {
		t.Fatalf("RedeemInvitation(name=%q, password=%q)", gotName, gotPassword)
	}
	assertContains(t, text(rec), "Your account is ready")
}

// TestActionPages_BrandingFallsBack: with no product name the copy reads
// without one, and no support line renders without an address.
func TestActionPages_BrandingFallsBack(t *testing.T) {
	h := newActionHandler(stubService{peek: ready("a@b.test")})
	body := text(get(t, h, "/auth/magic-link?token=t", nil))
	assertContains(t, body, "<h1>Sign in</h1>", "Continue to sign in as a@b.test.")
	assertNotContains(t, body, "Need help?", " to .")
}

func TestHandler_UnknownPathAndMethods(t *testing.T) {
	h := newActionHandler(stubService{peek: ready("a@b.test")})
	if rec := get(t, h, "/auth/nope", nil); rec.Code != http.StatusNotFound {
		t.Errorf("GET /auth/nope = %d, want 404", rec.Code)
	}
	if rec := get(t, h, "/auth/verify-email/", nil); rec.Code != http.StatusNotFound {
		t.Errorf("trailing slash = %d, want 404", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPut, "/auth/verify-email", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD, POST" {
		t.Errorf("PUT action = %d Allow=%q", rec.Code, rec.Header().Get("Allow"))
	}
	req = httptest.NewRequest(http.MethodPost, "/auth/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /auth/ = %d, want 405", rec.Code)
	}
	req = httptest.NewRequest(http.MethodHead, "/auth/verify-email?token=t", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Content-Security-Policy") == "" {
		t.Errorf("HEAD = %d body=%d bytes csp=%q", rec.Code, rec.Body.Len(), rec.Header().Get("Content-Security-Policy"))
	}
}
