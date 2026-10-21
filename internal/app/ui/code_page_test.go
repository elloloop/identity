package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/service"
)

const testBoundCode = "pkce_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func serveCodePage(t *testing.T, method string, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	CodePageHandler().ServeHTTP(rec, httptest.NewRequest(method, CodePagePath+"?"+query.Encode(), nil))
	return rec
}

// The page shows a bound code with the app's state as code#state, and a copy
// button the script reveals.
func TestCodePageShowsABoundCodeWithTheAppsState(t *testing.T) {
	rec := serveCodePage(t, http.MethodGet, url.Values{"code": {testBoundCode}, "state": {"8436cfbd3cf94948"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `<p class="value" id="code">`+testBoundCode+`#8436cfbd3cf94948</p>`) {
		t.Fatalf("page does not show code#state:\n%s", body)
	}
	for _, want := range []string{`id="copy" hidden`, `role="status"`, "Only paste it into the app where you started signing in.", "It works once, within a minute."} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

func TestCodePageShowsTheCodeAloneWithoutAState(t *testing.T) {
	rec := serveCodePage(t, http.MethodGet, url.Values{"code": {testBoundCode}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="code">`+testBoundCode+`</p>`) {
		t.Fatalf("status %d; page does not show the code alone:\n%s", rec.Code, rec.Body.String())
	}
}

// Every answer carries the page's protections, and its one script and one
// style block run only under the per-response nonce.
func TestCodePageHeaders(t *testing.T) {
	for _, query := range []url.Values{
		{"code": {testBoundCode}, "state": {"s"}},
		{"error": {"access_denied"}},
		{},
	} {
		rec := serveCodePage(t, http.MethodGet, query)
		h := rec.Header()
		if h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" ||
			h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" ||
			h.Get("Content-Type") != "text/html; charset=utf-8" {
			t.Fatalf("query %v: unsafe headers %v", query, h)
		}
		csp := h.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "form-action 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("query %v: CSP %q lacks %q", query, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-inline") {
			t.Errorf("query %v: CSP allows inline code: %q", query, csp)
		}
		nonces := regexp.MustCompile(`nonce="([^"]+)"`).FindAllStringSubmatch(rec.Body.String(), -1)
		if len(nonces) != 2 || nonces[0][1] != nonces[1][1] || !strings.Contains(csp, "script-src 'nonce-"+nonces[0][1]+"'") || !strings.Contains(csp, "style-src 'nonce-"+nonces[0][1]+"'") {
			t.Fatalf("query %v: the script and style need the CSP's nonce; CSP %q", query, csp)
		}
	}
	first := serveCodePage(t, http.MethodGet, url.Values{}).Header().Get("Content-Security-Policy")
	if first == serveCodePage(t, http.MethodGet, url.Values{}).Header().Get("Content-Security-Policy") {
		t.Fatal("the nonce must change on every response")
	}
}

// A code minted without a challenge works without the app's verifier, so the
// page never shows it, nor reflects it.
func TestCodePageNeverShowsAnUnboundCode(t *testing.T) {
	unbound := strings.TrimPrefix(testBoundCode, "pkce_")
	rec := serveCodePage(t, http.MethodGet, url.Values{"code": {unbound}, "state": {"s"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, unbound) || !strings.Contains(body, "did not protect its sign-in with a code challenge") {
		t.Fatalf("page reflected the unbound code or did not explain:\n%s", body)
	}
}

// Nothing the request carries is reflected when it is not a code to show.
func TestCodePageRefusesWhatIsNotACodeToShow(t *testing.T) {
	for name, query := range map[string]url.Values{
		"no code":            {"state": {"s"}},
		"empty state":        {"code": {testBoundCode}, "state": {""}},
		"state with a space": {"code": {testBoundCode}, "state": {"call us"}},
		"state with a hash":  {"code": {testBoundCode}, "state": {"a#b"}},
		"markup in state":    {"code": {testBoundCode}, "state": {"<b>x</b>"}},
		"oversized state":    {"code": {testBoundCode}, "state": {strings.Repeat("s", maxCodePageStateBytes+1)}},
		"markup as code":     {"code": {"<script>alert(1)</script>"}},
	} {
		t.Run(name, func(t *testing.T) {
			rec := serveCodePage(t, http.MethodGet, query)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", rec.Code)
			}
			body := rec.Body.String()
			if strings.Contains(body, testBoundCode) || strings.Contains(body, "<b>x</b>") || strings.Contains(body, "alert(1)") || strings.Contains(body, "call us") {
				t.Fatalf("page reflected the request:\n%s", body)
			}
		})
	}
}

// An error from the callback is shown as a fixed message; an unknown one reads
// as a refusal, and neither the value nor a code beside it is shown.
func TestCodePageExplainsARefusedSignIn(t *testing.T) {
	for code, want := range map[string]string{
		service.HostedOAuthErrorEmailNotVerified: "Your email address is not verified yet.",
		service.HostedOAuthErrorAccountDisabled:  "This account is disabled.",
		service.HostedOAuthErrorAccountLocked:    "There were too many attempts.",
		service.HostedOAuthErrorUnavailable:      "Sign-in is unavailable right now.",
		service.HostedOAuthErrorServer:           "Sign-in is unavailable right now.",
		service.HostedOAuthErrorAccessDenied:     "Sign-in was not allowed.",
		"call-555-0100-for-help":                 "Sign-in was not allowed.",
	} {
		rec := serveCodePage(t, http.MethodGet, url.Values{"error": {code}, "code": {testBoundCode}, "state": {"s"}})
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, "Sign-in did not finish") || !strings.Contains(body, want) {
			t.Errorf("error %q: status %d, want 200 with %q:\n%s", code, rec.Code, want, body)
		}
		if strings.Contains(body, testBoundCode) || strings.Contains(body, "555-0100") {
			t.Errorf("error %q: page shows a code or reflects the error value", code)
		}
	}
}

func TestCodePageRejectsOtherMethods(t *testing.T) {
	rec := serveCodePage(t, http.MethodPost, url.Values{"code": {testBoundCode}})
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("status %d, Allow %q; want 405 allowing GET", rec.Code, rec.Header().Get("Allow"))
	}
}

func TestSpokenDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		time.Minute:      "a minute",
		2 * time.Minute:  "2 minutes",
		45 * time.Second: "45 seconds",
		90 * time.Second: "90 seconds",
	} {
		if got := spokenDuration(d); got != want {
			t.Errorf("spokenDuration(%v) = %q, want %q", d, got, want)
		}
	}
}
