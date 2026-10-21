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

const (
	testBoundCode = "pkce_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testState     = "8436cfbd3cf94948"
)

// testCodePageHost is the host the page's requests reach, behind a proxy
// that terminates TLS.
const testCodePageHost = "auth.example.test"

func serveCodePage(t *testing.T, method string, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return serveCodePageNamedBy(t, "https://"+testCodePageHost+CodePagePath, method, query, testCodePageHost)
}

// serveCodePageNamedBy serves the page under an allowlist of entries to a
// request that reached host, as the proxy in front reports it.
func serveCodePageNamedBy(t *testing.T, entries, method string, query url.Values, host string) *httptest.ResponseRecorder {
	t.Helper()
	allow, err := service.ParseReturnAllowlist(entries)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, CodePagePath+"?"+query.Encode(), nil)
	req.Host = "backend.internal.test"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", host)
	rec := httptest.NewRecorder()
	CodePageHandler(allow).ServeHTTP(rec, req)
	return rec
}

// The page is opt-in by name, host by host: it shows a code only where an
// allowlist entry names it exactly. Anywhere else it answers a fixed 404 that
// shows nothing from the request, with the same protections.
func TestCodePageShowsACodeOnlyWhereItIsNamedExactly(t *testing.T) {
	page := "https://" + testCodePageHost + CodePagePath
	for _, tc := range []struct {
		name, entries, host string
		want                int
	}{
		{name: "named exactly", entries: page, host: testCodePageHost, want: http.StatusOK},
		{name: "named with its default port", entries: "https://" + testCodePageHost + ":443" + CodePagePath, host: testCodePageHost, want: http.StatusOK},
		{name: "reached with its default port", entries: page, host: testCodePageHost + ":443", want: http.StatusOK},
		{name: "named among others", entries: "https://app.example.test," + page, host: testCodePageHost, want: http.StatusOK},
		{name: "covered by an origin entry", entries: "https://" + testCodePageHost, host: testCodePageHost, want: http.StatusNotFound},
		{name: "covered by a prefix entry", entries: "https://" + testCodePageHost + "/auth", host: testCodePageHost, want: http.StatusNotFound},
		{name: "covered by a wildcard entry", entries: "https://*.example.test", host: testCodePageHost, want: http.StatusNotFound},
		{name: "named on another host", entries: "https://other.example.test" + CodePagePath, host: testCodePageHost, want: http.StatusNotFound},
		{name: "named on another port", entries: "https://" + testCodePageHost + ":8443" + CodePagePath, host: testCodePageHost, want: http.StatusNotFound},
		{name: "named for plain http", entries: "http://" + testCodePageHost + CodePagePath, host: testCodePageHost, want: http.StatusNotFound},
		{name: "a forwarded host list", entries: page, host: testCodePageHost + ", other.example.test", want: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveCodePageNamedBy(t, tc.entries, http.MethodGet, url.Values{"code": {testBoundCode}, "state": {testState}}, tc.host)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d", rec.Code, tc.want)
			}
			body := rec.Body.String()
			if shown := strings.Contains(body, testBoundCode); shown != (tc.want == http.StatusOK) {
				t.Fatalf("code shown = %v, want %v:\n%s", shown, tc.want == http.StatusOK, body)
			}
			if tc.want == http.StatusNotFound && (strings.Contains(body, testState) || !strings.Contains(body, "This page is not available")) {
				t.Fatalf("the 404 reflected the request or did not explain:\n%s", body)
			}
			if rec.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
				t.Fatalf("the answer lacks the page's protections: %v", rec.Header())
			}
		})
	}
}

// The page shows a bound code with the app's state as code#state, and a copy
// button the script reveals.
func TestCodePageShowsABoundCodeWithTheAppsState(t *testing.T) {
	rec := serveCodePage(t, http.MethodGet, url.Values{"code": {testBoundCode}, "state": {testState}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `<p class="value" id="code">`+testBoundCode+"#"+testState+`</p>`) {
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
		{"code": {testBoundCode}, "state": {testState}},
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
	rec := serveCodePage(t, http.MethodGet, url.Values{"code": {unbound}, "state": {testState}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, unbound) || !strings.Contains(body, "did not protect its sign-in with a code challenge") {
		t.Fatalf("page reflected the unbound code or did not explain:\n%s", body)
	}
}

// Nothing the request carries is reflected when there is no code to show.
func TestCodePageWithoutACode(t *testing.T) {
	for name, query := range map[string]url.Values{
		"nothing":        {},
		"only a state":   {"state": {testState}},
		"markup as code": {"code": {"<script>alert(1)</script>"}},
	} {
		t.Run(name, func(t *testing.T) {
			rec := serveCodePage(t, http.MethodGet, query)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", rec.Code)
			}
			body := rec.Body.String()
			if strings.Contains(body, testState) || strings.Contains(body, "alert(1)") || (!strings.Contains(body, "There is no code to show") && !strings.Contains(body, "This code cannot be shown")) {
				t.Fatalf("page reflected the request or did not explain:\n%s", body)
			}
		})
	}
}

// The page is on this server's origin and anyone can choose the state in a
// link to it, so a state that could carry words is never shown, and neither
// is the code beside it: the page says the sign-in cannot be shown.
func TestCodePageRefusesAStateThatCouldCarryAMessage(t *testing.T) {
	for name, state := range map[string]string{
		"a sentence in hyphens":  "Call-555-0100-to-unlock-your-account",
		"a domain":               "paste-this-code-at.support.example.net",
		"a phone number":         "555.0100.555.0100",
		"a space":                "call us",
		"a hash":                 "8436cfbd#3cf94948",
		"markup":                 "<b>x</b>",
		"uppercase hex":          "8436CFBD3CF94948",
		"empty":                  "",
		"shorter than the floor": strings.Repeat("a", CodePageStateMinLen-1),
		"longer than the cap":    strings.Repeat("a", CodePageStateMaxLen+1),
	} {
		t.Run(name, func(t *testing.T) {
			rec := serveCodePage(t, http.MethodGet, url.Values{"code": {testBoundCode}, "state": {state}})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, "This code cannot be shown") || !strings.Contains(body, "started its sign-in in a form this page cannot show") {
				t.Fatalf("page does not explain the refusal:\n%s", body)
			}
			if strings.Contains(body, testBoundCode) || (state != "" && strings.Contains(body, state)) || strings.Contains(body, "555") || strings.Contains(body, "example.net") || strings.Contains(body, "<b>x</b>") {
				t.Fatalf("page reflected the request:\n%s", body)
			}
		})
	}
}

func TestValidCodePageState(t *testing.T) {
	for state, want := range map[string]bool{
		testState:                                  true,
		strings.Repeat("0", CodePageStateMinLen):   true,
		strings.Repeat("f", CodePageStateMaxLen):   true,
		"0123456789abcdef0123456789abcdef":         true,
		strings.Repeat("0", CodePageStateMinLen-1): false,
		strings.Repeat("f", CodePageStateMaxLen+1): false,
		"8436cfbd3cf9494g":                         false,
		"8436CFBD3CF94948":                         false,
		"8436cfbd-3cf94948":                        false,
		"":                                         false,
	} {
		if got := ValidCodePageState(state); got != want {
			t.Errorf("ValidCodePageState(%q) = %v, want %v", state, got, want)
		}
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
		rec := serveCodePage(t, http.MethodGet, url.Values{"error": {code}, "code": {testBoundCode}, "state": {testState}})
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
