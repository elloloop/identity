package ui

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// consoleCSPNonce captures the nonce the console's policy admits scripts by.
var consoleCSPNonce = regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9_-]+)'`)

// absoluteWebURL matches an http(s) URL anywhere in the page, up to whatever
// ends it in markup, a style or a script string.
var absoluteWebURL = regexp.MustCompile(`(?i)https?://[^\s"'<>\\)]*`)

// consoleExampleDomain is the reserved domain the page's help text may name:
// it resolves nowhere, so a URL under it loads nothing.
const consoleExampleDomain = "example.com"

// consoleRPCService is the service every call the page makes belongs to.
const consoleRPCService = "identity.v1.IdentityService/"

func serveConsole(t *testing.T, opts ConsoleOptions, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	ConsoleHandler(opts).ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// consoleMarkup is the served page taken apart: every tag it opens, and the
// text of its style and script.
type consoleMarkup struct {
	tags   []html.Token
	style  string
	script string
}

func parseConsole(t *testing.T, body string) consoleMarkup {
	t.Helper()
	var page consoleMarkup
	tokens := html.NewTokenizer(strings.NewReader(body))
	element := ""
	for {
		switch tokens.Next() {
		case html.ErrorToken:
			if !errors.Is(tokens.Err(), io.EOF) {
				t.Fatalf("the page does not parse: %v", tokens.Err())
			}
			return page
		case html.StartTagToken, html.SelfClosingTagToken:
			tag := tokens.Token()
			page.tags = append(page.tags, tag)
			element = tag.Data
		case html.EndTagToken:
			element = ""
		case html.TextToken:
			switch element {
			case "style":
				page.style += string(tokens.Text())
			case "script":
				page.script += string(tokens.Text())
			}
		}
	}
}

func attribute(tag html.Token, name string) (string, bool) {
	for _, attr := range tag.Attr {
		if attr.Key == name {
			return attr.Val, true
		}
	}
	return "", false
}

func servedConsole(t *testing.T) consoleMarkup {
	t.Helper()
	rec := serveConsole(t, ConsoleOptions{}, http.MethodGet, ConsolePath)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	return parseConsole(t, rec.Body.String())
}

// The page signs a person in and holds their tokens, so every answer carries
// its protections and a policy that admits nothing but the page's own style
// and script.
func TestConsoleServesThePageWithItsProtections(t *testing.T) {
	rec := serveConsole(t, ConsoleOptions{}, http.MethodGet, ConsolePath)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	h := rec.Header()
	for name, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Content-Type":           "text/html; charset=utf-8",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"X-Frame-Options":        "DENY",
	} {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	csp := h.Get("Content-Security-Policy")
	nonce := consoleCSPNonce.FindStringSubmatch(csp)
	if nonce == nil {
		t.Fatalf("the policy admits scripts by no nonce: %q", csp)
	}
	want := "default-src 'none'; script-src 'nonce-" + nonce[1] + "'; style-src 'nonce-" + nonce[1] + "'; " +
		"connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	if csp != want {
		t.Errorf("Content-Security-Policy = %q, want %q", csp, want)
	}
	if !strings.HasPrefix(rec.Body.String(), "<!doctype html>") {
		t.Errorf("the body is not the page: %.60q", rec.Body.String())
	}
}

// The page has one style and one script, and each runs only under the nonce
// its own response's policy names. A nonce that repeated would admit a
// script injected into a later response.
func TestConsoleNonceIsPerResponseAndOnThePagesOwnStyleAndScript(t *testing.T) {
	seen := map[string]bool{}
	for range 3 {
		rec := serveConsole(t, ConsoleOptions{}, http.MethodGet, ConsolePath)
		match := consoleCSPNonce.FindStringSubmatch(rec.Header().Get("Content-Security-Policy"))
		if match == nil {
			t.Fatalf("no nonce in the policy: %q", rec.Header().Get("Content-Security-Policy"))
		}
		nonce := match[1]
		if len(nonce) < 32 {
			t.Errorf("nonce %q is too short to be unguessable", nonce)
		}
		if seen[nonce] {
			t.Fatalf("nonce %q was served twice", nonce)
		}
		seen[nonce] = true

		count := map[string]int{}
		for _, tag := range parseConsole(t, rec.Body.String()).tags {
			if tag.Data != "style" && tag.Data != "script" {
				if _, has := attribute(tag, "nonce"); has {
					t.Errorf("<%s> carries a nonce", tag.Data)
				}
				continue
			}
			count[tag.Data]++
			if got, _ := attribute(tag, "nonce"); got != nonce {
				t.Errorf("<%s> nonce = %q, want the policy's %q", tag.Data, got, nonce)
			}
		}
		if count["style"] != 1 || count["script"] != 1 {
			t.Errorf("the page has %d style and %d script elements, want one of each", count["style"], count["script"])
		}
	}
}

// The options reach the script as one JSON object, whatever they hold.
func TestConsoleTellsThePageTheServersOptions(t *testing.T) {
	for _, tc := range []struct {
		opts ConsoleOptions
		want string
	}{
		{ConsoleOptions{}, `{"selfServiceProjects":false,"settingsApplyWithinSeconds":0}`},
		{ConsoleOptions{SelfServiceProjects: true}, `{"selfServiceProjects":true,"settingsApplyWithinSeconds":0}`},
		{ConsoleOptions{SettingsApplyWithinSeconds: 30}, `{"selfServiceProjects":false,"settingsApplyWithinSeconds":30}`},
		{ConsoleOptions{SelfServiceProjects: true, SettingsApplyWithinSeconds: 300}, `{"selfServiceProjects":true,"settingsApplyWithinSeconds":300}`},
	} {
		script := parseConsole(t, serveConsole(t, tc.opts, http.MethodGet, ConsolePath).Body.String()).script
		if got := strings.Count(script, "const serverOptions = "+tc.want+";"); got != 1 {
			t.Errorf("options %+v: the script is given %s %d times, want once", tc.opts, tc.want, got)
		}
	}
}

// An option the page is given and never reads tells the person nothing: the
// script decides what to offer and what to say from each of them.
func TestConsoleScriptReadsEveryOption(t *testing.T) {
	script := servedConsole(t).script
	for _, option := range []string{"selfServiceProjects", "settingsApplyWithinSeconds"} {
		if !strings.Contains(script, "serverOptions."+option) {
			t.Errorf("the script never reads the %s option", option)
		}
	}
}

// A HEAD is the GET without its body.
func TestConsoleAnswersHead(t *testing.T) {
	rec := serveConsole(t, ConsoleOptions{}, http.MethodHead, ConsolePath)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("status %d with a %d-byte body, want 200 and none", rec.Code, rec.Body.Len())
	}
	h := rec.Header()
	if h.Get("Content-Length") == "" || h.Get("Content-Length") == "0" || h.Get("Cache-Control") != "no-store" ||
		!strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("a HEAD lacks the page's headers: %v", h)
	}
}

// The page calls the API by addresses relative to ConsolePath, so it is
// served there alone: under any other path those addresses would point
// somewhere else.
func TestConsoleServesNothingUnderItsPath(t *testing.T) {
	for _, path := range []string{
		ConsolePath + "index.html",
		ConsolePath + "projects",
		ConsolePath + "assets/app.js",
		ConsolePath + "/",
		strings.TrimSuffix(ConsolePath, "/"),
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
			rec := serveConsole(t, ConsoleOptions{}, method, path)
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s %s: status %d, want 404", method, path, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "<script") {
				t.Errorf("%s %s: the 404 carries the page", method, path)
			}
		}
	}
}

func TestConsoleRejectsOtherMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rec := serveConsole(t, ConsoleOptions{}, method, ConsolePath)
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: status %d, Allow %q; want 405 allowing GET, HEAD", method, rec.Code, rec.Header().Get("Allow"))
		}
		if strings.Contains(rec.Body.String(), "<script") {
			t.Errorf("%s: the 405 carries the page", method)
		}
	}
}

// The policy admits no outside source, so anything the page tried to load
// from one would fail in the browser without a word. The page is one
// document: no element fetches anything, every link stays under the server's
// own prefix, and the only web addresses in it are examples in help text.
func TestConsolePageLoadsNothingFromElsewhere(t *testing.T) {
	page := servedConsole(t)
	fetching := map[string]bool{
		"link": true, "img": true, "iframe": true, "frame": true, "object": true, "embed": true,
		"base": true, "audio": true, "video": true, "source": true, "track": true, "picture": true,
	}
	addressed := []string{"href", "src", "srcset", "action", "formaction", "poster", "data", "ping", "manifest", "xlink:href"}
	for _, tag := range page.tags {
		if fetching[tag.Data] {
			t.Errorf("<%s> loads a resource of its own", tag.Data)
		}
		for _, name := range addressed {
			ref, has := attribute(tag, name)
			if has && !strings.HasPrefix(ref, "#") && !strings.HasPrefix(ref, "../") {
				t.Errorf("<%s %s=%q> does not stay relative to the page", tag.Data, name, ref)
			}
		}
	}
	for _, at := range []string{"@import", "url("} {
		if strings.Contains(page.style, at) {
			t.Errorf("the style uses %s", at)
		}
	}

	body := serveConsole(t, ConsoleOptions{}, http.MethodGet, ConsolePath).Body.String()
	for _, found := range absoluteWebURL.FindAllString(body, -1) {
		// Help text ends a sentence on some of them.
		found = strings.TrimRight(found, ".,")
		parsed, err := url.Parse(found)
		if err != nil {
			t.Errorf("the page names %q, which is no URL: %v", found, err)
			continue
		}
		host := strings.TrimPrefix(parsed.Hostname(), "*.")
		if host != consoleExampleDomain && !strings.HasSuffix(host, "."+consoleExampleDomain) {
			t.Errorf("the page names the absolute URL %q", found)
		}
	}
}

// The policy has no 'unsafe-inline', so an inline event handler would never
// run and a style attribute would never apply.
func TestConsolePageHasNoInlineHandlersOrStyles(t *testing.T) {
	page := servedConsole(t)
	for _, tag := range page.tags {
		for _, attr := range tag.Attr {
			if strings.HasPrefix(attr.Key, "on") {
				t.Errorf("<%s> has the inline event handler %s", tag.Data, attr.Key)
			}
			if attr.Key == "style" {
				t.Errorf("<%s> has a style attribute", tag.Data)
			}
		}
		if _, has := attribute(tag, "src"); has && tag.Data == "script" {
			t.Error("the script is loaded by address instead of being inline")
		}
	}
	// The script builds the rest of the page; it must not do so from markup
	// text, which is how a handler or a server's string would get in.
	for _, sink := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"} {
		if strings.Contains(page.script, sink) {
			t.Errorf("the script uses %s", sink)
		}
	}
}

// The page must work when the whole server is published under a path prefix,
// so it reaches the API, and the sign-up page, relative to itself.
func TestConsolePageCallsTheAPIRelativeToItself(t *testing.T) {
	page := servedConsole(t)
	calls := 0
	for rest := page.script; ; {
		at := strings.Index(rest, consoleRPCService)
		if at < 0 {
			break
		}
		calls++
		if !strings.HasSuffix(rest[:at], "'../") {
			t.Errorf("the script names the API by an address that is not relative to the page: %.40q", rest[max(0, at-20):])
		}
		rest = rest[at+len(consoleRPCService):]
	}
	if calls == 0 {
		t.Fatal("the script names no API address")
	}
	for _, quoted := range []string{`'/`, `"/`} {
		if strings.Contains(page.script, "fetch("+quoted) {
			t.Errorf("the script fetches an address that starts at the server's root")
		}
	}
	signUp := false
	for _, tag := range page.tags {
		if ref, _ := attribute(tag, "href"); tag.Data == "a" && ref == "../auth/" {
			signUp = true
		}
	}
	if !signUp {
		t.Error("the page does not link to ../auth/ for creating an account")
	}
}

// Tokens live in the page's memory alone: nothing the script can reach
// outlives the page or is readable by another one.
func TestConsoleScriptKeepsTokensOutOfStorage(t *testing.T) {
	script := servedConsole(t).script
	for _, store := range []string{"localStorage", "sessionStorage", "indexedDB", "document.cookie"} {
		if strings.Contains(script, store) {
			t.Errorf("the script uses %s", store)
		}
	}
}
