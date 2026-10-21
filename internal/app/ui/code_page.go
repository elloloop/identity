package ui

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/elloloop/identity/internal/service"
)

// CodePagePath is the hosted page an app that cannot take the hosted
// callback's redirect (a CLI on another machine, a TV) names as return_to.
// The callback lands the browser here with ?code=, and the page shows the
// code for the person to copy into the app, which redeems it with its
// code_verifier. It is served only while the hosted flow is enabled, and an
// operator admits it like any return_to:
// GATEWAY_OAUTH_ALLOWED_RETURN_URLS=https://auth.example.com/auth/code.
const CodePagePath = "/auth/code"

// maxCodePageStateBytes bounds the app's state the page echoes beside the
// code: enough for any random state, too little to carry a message.
const maxCodePageStateBytes = 256

// codePageView is what the page template renders: a code to copy, or a
// heading and a message saying why there is none.
type codePageView struct {
	Nonce   string
	Title   string
	Message string
	Value   string
	TTL     string
}

var codePageTemplate = template.Must(template.New("code").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{.Title}}</title>
<style nonce="{{.Nonce}}">
:root { color-scheme: light dark; --bg: #f6f7f9; --card: #ffffff; --text: #16181d; --muted: #4a5160; --line: #d5d9e0; --accent: #1f5fd1; --accent-text: #ffffff; --warn-bg: #fff6e0; --warn-line: #e3b341; }
@media (prefers-color-scheme: dark) { :root { --bg: #111318; --card: #1b1e25; --text: #eef0f4; --muted: #b3b9c5; --line: #343944; --accent: #7aa7ff; --accent-text: #0b1020; --warn-bg: #2b2412; --warn-line: #b38a1f; } }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 16px; background: var(--bg); color: var(--text); font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { width: 100%; max-width: 34rem; background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 24px; }
h1 { font-size: 1.375rem; line-height: 1.3; margin: 0 0 12px; }
p { margin: 0 0 12px; color: var(--muted); }
.value { margin: 16px 0; padding: 12px; border: 1px solid var(--line); border-radius: 8px; color: var(--text); font: 0.9375rem/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; user-select: all; }
button { font: inherit; font-weight: 600; padding: 10px 18px; border: 0; border-radius: 8px; background: var(--accent); color: var(--accent-text); cursor: pointer; }
button:focus-visible { outline: 3px solid var(--text); outline-offset: 2px; }
.status { display: inline-block; margin-left: 12px; color: var(--text); }
.warning { margin-top: 20px; padding: 12px; border: 1px solid var(--warn-line); border-radius: 8px; background: var(--warn-bg); color: var(--text); }
</style>
</head>
<body>
<main>
<h1>{{.Title}}</h1>
{{if .Value}}<p>Paste it into the app you are signing in to, where it asks for the code.</p>
<p class="value" id="code">{{.Value}}</p>
<p><button type="button" id="copy" hidden>Copy code</button><span class="status" id="copy-status" role="status" aria-live="polite"></span></p>
<p class="warning"><strong>Only paste it into the app where you started signing in.</strong> If anyone else asks you for this code, do not give it to them: it would let them into your account.</p>
<p>It works once, within {{.TTL}}.</p>{{else}}<p>{{.Message}}</p>{{end}}
</main>
<script nonce="{{.Nonce}}">
(function () {
  history.replaceState(null, "", location.pathname);
  var button = document.getElementById("copy");
  if (!button || !navigator.clipboard) { return; }
  var value = document.getElementById("code").textContent;
  var status = document.getElementById("copy-status");
  button.hidden = false;
  button.addEventListener("click", function () {
    navigator.clipboard.writeText(value).then(function () {
      status.textContent = "Copied";
    }, function () {
      status.textContent = "Could not copy. Select the code and copy it.";
    });
  });
})();
</script>
</body>
</html>
`))

// CodePageHandler serves CodePagePath. It shows only a code minted for a
// sign-in the app bound to a PKCE challenge, so the code it shows is
// useless without that app's code_verifier; a code bound to none is never
// shown. The app's state, when it sent one, is shown after the code as
// code#state, so the app can tell a code from an earlier sign-in. The page
// echoes nothing else from the request: an error= the callback sent is
// shown as a fixed message, and anything malformed as a fixed explanation.
func CodePageHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		nonceBytes := make([]byte, 24)
		if _, err := rand.Read(nonceBytes); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		view, status := codePageFor(r)
		// The URL-safe alphabet, so html/template has nothing to escape
		// in the nonce attributes.
		view.Nonce = base64.RawURLEncoding.EncodeToString(nonceBytes)
		var body bytes.Buffer
		if err := codePageTemplate.Execute(&body, view); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+view.Nonce+"'; style-src 'nonce-"+view.Nonce+"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(body.Bytes())
	})
}

// codePageFor decides what the page says for r's query, and its status.
func codePageFor(r *http.Request) (codePageView, int) {
	q := r.URL.Query()
	if refusal := q.Get("error"); refusal != "" {
		return codePageView{Title: "Sign-in did not finish", Message: signInRefusalMessage(refusal)}, http.StatusOK
	}
	code, state := q.Get("code"), q.Get("state")
	if code == "" || q.Has("state") && !validCodePageState(state) {
		return codePageView{
			Title:   "There is no code to show",
			Message: "This page shows a sign-in code after you sign in from an app. Go back to the app and start signing in again.",
		}, http.StatusBadRequest
	}
	if !service.PKCEBoundOAuthCode(code) {
		return codePageView{
			Title:   "This code cannot be shown",
			Message: "The app that sent you here did not protect its sign-in with a code challenge, so its code is not shown. Go back to the app and start signing in again. If this keeps happening, tell the app's developer.",
		}, http.StatusBadRequest
	}
	value := code
	if state != "" {
		value += "#" + state
	}
	return codePageView{Title: "Copy this code", Value: value, TTL: spokenDuration(service.OAuthOneTimeCodeTTL)}, http.StatusOK
}

// signInRefusalMessage is the page's message for an error code the hosted
// callback sends; an unknown code reads as a refusal.
func signInRefusalMessage(code string) string {
	switch code {
	case service.HostedOAuthErrorEmailNotVerified:
		return "Your email address is not verified yet. Follow the verification link we sent you, then go back to the app and sign in again."
	case service.HostedOAuthErrorAccountDisabled:
		return "This account is disabled."
	case service.HostedOAuthErrorAccountLocked:
		return "There were too many attempts. Wait a while, then go back to the app and sign in again."
	case service.HostedOAuthErrorUnavailable, service.HostedOAuthErrorServer:
		return "Sign-in is unavailable right now. Go back to the app and try again in a moment."
	default:
		return "Sign-in was not allowed. Go back to the app to try again."
	}
}

// validCodePageState admits a state of RFC 3986 unreserved characters, the
// alphabet of every random state, so '#' can only be the separator.
func validCodePageState(state string) bool {
	if state == "" || len(state) > maxCodePageStateBytes {
		return false
	}
	for _, c := range []byte(state) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// spokenDuration says d as the page's sentence needs it: "a minute",
// "2 minutes", "45 seconds".
func spokenDuration(d time.Duration) string {
	if d%time.Minute != 0 {
		return strconv.Itoa(int(d/time.Second)) + " seconds"
	}
	if minutes := int(d / time.Minute); minutes != 1 {
		return strconv.Itoa(minutes) + " minutes"
	}
	return "a minute"
}
