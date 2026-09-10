package ui

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
)

// pagePolicy describes what one hosted page is allowed to do, from which its
// Content-Security-Policy is derived. The default is nothing: no scripts, no
// frames, no third-party hosts; each page opts into exactly what it uses.
type pagePolicy struct {
	nonce string
	// scripts reports whether the page runs any script. The action pages
	// run none, so their policy admits none.
	scripts bool
	// captcha admits the Turnstile loader script and the widget's frame.
	captcha bool
	// formAction pins form submissions to this origin. It is left out on a
	// page whose successful POST redirects the browser to the app: Chrome
	// applies form-action to the redirect that follows a submission, which
	// would block the handover to return_to.
	formAction bool
}

func (p pagePolicy) contentSecurityPolicy() string {
	directives := []string{
		"default-src 'none'",
		"base-uri 'none'",
		"frame-ancestors 'none'",
		"img-src 'self' data:",
		"style-src 'nonce-" + p.nonce + "'",
		"connect-src 'self'",
	}
	if p.scripts {
		scriptSrc := "script-src 'nonce-" + p.nonce + "'"
		if p.captcha {
			scriptSrc += " " + turnstileOrigin
		}
		directives = append(directives, scriptSrc)
	}
	if p.captcha {
		directives = append(directives, "frame-src "+turnstileOrigin)
	}
	if p.formAction {
		directives = append(directives, "form-action 'self'")
	}
	return strings.Join(directives, "; ")
}

// newNonce returns a fresh CSP nonce for one response. The URL-safe base64
// alphabet is used because html/template entity-escapes '+', '/' and '='
// inside attribute values, which would make the nonce in the page differ
// from the one in the header; CSP admits '-' and '_' in a nonce.
func newNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// setSecurityHeaders applies the response headers every hosted response
// carries — rendered pages, redirects and error replies alike.
//
//   - no-store: the pages embed per-project options and, on the action
//     pages, a token-bound state, so no cache may serve them.
//   - no-referrer: an action page's URL carries the emailed token; it must
//     not reach the CAPTCHA, font or logo hosts as a Referer.
//   - frame-ancestors 'none' (and X-Frame-Options for older agents): a
//     Confirm button must not be clickjackable.
//   - noindex: nothing here is content for a crawler, and the action URLs
//     are secrets.
func setSecurityHeaders(h http.Header, p pagePolicy) {
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Content-Security-Policy", p.contentSecurityPolicy())
}
