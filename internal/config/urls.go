package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/elloloop/identity/internal/origin"
)

// parseHTTPSOrLoopbackURL parses an absolute HTTPS URL. Plain HTTP is accepted
// only when the host is loopback — the localhost-dev convention for every URL
// the server calls or hands to users (webhook endpoints, email link bases).
// Errors never echo credentials the URL carries (origin.Redact); url.Parse's
// own error is not wrapped because it quotes the whole input.
func parseHTTPSOrLoopbackURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("url must not be empty")
	}
	shown := origin.Redact(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("url %q is not a valid URL", shown)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("url %q must be absolute (scheme and host)", shown)
	}
	// "https://:443" has a Host but no host name to call.
	if u.Hostname() == "" {
		return nil, fmt.Errorf("url %q has no host name", shown)
	}
	// url.Parse checks a port is digits, not that it is one a socket can use.
	if p := u.Port(); p != "" && !origin.ValidPort(p) {
		return nil, fmt.Errorf("url %q port must be a number from 1 to 65535", shown)
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return u, nil
		}
		return nil, fmt.Errorf("url %q must use https (http is accepted only for a loopback host)", shown)
	default:
		return nil, fmt.Errorf("url %q must use https", shown)
	}
}

// ValidateEmailedLinkURL checks raw, a URL that emailed links are built on,
// wherever it is configured: it must be an absolute https URL (http only for
// a loopback host), and carry no userinfo, query or fragment, since the link
// appends its own path or "?token=…" to it, nor any character
// mustBePercentEncoded names. Empty is valid. The error never echoes a
// password the URL carries.
func ValidateEmailedLinkURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := parseHTTPSOrLoopbackURL(raw)
	if err != nil {
		return err
	}
	// url.Parse records a bare trailing "?" (ForceQuery) but drops a bare
	// trailing "#", which would still put the page and token in the fragment.
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return fmt.Errorf("url %q must not carry userinfo, a query or a fragment", origin.Redact(raw))
	}
	// The link is the value as written plus "?token=…", so a space, a quote
	// or another character a URL must percent-encode would break it or end it
	// early in a mail client.
	if strings.ContainsFunc(raw, mustBePercentEncoded) {
		return fmt.Errorf("url %q must percent-encode spaces, quotes and other characters a URL cannot carry as they are",
			origin.Redact(raw))
	}
	return nil
}

// mustBePercentEncoded reports whether r is an ASCII character a URL may
// carry only percent-encoded (RFC 3986 §2): a control character, a space, or
// one of " < > \ ^ ` { | }. url.Parse already refuses the control
// characters; they are kept so the predicate states the whole rule. Non-ASCII
// is left alone, since an internationalized host name is written that way
// and mail clients link it.
func mustBePercentEncoded(r rune) bool {
	return r <= ' ' || r == 0x7f || strings.ContainsRune("\"<>\\^`{|}", r)
}

// isLoopbackHost reports whether host is a loopback name or address
// (localhost, 127.0.0.0/8, or ::1) — the only case a plaintext URL is
// accepted.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
