package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
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
	// Hostname, not Host: "https://:443" has a Host but no host to call.
	if u.Hostname() == "" {
		return nil, fmt.Errorf("url %q must be absolute (scheme and host)", shown)
	}
	// url.Parse checks a port is digits, not that it is one a socket can use.
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("url %q has an invalid port", shown)
		}
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
