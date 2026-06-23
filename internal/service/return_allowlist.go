package service

import (
	"net/url"
	"path"
	"strings"
)

// ReturnAllowlist is the fail-closed validator for an app return_to URL.
// It is built from GATEWAY_OAUTH_ALLOWED_RETURN_URLS — a comma-separated
// list of exact origins or path prefixes — and shared by the hosted OAuth
// flow (where the HTTP handler checks return_to at /oauth/start) and the
// passwordless magic-link flow (where RequestMagicLink checks the
// requested return_to). A return_to must have the configured origin and,
// for path entries, match the configured path or one of its descendants.
//
// An empty allowlist disables both flows that depend on it: Enabled()
// reports false and Allows() rejects everything.
type ReturnAllowlist struct {
	entries []string
}

// ParseReturnAllowlist splits the comma-separated config value into
// trimmed, non-empty entries. Whitespace-only entries are dropped.
func ParseReturnAllowlist(csv string) ReturnAllowlist {
	var entries []string
	for _, part := range strings.Split(csv, ",") {
		if e := strings.TrimSpace(part); e != "" {
			entries = append(entries, e)
		}
	}
	return ReturnAllowlist{entries: entries}
}

// Enabled reports whether any allowlist entry is configured.
func (a ReturnAllowlist) Enabled() bool { return len(a.entries) > 0 }

// Entries returns the configured allowlist entries (for startup logging).
func (a ReturnAllowlist) Entries() []string { return a.entries }

// Allows reports whether returnTo is permitted by an exact origin or a
// path-bound prefix. Allowlist entries may not contain a query or fragment.
func (a ReturnAllowlist) Allows(returnTo string) bool {
	returnURL, ok := parseReturnURL(returnTo)
	if !ok {
		return false
	}
	for _, e := range a.entries {
		entryURL, ok := parseReturnURL(e)
		if !ok || entryURL.RawQuery != "" || entryURL.Fragment != "" {
			continue
		}
		if sameReturnOrigin(entryURL, returnURL) && returnPathAllowed(entryURL, returnURL) {
			return true
		}
	}
	return false
}

func parseReturnURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Hostname() == "" {
		return nil, false
	}
	if !strings.EqualFold(u.Scheme, "https") && !strings.EqualFold(u.Scheme, "http") {
		return nil, false
	}
	return u, true
}

func sameReturnOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		returnPort(a) == returnPort(b)
}

func returnPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

func returnPathAllowed(entry, returnTo *url.URL) bool {
	if entry.Path == "" || entry.Path == "/" {
		return true
	}
	prefix := strings.TrimSuffix(path.Clean(entry.Path), "/")
	returnPath := path.Clean(returnTo.Path)
	return returnPath == prefix || strings.HasPrefix(returnPath, prefix+"/")
}
