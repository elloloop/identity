package service

import "strings"

// ReturnAllowlist is the fail-closed validator for an app return_to URL.
// It is built from GATEWAY_OAUTH_ALLOWED_RETURN_URLS — a comma-separated
// list of exact origins or URL prefixes — and shared by the hosted OAuth
// flow (where the HTTP handler checks return_to at /oauth/start) and the
// passwordless magic-link flow (where RequestMagicLink checks the
// requested return_to). A return_to is allowed when it equals an entry or
// begins with one; everything else is rejected.
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

// Allows reports whether returnTo is permitted. A returnTo matches when
// it equals an allowlist entry or begins with one (prefix match), so a
// deployer can allow an entire app origin or pin a specific callback
// path. The match is exact-byte; no normalization is applied because a
// normalized-but-mismatched URL is exactly the open-redirect case the
// allowlist exists to close.
func (a ReturnAllowlist) Allows(returnTo string) bool {
	returnTo = strings.TrimSpace(returnTo)
	if returnTo == "" {
		return false
	}
	for _, e := range a.entries {
		if returnTo == e || strings.HasPrefix(returnTo, e) {
			return true
		}
	}
	return false
}
