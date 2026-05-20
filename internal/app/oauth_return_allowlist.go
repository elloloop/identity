package app

import "strings"

// returnAllowlist is the fail-closed validator for the hosted OAuth
// flow's return_to parameter. It is built from
// GATEWAY_OAUTH_ALLOWED_RETURN_URLS — a comma-separated list of exact
// origins or URL prefixes. A return_to is allowed when it equals an
// entry or begins with an entry; everything else is rejected.
//
// An empty allowlist disables the hosted flow: Enabled() reports false
// and the /oauth/start + /oauth/callback routes are not registered.
type returnAllowlist struct {
	entries []string
}

// parseReturnAllowlist splits the comma-separated config value into
// trimmed, non-empty entries. Whitespace-only entries are dropped.
func parseReturnAllowlist(csv string) returnAllowlist {
	var entries []string
	for _, part := range strings.Split(csv, ",") {
		if e := strings.TrimSpace(part); e != "" {
			entries = append(entries, e)
		}
	}
	return returnAllowlist{entries: entries}
}

// Enabled reports whether the hosted flow is configured.
func (a returnAllowlist) Enabled() bool { return len(a.entries) > 0 }

// Entries returns the configured allowlist entries (for startup logging).
func (a returnAllowlist) Entries() []string { return a.entries }

// Allows reports whether returnTo is permitted. A returnTo matches when
// it equals an allowlist entry or begins with one (prefix match), so a
// deployer can allow an entire app origin or pin a specific callback
// path. The match is exact-byte; no normalization is applied because a
// normalized-but-mismatched URL is exactly the open-redirect case the
// allowlist exists to close.
func (a returnAllowlist) Allows(returnTo string) bool {
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
