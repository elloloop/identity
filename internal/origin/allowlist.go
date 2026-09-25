package origin

import (
	"net/url"
	"slices"
)

// Allowlist is a validated set of browser origins: serialized origins matched
// exactly, plus wildcard patterns. The zero value allows nothing.
type Allowlist struct {
	exact    []string
	patterns []Pattern
}

// NewAllowlist builds an Allowlist from already-validated entries.
func NewAllowlist(exact []string, patterns []Pattern) Allowlist {
	return Allowlist{exact: exact, patterns: patterns}
}

// Exact returns the exact origins in configured order.
func (a Allowlist) Exact() []string { return a.exact }

// Patterns returns the wildcard patterns, in canonical form, in configured order.
func (a Allowlist) Patterns() []string {
	out := make([]string, len(a.patterns))
	for i, p := range a.patterns {
		out[i] = p.String()
	}
	return out
}

// Allows reports whether origin, an Origin request header, is admitted. An
// exact entry must match byte for byte (the serialized-origin comparison); a
// pattern admits only a bare serialized origin, never one with a path, query,
// fragment or userinfo.
func (a Allowlist) Allows(origin string) bool {
	if slices.Contains(a.exact, origin) {
		return true
	}
	if len(a.patterns) == 0 {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Opaque != "" || u.User != nil || u.Path != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return false
	}
	for _, p := range a.patterns {
		if p.Matches(u) {
			return true
		}
	}
	return false
}
