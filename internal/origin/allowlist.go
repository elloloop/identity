package origin

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// ErrAllowedOriginsEmpty is returned by ParseAllowedOrigins and
// ValidateAllowedOrigins when the resolved list contains no origins.
var ErrAllowedOriginsEmpty = errors.New("cors: no allowed origins configured")

// Allowlist is a validated CORS allow-list: serialized origins matched
// exactly, plus wildcard patterns. The zero value allows nothing.
type Allowlist struct {
	exact    []string
	patterns []Pattern
}

// ParseAllowedOrigins splits a comma-separated origin list and validates each
// entry with ValidateAllowedOrigins.
func ParseAllowedOrigins(raw string, allowCredentials bool) (Allowlist, error) {
	if strings.TrimSpace(raw) == "" {
		return Allowlist{}, ErrAllowedOriginsEmpty
	}
	return ValidateAllowedOrigins(strings.Split(raw, ","), allowCredentials)
}

// ValidateAllowedOrigins validates a list of origins: each entry is a bare
// lower-case-scheme http(s) origin, or a one-label wildcard pattern (see
// ParsePattern). When allowCredentials is true it also refuses the bare
// wildcard "*", the literal "null" and empty entries: the CORS middleware
// always sets Access-Control-Allow-Credentials, so any of those would expose
// authenticated state to arbitrary origins. Exact entries keep their input
// order and case; patterns are canonicalized (lower case, default port
// dropped). An all-empty input is ErrAllowedOriginsEmpty.
func ValidateAllowedOrigins(origins []string, allowCredentials bool) (Allowlist, error) {
	var a Allowlist
	for _, entry := range origins {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			if allowCredentials {
				return Allowlist{}, errors.New("cors: empty origin entry not allowed with credentials")
			}
			continue
		}
		if allowCredentials {
			if entry == wildcardChar {
				return Allowlist{}, errors.New(`cors: wildcard "*" origin not allowed with credentials`)
			}
			if entry == "null" {
				return Allowlist{}, errors.New(`cors: literal "null" origin not allowed with credentials`)
			}
		}
		u, err := parseBareOrigin(entry)
		if err != nil {
			return Allowlist{}, fmt.Errorf("cors: origin %q invalid: %w", entry, err)
		}
		if !IsPattern(entry) {
			a.exact = append(a.exact, entry)
			continue
		}
		p, err := ParsePattern(u)
		if err != nil {
			return Allowlist{}, fmt.Errorf("cors: origin %q invalid: %w", entry, err)
		}
		a.patterns = append(a.patterns, p)
	}
	if len(a.exact) == 0 && len(a.patterns) == 0 {
		return Allowlist{}, ErrAllowedOriginsEmpty
	}
	return a, nil
}

func parseBareOrigin(s string) (*url.URL, error) {
	if strings.ContainsAny(s, " \t\r\n") {
		return nil, errors.New("contains whitespace")
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return nil, errors.New("scheme must be lower-case http:// or https://")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, errors.New("host is empty")
	}
	if u.Path != "" {
		return nil, errors.New("path not allowed")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return nil, errors.New("query not allowed")
	}
	if u.Fragment != "" {
		return nil, errors.New("fragment not allowed")
	}
	if u.User != nil {
		return nil, errors.New("userinfo not allowed")
	}
	return u, nil
}

// Exact returns a copy of the exact origins in configured order.
func (a Allowlist) Exact() []string { return slices.Clone(a.exact) }

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
// pattern admits only a value in serialized-origin form, scheme://host[:port]
// with nothing before or after it.
func (a Allowlist) Allows(origin string) bool {
	if slices.Contains(a.exact, origin) {
		return true
	}
	if len(a.patterns) == 0 {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme+"://"+u.Host != origin {
		return false
	}
	host, port := strings.ToLower(u.Hostname()), EffectivePort(u)
	for _, p := range a.patterns {
		if p.matches(u.Scheme, host, port) {
			return true
		}
	}
	return false
}
