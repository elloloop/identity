package service

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/elloloop/identity/internal/origin"
)

// ReturnAllowlist is the fail-closed validator for an app return_to URL.
// It is built from GATEWAY_OAUTH_ALLOWED_RETURN_URLS — a comma-separated
// list of exact origins, path prefixes, or one-label wildcard origins
// (https://*.parent.example, optionally with a path prefix) — and shared by
// the hosted OAuth flow (where the HTTP handler checks return_to at
// /oauth/start) and the passwordless magic-link flow (where RequestMagicLink
// checks the requested return_to). A return_to must have the configured
// origin (or match the pattern) and, for path entries, match the configured
// path or one of its descendants.
//
// An empty allowlist disables both flows that depend on it: Enabled()
// reports false and Allows() rejects everything.
type ReturnAllowlist struct {
	entries  []string
	patterns []returnPattern
}

type returnPattern struct {
	raw    string
	origin origin.Pattern
	entry  *url.URL
}

// ParseReturnAllowlist splits the comma-separated config value into
// trimmed, non-empty entries. Whitespace-only entries are dropped. A
// wildcard entry that is not a valid one-label https pattern is an error, so
// a mistyped pattern fails startup instead of silently admitting nothing (or
// too much).
func ParseReturnAllowlist(csv string) (ReturnAllowlist, error) {
	var a ReturnAllowlist
	for _, part := range strings.Split(csv, ",") {
		e := strings.TrimSpace(part)
		if e == "" {
			continue
		}
		if !origin.IsPattern(e) {
			a.entries = append(a.entries, e)
			continue
		}
		p, err := parseReturnPattern(e)
		if err != nil {
			return ReturnAllowlist{}, fmt.Errorf("return URL pattern %q: %w", e, err)
		}
		a.patterns = append(a.patterns, p)
	}
	return a, nil
}

func parseReturnPattern(raw string) (returnPattern, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return returnPattern{}, err
	}
	if u.User != nil {
		return returnPattern{}, errors.New("userinfo not allowed")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return returnPattern{}, errors.New("query and fragment not allowed")
	}
	p, err := origin.ParsePattern(u)
	if err != nil {
		return returnPattern{}, err
	}
	return returnPattern{raw: raw, origin: p, entry: u}, nil
}

// Enabled reports whether any allowlist entry is configured.
func (a ReturnAllowlist) Enabled() bool { return len(a.entries) > 0 || len(a.patterns) > 0 }

// Entries returns the configured exact and path-prefix entries (for startup
// logging).
func (a ReturnAllowlist) Entries() []string { return a.entries }

// Patterns returns the configured wildcard entries (for startup logging).
func (a ReturnAllowlist) Patterns() []string {
	out := make([]string, len(a.patterns))
	for i, p := range a.patterns {
		out[i] = p.raw
	}
	return out
}

// Allows reports whether returnTo is permitted by an exact origin, a
// path-bound prefix, or a wildcard pattern (with its path prefix, if any).
// Allowlist entries may not contain a query or fragment.
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
	for _, p := range a.patterns {
		if p.origin.Matches(returnURL) && returnPathAllowed(p.entry, returnURL) {
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
		origin.EffectivePort(a) == origin.EffectivePort(b)
}

func returnPathAllowed(entry, returnTo *url.URL) bool {
	if entry.Path == "" || entry.Path == "/" {
		return true
	}
	prefix := strings.TrimSuffix(path.Clean(entry.Path), "/")
	returnPath := path.Clean(returnTo.Path)
	return returnPath == prefix || strings.HasPrefix(returnPath, prefix+"/")
}
