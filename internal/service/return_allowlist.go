package service

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
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
// An allowlist with no usable entry disables both flows that depend on it:
// Enabled() reports false and Allows() rejects everything.
type ReturnAllowlist struct {
	entries []returnEntry
	ignored []string
}

// returnEntry is one usable allowlist entry, parsed once. pattern is nil for
// an exact origin or path-prefix entry.
type returnEntry struct {
	raw     string
	url     *url.URL
	pattern *origin.Pattern
}

func (e returnEntry) originMatches(u *url.URL) bool {
	if e.pattern != nil {
		return e.pattern.Matches(u)
	}
	return sameReturnOrigin(e.url, u)
}

// ParseReturnAllowlist splits the comma-separated config value into trimmed,
// non-empty entries. A wildcard entry must be a valid one-label https pattern
// (optionally with a path prefix, no query or fragment); one that is not is an
// error, so a mistyped pattern fails startup instead of admitting nothing or
// too much. A non-wildcard entry that is not an absolute http(s) URL without
// query or fragment admits nothing but is not an error: it is left out of the
// allowlist and reported by Ignored() so the caller can warn about it.
func ParseReturnAllowlist(csv string) (ReturnAllowlist, error) {
	var a ReturnAllowlist
	for _, part := range strings.Split(csv, ",") {
		raw := strings.TrimSpace(part)
		if raw == "" {
			continue
		}
		if origin.IsPattern(raw) {
			e, err := parseReturnPattern(raw)
			if err != nil {
				return ReturnAllowlist{}, fmt.Errorf("return URL pattern %q: %w", origin.Redact(raw), err)
			}
			a.entries = append(a.entries, e)
			continue
		}
		u, ok := parseReturnURL(raw)
		if !ok || u.RawQuery != "" || u.Fragment != "" {
			a.ignored = append(a.ignored, origin.Redact(raw))
			continue
		}
		a.entries = append(a.entries, returnEntry{raw: raw, url: u})
	}
	return a, nil
}

func parseReturnPattern(raw string) (returnEntry, error) {
	u, err := url.Parse(raw)
	if err != nil {
		// url.Parse's error quotes the whole input, credentials included.
		return returnEntry{}, errors.New("not a valid URL")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return returnEntry{}, errors.New("query and fragment not allowed")
	}
	p, err := origin.ParsePattern(u)
	if err != nil {
		return returnEntry{}, err
	}
	return returnEntry{raw: raw, url: u, pattern: &p}, nil
}

// Enabled reports whether any usable allowlist entry is configured.
func (a ReturnAllowlist) Enabled() bool { return len(a.entries) > 0 }

// Entries returns the usable exact and path-prefix entries as configured (for
// startup logging).
func (a ReturnAllowlist) Entries() []string {
	var out []string
	for _, e := range a.entries {
		if e.pattern == nil {
			out = append(out, e.raw)
		}
	}
	return out
}

// Patterns returns the wildcard entries in canonical form — the pattern as
// origin.Pattern.String renders it (the same form the CORS allow-list logs)
// followed by the entry's path prefix — for startup logging.
func (a ReturnAllowlist) Patterns() []string {
	var out []string
	for _, e := range a.entries {
		if e.pattern != nil {
			out = append(out, e.pattern.String()+e.url.EscapedPath())
		}
	}
	return out
}

// Ignored returns the malformed non-wildcard entries that admit nothing, with
// any credentials redacted (origin.Redact), for a startup warning.
func (a ReturnAllowlist) Ignored() []string { return slices.Clone(a.ignored) }

// Allows reports whether returnTo is permitted by an exact origin, a
// path-bound prefix, or a wildcard pattern (with its path prefix, if any).
func (a ReturnAllowlist) Allows(returnTo string) bool {
	returnURL, ok := parseReturnURL(returnTo)
	if !ok {
		return false
	}
	for _, e := range a.entries {
		if e.originMatches(returnURL) && returnPathAllowed(e.url, returnURL) {
			return true
		}
	}
	return false
}

// parseReturnURL parses an absolute http(s) URL without userinfo. A URL
// containing a backslash is refused outright: browsers treat "\" as "/" in an
// http(s) URL, so "/auth/..\x" would pass a "/auth" prefix check here and
// then be normalised by the browser to "/x". Control characters are refused by
// url.Parse, and "." / ".." segments (literal or percent-encoded) are resolved
// by path.Clean before the prefix check, as a browser resolves them.
func parseReturnURL(raw string) (*url.URL, bool) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, `\`) {
		return nil, false
	}
	u, err := url.Parse(raw)
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
