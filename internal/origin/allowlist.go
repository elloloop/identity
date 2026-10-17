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
// lower-case-scheme http(s) origin, a one-label wildcard pattern (see
// ParsePattern), or an exact origin on an application's own scheme (see
// parseBareOrigin). When allowCredentials is true it also refuses the bare
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
			if entry == wildcard {
				return Allowlist{}, errors.New(`cors: wildcard "*" origin not allowed with credentials`)
			}
			if entry == "null" {
				return Allowlist{}, errors.New(`cors: literal "null" origin not allowed with credentials`)
			}
		}
		u, err := parseBareOrigin(entry)
		if err != nil {
			return Allowlist{}, fmt.Errorf("cors: origin %q invalid: %w", Redact(entry), err)
		}
		if !IsPattern(entry) {
			a.exact = append(a.exact, entry)
			continue
		}
		p, err := ParsePattern(u)
		if err != nil {
			return Allowlist{}, fmt.Errorf("cors: origin %q invalid: %w", Redact(entry), err)
		}
		a.patterns = append(a.patterns, p)
	}
	if len(a.exact) == 0 && len(a.patterns) == 0 {
		return Allowlist{}, ErrAllowedOriginsEmpty
	}
	return a, nil
}

// parseBareOrigin parses an entry that must be a serialized origin,
// scheme://host, with a lower-case scheme and nothing after the host. An http
// or https entry takes any host and port url.Parse accepts. Any other scheme
// is an application's own: a desktop or mobile shell that registers it as a
// standard scheme for the pages it serves, so its browser engine sends their
// origin as scheme://host. Such an entry takes only the form that engine
// sends unchanged: a DNS name of lower-case labels, with no port.
func parseBareOrigin(s string) (*url.URL, error) {
	if strings.ContainsAny(s, " \t\r\n") {
		return nil, errors.New("contains whitespace")
	}
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok || !validScheme(scheme) {
		return nil, errors.New("must be scheme://host with a lower-case scheme, such as https://app.example.com")
	}
	if slices.Contains(refusedSchemes, scheme) {
		return nil, fmt.Errorf("scheme %s: never names the origin of a page that makes requests", scheme)
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, errInvalidURL
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
		return nil, errFragment
	}
	if u.User != nil {
		return nil, errors.New("userinfo not allowed")
	}
	if !isWebScheme(scheme) {
		// The rules below read the entry's own text after "://", not u.Host
		// or u.Fragment: url.Parse keeps no trace of an empty fragment, and
		// an entry carrying any "#" or port is not the origin an engine sends.
		if strings.Contains(rest, "#") {
			return nil, errFragment
		}
		if err := checkAppHost(rest); err != nil {
			return nil, err
		}
	}
	return u, nil
}

var errFragment = errors.New("fragment not allowed")

// isWebScheme reports whether scheme is http or https, the schemes whose
// entries keep the rules they had before application schemes were accepted.
func isWebScheme(scheme string) bool {
	return scheme == httpScheme || scheme == httpsScheme
}

// refusedSchemes are the schemes besides http and https that the URL, Fetch
// and HTML standards give a meaning of their own, so none is an application's
// own: about:, data: and javascript: pages have an opaque origin (sent as
// "null"), blob: and filesystem: URLs take the origin of the URL inside them,
// file: is shared by every local file, ws: and wss: name sockets, not pages,
// and browsers no longer load ftp: pages.
var refusedSchemes = []string{"about", "blob", "data", "file", "filesystem", "ftp", "javascript", "ws", "wss"}

var (
	errAppOriginHost = errors.New("an origin on an application's own scheme is exact: its host is a DNS name of lower-case labels (letters, digits, hyphens, dots), with no port or wildcard")
	// A browser engine parses a host that ends in a number as an IPv4
	// address and sends it rewritten (app://1 as app://0.0.0.1), so an entry
	// spelled that way would never match.
	errAppOriginNumericHost = errors.New("an origin on an application's own scheme takes a DNS name, not an IP address: its last label is not a number")
)

// validScheme reports whether s is an RFC 3986 scheme in lower case, the form
// a browser serializes: a letter, then letters, digits, "+", "-" or ".".
func validScheme(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// checkAppHost accepts host when it is one or more dot-separated lower-case
// DNS labels whose last label does not end in a number in the URL standard's
// sense (decimal digits, or 0x and hex digits).
func checkAppHost(host string) error {
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if !validLabel(l) {
			return errAppOriginHost
		}
	}
	if last := labels[len(labels)-1]; isNumeric(last) || isHexNumber(last) {
		return errAppOriginNumericHost
	}
	return nil
}

// isHexNumber reports whether l is "0x" followed by zero or more hex digits,
// which the URL standard's host parser reads as a number.
func isHexNumber(l string) bool {
	digits, ok := strings.CutPrefix(l, "0x")
	return ok && strings.Trim(digits, "0123456789abcdef") == ""
}

// errInvalidURL replaces url.Parse's error, which quotes the whole input and so
// would carry any credentials in it into logs.
var errInvalidURL = errors.New("not a valid URL")

// Redact renders a configured allowlist entry for a log line or an error
// message without any credentials it carries: userinfo is replaced wholesale
// (neither the user nor the password appears), and any other entry that
// contains "@" — where a credential could hide in a shape url.Parse does not
// read as userinfo — is not echoed at all.
func Redact(entry string) string {
	if u, err := url.Parse(entry); err == nil && u.User != nil {
		masked := *u
		masked.User = url.User(redactedUserinfo)
		return masked.String()
	}
	if strings.Contains(entry, "@") {
		return redactedEntry
	}
	return entry
}

const (
	redactedUserinfo = "REDACTED"
	redactedEntry    = "[entry withheld: may contain credentials]"
)

// Exact returns a copy of the exact origins in configured order.
func (a Allowlist) Exact() []string { return slices.Clone(a.exact) }

// AppSchemeOrigins returns the exact origins on an application's own scheme,
// in configured order. A mistyped http(s) scheme is one of them, so listing
// them apart is what lets an operator see one.
func (a Allowlist) AppSchemeOrigins() []string {
	var out []string
	for _, e := range a.exact {
		if scheme, _, _ := strings.Cut(e, "://"); !isWebScheme(scheme) {
			out = append(out, e)
		}
	}
	return out
}

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
