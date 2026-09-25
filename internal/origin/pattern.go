// Package origin holds the browser-origin rules shared by the return_to
// allowlist and the CORS allow-list: the effective-port rule and the
// one-label wildcard origin pattern (https://*.parent.example).
package origin

import (
	"errors"
	"net/url"
	"strings"
)

const (
	wildcardLabel    = "*"
	httpsScheme      = "https"
	httpsDefaultPort = "443"
	httpDefaultPort  = "80"
	// minParentLabels keeps a pattern from spanning a whole public suffix:
	// https://*.app would admit every site on the .app TLD.
	minParentLabels = 2
	maxLabelLen     = 63
)

// Pattern parse errors. Each names one startup rejection of a wildcard entry.
var (
	ErrPatternScheme      = errors.New("wildcard origin must use https")
	ErrPatternLabel       = errors.New("wildcard must be the entire leftmost host label, as in https://*.parent.example")
	ErrPatternParentShort = errors.New("wildcard parent domain must have at least two labels")
	ErrPatternParentLabel = errors.New("wildcard parent domain has an invalid DNS label")
)

// Pattern is a validated one-label wildcard origin, https://*.<parent>[:port].
// The wildcard stands for exactly one DNS label; the scheme (https), the
// parent domain and the port are fixed.
type Pattern struct {
	parent string
	port   string
}

// IsPattern reports whether an allowlist entry is written as a wildcard and
// so must parse as a Pattern rather than be compared literally.
func IsPattern(entry string) bool { return strings.Contains(entry, wildcardLabel) }

// ParsePattern validates the scheme, host and port of a wildcard entry.
// Callers apply their own rules to the rest of the URL (CORS allows no path;
// a return URL keeps its path prefix) and reject userinfo before calling.
func ParsePattern(u *url.URL) (Pattern, error) {
	if u.Scheme != httpsScheme {
		return Pattern{}, ErrPatternScheme
	}
	if strings.Contains(u.EscapedPath()+u.RawQuery+u.Fragment, wildcardLabel) {
		return Pattern{}, ErrPatternLabel
	}
	labels := strings.Split(strings.ToLower(u.Hostname()), ".")
	if labels[0] != wildcardLabel {
		return Pattern{}, ErrPatternLabel
	}
	parent := labels[1:]
	if len(parent) < minParentLabels {
		return Pattern{}, ErrPatternParentShort
	}
	for _, l := range parent {
		if !validLabel(l) {
			return Pattern{}, ErrPatternParentLabel
		}
	}
	return Pattern{parent: strings.Join(parent, "."), port: EffectivePort(u)}, nil
}

// Matches reports whether u is an https URL on the pattern's port whose host
// is exactly one valid DNS label under the parent domain. Host comparison is
// case-insensitive, as DNS is.
func (p Pattern) Matches(u *url.URL) bool {
	if u.Scheme != httpsScheme || EffectivePort(u) != p.port {
		return false
	}
	label, ok := strings.CutSuffix(strings.ToLower(u.Hostname()), "."+p.parent)
	return ok && validLabel(label)
}

// String is the canonical form of the pattern: lower-case, with the port
// omitted when it is the https default.
func (p Pattern) String() string {
	s := httpsScheme + "://" + wildcardLabel + "." + p.parent
	if p.port != httpsDefaultPort {
		s += ":" + p.port
	}
	return s
}

// EffectivePort is u's explicit port, or the scheme's default when omitted,
// so https://host and https://host:443 compare as the same origin.
func EffectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == httpsScheme {
		return httpsDefaultPort
	}
	return httpDefaultPort
}

// validLabel reports whether l is a lower-case LDH hostname label: 1–63
// letters, digits and hyphens, not starting or ending with a hyphen.
func validLabel(l string) bool {
	if l == "" || len(l) > maxLabelLen || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
