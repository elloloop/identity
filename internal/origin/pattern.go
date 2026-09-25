// Package origin holds the browser-origin rules shared by the return_to
// allowlist and the CORS allow-list: the effective-port rule, the one-label
// wildcard origin pattern (https://*.parent.example), and the validated CORS
// allow-list built from them.
package origin

import (
	"errors"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

const (
	// wildcard is both the character that marks an entry as a pattern and
	// the whole leftmost label a valid pattern consists of.
	wildcard         = "*"
	httpsScheme      = "https"
	httpsDefaultPort = "443"
	httpDefaultPort  = "80"
	// minParentLabels refuses a single-label parent outright (https://*.app);
	// the public-suffix check then refuses multi-label suffixes such as co.uk
	// or a shared hosting domain like pages.dev.
	minParentLabels = 2
	maxLabelLen     = 63
	maxPort         = 65535
)

// Pattern parse errors. Each names one startup rejection of a wildcard entry.
var (
	ErrPatternScheme             = errors.New("wildcard origin must use https")
	ErrPatternLabel              = errors.New("wildcard must be the entire leftmost host label, as in https://*.parent.example")
	ErrPatternParentShort        = errors.New("wildcard parent domain must have at least two labels")
	ErrPatternParentLabel        = errors.New("wildcard parent domain has an invalid DNS label")
	ErrPatternParentNumeric      = errors.New("wildcard parent domain must not end in a numeric label (it would match IP addresses)")
	ErrPatternPort               = errors.New("wildcard origin port must be a number from 1 to 65535")
	ErrPatternParentPublicSuffix = errors.New("wildcard parent domain is a public suffix (a TLD or a shared hosting domain); scope it to a domain you control, such as https://*.<project>.pages.dev")
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
func IsPattern(entry string) bool { return strings.Contains(entry, wildcard) }

// ParsePattern validates the scheme, host and port of a wildcard entry.
// Callers apply their own rules to the rest of the URL (CORS allows no path;
// a return URL keeps its path prefix) and reject userinfo before calling.
//
// A parent that is itself a public suffix — an ICANN suffix like co.uk or a
// private one like a shared static-hosting domain — is refused: every tenant
// of that suffix could otherwise receive a user's OAuth code or make
// credentialed CORS calls.
func ParsePattern(u *url.URL) (Pattern, error) {
	if u.Scheme != httpsScheme {
		return Pattern{}, ErrPatternScheme
	}
	if strings.Contains(u.Path+u.RawQuery+u.Fragment, wildcard) {
		return Pattern{}, ErrPatternLabel
	}
	labels := strings.Split(strings.ToLower(u.Hostname()), ".")
	if labels[0] != wildcard {
		return Pattern{}, ErrPatternLabel
	}
	parentLabels := labels[1:]
	if len(parentLabels) < minParentLabels {
		return Pattern{}, ErrPatternParentShort
	}
	for _, l := range parentLabels {
		if !validLabel(l) {
			return Pattern{}, ErrPatternParentLabel
		}
	}
	if isNumeric(parentLabels[len(parentLabels)-1]) {
		return Pattern{}, ErrPatternParentNumeric
	}
	parent := strings.Join(parentLabels, ".")
	if suffix, _ := publicsuffix.PublicSuffix(parent); suffix == parent {
		return Pattern{}, ErrPatternParentPublicSuffix
	}
	port, err := canonicalPort(u)
	if err != nil {
		return Pattern{}, err
	}
	return Pattern{parent: parent, port: port}, nil
}

// canonicalPort is the pattern's effective port without leading zeros, so an
// entry written ":0443" means 443 rather than a port no browser ever sends.
func canonicalPort(u *url.URL) (string, error) {
	n, err := strconv.Atoi(EffectivePort(u))
	if err != nil || n < 1 || n > maxPort {
		return "", ErrPatternPort
	}
	return strconv.Itoa(n), nil
}

func isNumeric(l string) bool {
	for i := 0; i < len(l); i++ {
		if l[i] < '0' || l[i] > '9' {
			return false
		}
	}
	return l != ""
}

// Matches reports whether u is an https URL on the pattern's port whose host
// is exactly one valid DNS label under the parent domain. Host comparison is
// case-insensitive, as DNS is.
func (p Pattern) Matches(u *url.URL) bool {
	return p.matches(u.Scheme, strings.ToLower(u.Hostname()), EffectivePort(u))
}

// matches is Matches on an already lower-cased hostname, so a caller checking
// several patterns lower-cases once.
func (p Pattern) matches(scheme, lowerHost, port string) bool {
	if scheme != httpsScheme || port != p.port {
		return false
	}
	label, ok := strings.CutSuffix(lowerHost, "."+p.parent)
	return ok && validLabel(label)
}

// String is the canonical form of the pattern: lower-case, with the port
// omitted when it is the https default.
func (p Pattern) String() string {
	s := httpsScheme + "://" + wildcard + "." + p.parent
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
