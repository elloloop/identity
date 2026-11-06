package origin

import (
	"net"
	"net/url"
	"strings"
)

// IsDNSName reports whether host is a lower-case DNS name: labels of letters,
// digits and hyphens, none starting or ending with a hyphen.
func IsDNSName(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !validLabel(label) {
			return false
		}
	}
	return true
}

// IsRegistrableSuffix reports whether rpID may serve as the WebAuthn
// relying-party id of hostname: it is hostname or a parent of it, and it is not
// itself a public suffix, which no browser lets a site claim. The loopback name
// localhost has no public suffix, and WebAuthn accepts it for itself.
func IsRegistrableSuffix(rpID, hostname string) bool {
	if !IsDNSName(rpID) || net.ParseIP(rpID) != nil {
		return false
	}
	if rpID == "localhost" {
		return hostname == rpID
	}
	if isPublicSuffix(rpID) {
		return false
	}
	return hostname == rpID || strings.HasSuffix(hostname, "."+rpID)
}

// IsSerializedPort reports whether u's port is written as a browser serializes
// an origin: omitted when it is the scheme's default, otherwise a valid port with
// no leading zeros.
func IsSerializedPort(u *url.URL) bool {
	if strings.HasSuffix(u.Host, ":") {
		return false
	}
	port := u.Port()
	if port == "" {
		return true
	}
	if !ValidPort(port) || strings.HasPrefix(port, "0") {
		return false
	}
	defaultPort := httpDefaultPort
	if u.Scheme == httpsScheme {
		defaultPort = httpsDefaultPort
	}
	return port != defaultPort
}
