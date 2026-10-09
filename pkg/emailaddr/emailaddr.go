// Package emailaddr is the one rule the identity service uses to decide that
// two spellings of an email address name the same mailbox. Every account
// address the service stores, and every address it looks an account up by, is
// in the form Canonicalize returns. A service that keeps its own records keyed
// by an account's email compares in the same form by calling Canonicalize on
// both sides, so a person who signs up as one spelling and is invited or
// searched for as another is still recognised.
package emailaddr

import (
	"strings"

	"golang.org/x/net/idna"
)

// gmailDomain is the domain every shared-inbox Google address canonicalizes
// to. googlemailDomain delivers to the same inbox.
const (
	gmailDomain      = "gmail.com"
	googlemailDomain = "googlemail.com"
)

// Canonicalize returns the canonical form of addr:
//
//   - Trimmed and lower-cased.
//   - Everything from the first '+' in the local part dropped. Almost every
//     provider delivers a "+tag" address to the untagged mailbox.
//   - The domain canonicalized as CanonicalizeDomain does: googlemail.com
//     becomes gmail.com, and an internationalized domain is punycoded so
//     visually equal unicode domains compare equal.
//   - For gmail.com only, every dot removed from the local part. Gmail ignores
//     them; most other providers treat dots as significant, so they are kept
//     everywhere else.
//
// It is permissive on malformed input: an address with no '@' comes back
// trimmed and lower-cased, so a caller may canonicalize before validating.
// It is idempotent.
func Canonicalize(addr string) string {
	addr = strings.TrimSpace(strings.ToLower(addr))
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return addr
	}
	local := addr[:at]
	domain := CanonicalizeDomain(addr[at+1:])
	if i := strings.Index(local, "+"); i >= 0 {
		local = local[:i]
	}
	if domain == gmailDomain {
		local = strings.ReplaceAll(local, ".", "")
	}
	return local + "@" + domain
}

// CanonicalizeDomain returns the canonical form of a bare email domain, the
// same form Canonicalize gives an address's domain: trimmed, lower-cased,
// without a trailing FQDN dot, punycoded when it is internationalized, and
// googlemail.com folded into gmail.com. A domain that cannot be punycoded is
// returned otherwise canonicalized.
func CanonicalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	// "example.com." and "example.com" name the same domain; an address never
	// carries the trailing dot, so a configured entry that kept it would match
	// nothing.
	domain = strings.TrimSuffix(domain, ".")
	if ascii, err := idna.Lookup.ToASCII(domain); err == nil {
		domain = ascii
	}
	if domain == googlemailDomain {
		return gmailDomain
	}
	return domain
}

// SameMailbox reports whether a and b canonicalize to the same address.
func SameMailbox(a, b string) bool {
	return Canonicalize(a) == Canonicalize(b)
}
