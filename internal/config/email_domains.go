package config

import (
	"strings"

	"golang.org/x/net/idna"
)

// publicEmailProviders is the built-in set of consumer / public email
// providers — domains where a verified address does NOT imply affiliation
// with a company, so a Tenant must never be auto-formed from one. It is a
// representative set of the major global providers, not an exhaustive
// directory; deployers extend it via GATEWAY_PUBLIC_EMAIL_DOMAINS.
var publicEmailProviders = map[string]struct{}{
	// Google
	"gmail.com": {}, "googlemail.com": {},
	// Microsoft
	"outlook.com": {}, "outlook.co.uk": {}, "outlook.de": {}, "outlook.fr": {},
	"hotmail.com": {}, "hotmail.co.uk": {}, "hotmail.fr": {}, "hotmail.de": {},
	"live.com": {}, "live.co.uk": {}, "live.fr": {}, "msn.com": {},
	// Yahoo
	"yahoo.com": {}, "yahoo.co.uk": {}, "yahoo.co.in": {}, "yahoo.fr": {},
	"yahoo.de": {}, "yahoo.es": {}, "yahoo.ca": {}, "yahoo.com.br": {},
	"ymail.com": {}, "rocketmail.com": {},
	// Apple
	"icloud.com": {}, "me.com": {}, "mac.com": {},
	// AOL
	"aol.com": {},
	// Proton
	"proton.me": {}, "protonmail.com": {}, "pm.me": {},
	// Other privacy / paid consumer
	"fastmail.com": {}, "hey.com": {}, "tutanota.com": {}, "tuta.com": {}, "tutanota.de": {},
	// GMX / mail.com / Zoho
	"gmx.com": {}, "gmx.net": {}, "gmx.de": {}, "mail.com": {}, "zoho.com": {},
	// Russia
	"yandex.com": {}, "yandex.ru": {}, "mail.ru": {}, "bk.ru": {}, "inbox.ru": {}, "list.ru": {},
	// China
	"qq.com": {}, "foxmail.com": {}, "163.com": {}, "126.com": {}, "sina.com": {},
	// Korea
	"naver.com": {}, "hanmail.net": {}, "daum.net": {},
	// Germany
	"web.de": {}, "t-online.de": {}, "freenet.de": {},
	// Italy
	"libero.it": {}, "virgilio.it": {},
	// France
	"orange.fr": {}, "free.fr": {}, "laposte.net": {}, "wanadoo.fr": {}, "sfr.fr": {},
	// US ISPs
	"comcast.net": {}, "verizon.net": {}, "att.net": {}, "sbcglobal.net": {}, "cox.net": {},
	// India
	"rediffmail.com": {},
}

// IsPublicEmailDomain reports whether emailOrDomain belongs to a public /
// consumer email provider — a domain a Tenant must never be auto-formed
// from. The input may be a full address (the part after the last '@' is
// used) or a bare domain; it is lower-cased, trimmed, stripped of a
// trailing FQDN dot, and punycode-canonicalised before the built-in set
// and GATEWAY_PUBLIC_EMAIL_DOMAINS are consulted, so an IDN homograph
// cannot slip past the check.
func (c *Config) IsPublicEmailDomain(emailOrDomain string) bool {
	d := canonicalEmailDomain(emailOrDomain)
	if d == "" {
		return false
	}
	if _, ok := publicEmailProviders[d]; ok {
		return true
	}
	for _, extra := range splitCSVDomains(c.PublicEmailDomains) {
		if extra == d {
			return true
		}
	}
	return false
}

// canonicalEmailDomain extracts and canonicalises the domain from an email
// address or a bare domain: the substring after the last '@' (when
// present), lower-cased and trimmed, with a trailing FQDN dot removed and
// IDN labels punycoded. Returns "" when there is no usable domain.
func canonicalEmailDomain(emailOrDomain string) string {
	s := strings.TrimSpace(strings.ToLower(emailOrDomain))
	if at := strings.LastIndex(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return ""
	}
	if ascii, err := idna.Lookup.ToASCII(s); err == nil {
		s = ascii
	}
	return s
}

// splitCSVDomains parses a comma-separated domain list, canonicalising each
// entry and dropping blanks. Shared by the public-domain check and any
// future env-extended domain list.
func splitCSVDomains(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if d := canonicalEmailDomain(p); d != "" {
			out = append(out, d)
		}
	}
	return out
}
