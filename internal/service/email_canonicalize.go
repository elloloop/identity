package service

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"golang.org/x/net/idna"
)

// RFC-5321 caps. Stored here rather than inlined so a future tuning is
// one edit, not a grep.
const (
	emailMaxLocalLen  = 64
	emailMaxDomainLen = 253
	emailMaxTotalLen  = 254
)

// reservedTLDs are TLDs reserved by RFC-2606 / RFC-6761 (and a few
// internal-only suffixes). Email addresses under these can never
// receive password resets or any other delivery, so they're rejected
// at signup time.
var reservedTLDs = map[string]struct{}{
	"test":        {},
	"example":     {},
	"invalid":     {},
	"localhost":   {},
	"local":       {},
	"internal":    {},
	"localdomain": {},
}

// disposableDomains is the built-in blocklist of well-known
// throwaway-email providers. This is intentionally a SMALL list —
// the goal is to block the top abuse vectors (mailinator and friends),
// not to be exhaustive. Deployers extend it via
// GATEWAY_DISPOSABLE_EMAIL_DOMAINS (CSV) when they need more.
var disposableDomains = map[string]struct{}{
	"mailinator.com":   {},
	"10minutemail.com": {},
	"guerrillamail.com": {},
	"sharklasers.com":  {}, // guerrillamail alias
	"yopmail.com":      {},
	"tempmail.org":     {},
	"trashmail.com":    {},
	"dispostable.com":  {},
	"maildrop.cc":      {},
	"getnada.com":      {},
	"throwawaymail.com": {},
	"fakeinbox.com":    {},
	"mintemail.com":    {},
	"mailnesia.com":    {},
}

// gmailDomains are the addresses that share the @gmail.com inbox.
// Dot-stripping in the local part only applies here — most non-Google
// SMTP servers treat dots as significant.
var gmailDomains = map[string]bool{
	"gmail.com":       true,
	"googlemail.com":  true,
}

// canonicalizeEmail returns the canonical form used for duplicate
// detection and lookup. It implements Gmail's normalization rules:
//
//   - Lowercase + trim (always).
//   - Strip everything from '+' onward in the local part (universal —
//     virtually every provider supports +addressing and the un-tagged
//     form is always deliverable).
//   - For @gmail.com / @googlemail.com only: strip dots from the local
//     part and collapse googlemail.com → gmail.com.
//   - Punycode IDN domains via golang.org/x/net/idna so visually-
//     equivalent unicode domains compare equal.
//
// The function is intentionally permissive on malformed input — it
// returns the input unchanged when there's no '@' to split on so
// callers can run it before validateEmailFormat without a panic.
// Production code runs validation FIRST, canonicalization SECOND.
func canonicalizeEmail(addr string) string {
	addr = strings.TrimSpace(strings.ToLower(addr))
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return addr
	}
	local := addr[:at]
	domain := addr[at+1:]

	// Strip plus-tag from local part (universal).
	if i := strings.Index(local, "+"); i >= 0 {
		local = local[:i]
	}

	// Punycode the domain. Errors leave the original domain in place —
	// validateEmailFormat will catch malformed inputs before this.
	if ascii, err := idna.Lookup.ToASCII(domain); err == nil {
		domain = ascii
	}

	if gmailDomains[domain] {
		local = strings.ReplaceAll(local, ".", "")
		domain = "gmail.com"
	}
	return local + "@" + domain
}

// validateEmailFormat is the gate every email-bearing RPC runs before
// storing or looking up by email. The intent is anti-abuse +
// deliverability:
//
//   - Reject formatting nonsense (RFC-5322 via net/mail.ParseAddress
//     plus stricter "one @, dot in domain, no leading/trailing dot,
//     no whitespace, no control characters").
//   - Reject oversize inputs that pollute storage / mail headers.
//   - Reject reserved/non-routable TLDs (.test, .example, .invalid,
//     .localhost, .local, .internal, .localdomain).
//   - Reject disposable / one-time-use email providers (mailinator
//     and friends — the top free-tier abuse vector).
//
// On success, returns nil. The caller usually pairs this with
// canonicalizeEmail to get the storage/lookup form.
func validateEmailFormat(addr string) error {
	if addr == "" {
		return errors.New("email is required")
	}
	if strings.ContainsAny(addr, " \t\r\n\v\f") {
		return errors.New("email must not contain whitespace")
	}
	for _, r := range addr {
		if r < 0x20 || r == 0x7f {
			return errors.New("email must not contain control characters")
		}
	}
	if len(addr) > emailMaxTotalLen {
		return fmt.Errorf("email too long (max %d chars)", emailMaxTotalLen)
	}
	at := strings.Count(addr, "@")
	if at != 1 {
		return errors.New("email must contain exactly one '@'")
	}
	parsed, err := mail.ParseAddress(addr)
	if err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}
	if parsed.Address != addr {
		return errors.New("invalid email")
	}
	local, domain, _ := strings.Cut(addr, "@")
	if local == "" {
		return errors.New("email local part is empty")
	}
	if len(local) > emailMaxLocalLen {
		return fmt.Errorf("email local part too long (max %d chars)", emailMaxLocalLen)
	}
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") {
		return errors.New("email local part must not start or end with '.'")
	}
	if strings.Contains(local, "..") {
		return errors.New("email local part must not contain consecutive dots")
	}
	if domain == "" || !strings.Contains(domain, ".") {
		return errors.New("email domain must contain a '.'")
	}
	if len(domain) > emailMaxDomainLen {
		return fmt.Errorf("email domain too long (max %d chars)", emailMaxDomainLen)
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return errors.New("email domain must not start or end with '.'")
	}
	if strings.Contains(domain, "..") {
		return errors.New("email domain must not contain consecutive dots")
	}
	// Strip a trailing dot the user might have typed (FQDN form is
	// legal-but-cosmetic; the checks below operate on the bare form).
	domainBare := strings.TrimSuffix(strings.ToLower(domain), ".")
	tld := domainBare
	if i := strings.LastIndex(domainBare, "."); i >= 0 {
		tld = domainBare[i+1:]
	}
	if _, reserved := reservedTLDs[tld]; reserved {
		return fmt.Errorf("email domain has reserved/non-routable TLD %q", tld)
	}
	// Punycode the domain to canonical ASCII before checking the
	// disposable list so an attacker can't bypass with an IDN
	// homograph of mailinator.
	domainCanon := domainBare
	if ascii, err := idna.Lookup.ToASCII(domainBare); err == nil {
		domainCanon = ascii
	}
	if _, banned := disposableDomains[domainCanon]; banned {
		return fmt.Errorf("disposable email addresses are not allowed")
	}
	return nil
}
