package email

import (
	"net/mail"
	"strings"
	"unicode/utf8"
)

// Redact returns a privacy-safe representation of an email address for use
// in logs and metrics labels: the first character of the local part,
// asterisks for the rest, and the domain. "alice@example.com" becomes
// "a***@example.com". An RFC 5322 form is reduced to its mailbox first, so a
// display name or a quoted local part containing "@" cannot carry the
// address through. Inputs without an "@" are returned unchanged.
//
// Logs at production scale store every "to" address indefinitely; raw
// emails in those streams put the service squarely on the GDPR fast-lane.
// Every code path that logs an email address MUST use Redact instead.
func Redact(s string) string {
	if addr, err := mail.ParseAddress(s); err == nil {
		s = addr.Address
	}
	at := strings.LastIndexByte(s, '@')
	if at <= 0 {
		return s
	}
	first, _ := utf8.DecodeRuneInString(s)
	return string(first) + "***" + s[at:]
}
