package email

import "strings"

// Redact returns a privacy-safe representation of an email address for use
// in logs and metrics labels: the first character of the local part,
// asterisks for the rest, and the domain. "alice@example.com" becomes
// "a***@example.com". Inputs without an "@" are returned unchanged.
//
// Logs at production scale store every "to" address indefinitely; raw
// emails in those streams put the service squarely on the GDPR fast-lane.
// Every code path that logs an email address MUST use Redact instead.
func Redact(s string) string {
	at := strings.IndexByte(s, '@')
	if at <= 0 {
		return s
	}
	return string(s[0]) + "***" + s[at:]
}
