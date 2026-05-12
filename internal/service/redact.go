package service

import "strings"

// redactEmail returns a privacy-safe representation suitable for logs:
// the first character of the local part, asterisks for the rest, and
// the domain. "alice@example.com" -> "a***@example.com". Empty input
// returns "". This is the format used everywhere we log identifying
// fields — never raw email — to keep log aggregation off the GDPR
// fast-lane.
func redactEmail(s string) string {
	at := strings.IndexByte(s, '@')
	if at <= 0 {
		return s
	}
	local := s[:at]
	domain := s[at:]
	if len(local) <= 1 {
		return string(local[0]) + "***" + domain
	}
	return string(local[0]) + "***" + domain
}
