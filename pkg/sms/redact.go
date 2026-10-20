package sms

import "strings"

// Redact returns a phone number safe to log: the country prefix and the last
// two digits, the middle masked. "+15551234567" becomes "+1********67".
// Every code path that logs a phone number MUST use Redact instead.
func Redact(p string) string {
	if len(p) <= 4 {
		return "***"
	}
	return p[:2] + strings.Repeat("*", len(p)-4) + p[len(p)-2:]
}
