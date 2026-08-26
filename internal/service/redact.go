package service

import (
	"strings"

	"github.com/elloloop/identity/pkg/email"
)

// redactEmail is a package-local alias for email.Redact, kept so the
// existing service-layer call sites read naturally. New code may call
// email.Redact directly.
func redactEmail(s string) string { return email.Redact(s) }

// redactIdentifier redacts a login identifier for logs: an email address is
// redacted, while a managed-child username (no '@') names no inbox and is
// logged as-is.
func redactIdentifier(s string) string {
	if strings.Contains(s, "@") {
		return email.Redact(s)
	}
	return s
}
