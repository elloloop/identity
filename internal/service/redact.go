package service

import (
	"strings"

	"github.com/elloloop/identity/pkg/email"
)

// redactEmail wraps email.Redact because `email` is a parameter name across
// most of this package (auth_login.go alone has five functions taking one),
// and inside those bodies the package identifier is shadowed — `email.Redact`
// does not compile there. It is a naming workaround, not a compatibility
// shim: there is no second way to do this, and new code in this package
// should use it too.
func redactEmail(s string) string { return email.Redact(s) }

// redactIdentifier redacts a login identifier for logs: an email address is
// redacted, while a managed-child username (no '@') names no inbox and is
// logged as-is.
func redactIdentifier(s string) string {
	if strings.Contains(s, "@") {
		return redactEmail(s)
	}
	return s
}
