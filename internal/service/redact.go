package service

import "github.com/elloloop/identity/pkg/email"

// redactEmail is a package-local alias for email.Redact, kept so the
// existing service-layer call sites read naturally. New code may call
// email.Redact directly.
func redactEmail(s string) string { return email.Redact(s) }
