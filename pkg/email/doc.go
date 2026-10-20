// Package email provides a provider-agnostic email transport layer.
//
// The package exposes a small Transport interface that can be implemented by
// any backend. Out of the box it ships with:
//
//   - SMTP transport (works with Gmail, AWS SES, SendGrid, Mailgun, Postmark,
//     and any other provider that exposes SMTP).
//   - Chain transport that tries multiple transports in order, providing
//     primary/secondary/tertiary failover.
//   - LogOnly transport, used when no SMTP is configured and as the last
//     link of a chain whose providers all failed; it emits a WARN log that
//     a message was dropped (redacted recipient, subject, body sizes),
//     never its body. Point SMTP at a mail catcher to read messages locally.
//
// A small templates sub-package embeds plain text+HTML templates for common
// transactional emails (password reset, email verification, invitations).
package email
