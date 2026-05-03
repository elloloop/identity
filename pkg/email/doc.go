// Package email provides a provider-agnostic email transport layer.
//
// The package exposes a small Transport interface that can be implemented by
// any backend. Out of the box it ships with:
//
//   - SMTP transport (works with Gmail, AWS SES, SendGrid, Mailgun, Postmark,
//     and any other provider that exposes SMTP).
//   - Chain transport that tries multiple transports in order, providing
//     primary/secondary/tertiary failover.
//   - LogOnly transport for local development when no SMTP is configured;
//     it emits a structured WARN log with the recipient and subject so the
//     developer can manually deliver the message.
//
// A small templates sub-package embeds plain text+HTML templates for common
// transactional emails (password reset, email verification, invitations).
package email
