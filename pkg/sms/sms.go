// Package sms is the abstraction over an SMS backend, mirroring
// pkg/email. A Sender delivers a short text Message (a verification
// OTP) to a phone number. Concrete senders for Twilio, AWS SNS, and
// Azure Communication Services live in sibling files; NewLogOnly is the
// disabled/dev default that logs instead of delivering.
//
// All senders are safe for concurrent use and honor ctx cancellation
// via the injected *http.Client. Each provider's base URL is an
// injectable struct field so tests can point Send at an httptest server
// without any hardcoded endpoint.
package sms

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors returned (wrapped) by the sms package. Callers test
// with errors.Is.
var (
	// ErrInvalidMessage is returned (wrapped) when a Message fails
	// validation.
	ErrInvalidMessage = errors.New("sms: invalid message")

	// ErrTransport is returned (wrapped) when a backend rejects the send
	// or the HTTP round trip fails.
	ErrTransport = errors.New("sms: transport failure")

	// ErrProviderUnavailable is returned (wrapped) when a provider is
	// configured but cannot be reached, or a provider arm is not yet
	// implemented.
	ErrProviderUnavailable = errors.New("sms: provider unavailable")
)

// Message is a single outgoing SMS. Validate must pass before a Sender
// dispatches it.
type Message struct {
	// To is the destination phone number in E.164 form (e.g.
	// "+14155550123").
	To string

	// From is the sender id / originating number. May be empty when the
	// Sender injects a configured default.
	From string

	// Body is the message text.
	Body string
}

// Sender delivers an SMS Message. Implementations validate the message
// and return a wrapped ErrInvalidMessage for malformed input, or a
// wrapped ErrTransport / ErrProviderUnavailable for backend failures.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// Validate checks the message is well-formed: a non-empty E.164-looking
// To and a non-empty Body. The check is deliberately permissive on the
// number shape (a leading '+' and digits) — providers do the
// authoritative validation, and identity's own normalization runs in
// the service layer.
func (m Message) Validate() error {
	to := strings.TrimSpace(m.To)
	if to == "" {
		return fmt.Errorf("%w: to is required", ErrInvalidMessage)
	}
	if !looksLikeE164(to) {
		return fmt.Errorf("%w: to %q is not E.164", ErrInvalidMessage, m.To)
	}
	if strings.TrimSpace(m.Body) == "" {
		return fmt.Errorf("%w: body is required", ErrInvalidMessage)
	}
	return nil
}

// looksLikeE164 reports whether s is a leading '+' followed by 1..15
// decimal digits, the E.164 shape. It does not validate the country
// code or assigned-range, only the structural form.
func looksLikeE164(s string) bool {
	if len(s) < 2 || s[0] != '+' {
		return false
	}
	digits := s[1:]
	if len(digits) > 15 {
		return false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
