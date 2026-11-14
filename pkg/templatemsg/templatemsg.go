// Package templatemsg is the abstraction over a messaging-app backend that
// delivers pre-approved template messages, beside pkg/sms. Such a backend
// does not take free text: the operator registers a template with the
// provider, and a send names the template, its language and the values of
// its placeholders. A Sender delivers one Message (a verification code) to
// a phone number.
//
// This package ships no provider: an embedder supplies a Sender for the
// provider it uses, and a deployment without one has no message channel.
package templatemsg

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors returned (wrapped) by Senders. Callers test with
// errors.Is.
var (
	// ErrInvalidMessage is returned (wrapped) when a Message fails
	// validation.
	ErrInvalidMessage = errors.New("templatemsg: invalid message")

	// ErrTransport is returned (wrapped) when a backend rejects the send or
	// the round trip fails.
	ErrTransport = errors.New("templatemsg: transport failure")
)

// Message is a single outgoing template message.
type Message struct {
	// To is the destination phone number in E.164 form (e.g.
	// "+14155550123").
	To string

	// Template is the name the template is registered under with the
	// provider.
	Template string

	// Language is the template's language code as the provider knows it
	// (e.g. "en"). May be empty when the Sender has a default.
	Language string

	// Params are the values of the template's placeholders, in order. A
	// verification template takes one: the code.
	Params []string
}

// Sender delivers a template Message. Implementations validate the message
// and return a wrapped ErrInvalidMessage for malformed input, or a wrapped
// ErrTransport for a backend failure. They must be safe for concurrent use,
// and must never log Params, which carry one-time codes, nor put them in an
// error they return: the caller logs those errors, and a provider's error
// often echoes the request it refused.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// Validate checks the message is well-formed: an E.164-looking To and a
// Template. Providers do the authoritative validation.
func (m Message) Validate() error {
	to := strings.TrimSpace(m.To)
	if !looksLikeE164(to) {
		return fmt.Errorf("%w: to is not E.164", ErrInvalidMessage)
	}
	if strings.TrimSpace(m.Template) == "" {
		return fmt.Errorf("%w: template is required", ErrInvalidMessage)
	}
	return nil
}

// looksLikeE164 reports whether s is a leading '+' followed by 1..15
// decimal digits.
func looksLikeE164(s string) bool {
	if len(s) < 2 || len(s) > 16 || s[0] != '+' {
		return false
	}
	for _, r := range s[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
