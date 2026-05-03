package email

import (
	"fmt"
	"net/mail"
	"strings"
)

// Message is a single outgoing email. Validate must be called (or NewMessage
// used) before passing to a Transport. Either HTML or Text (or both) must be
// non-empty.
type Message struct {
	// To is the recipient address (RFC 5322). Exactly one recipient is
	// supported; for multi-recipient sends, call Send once per recipient so
	// each delivery can be tracked and retried independently.
	To string

	// From is the sender address (RFC 5322). May be left empty when using a
	// transport that injects a default From (e.g. SMTPConfig.From).
	From string

	// Subject is the email subject line.
	Subject string

	// HTML is the HTML body. Optional if Text is set.
	HTML string

	// Text is the plain-text body. Optional if HTML is set.
	Text string
}

// NewMessage constructs a Message and runs Validate. Returns a wrapped
// ErrInvalidMessage on failure.
func NewMessage(to, from, subject, html, text string) (Message, error) {
	m := Message{
		To:      to,
		From:    from,
		Subject: subject,
		HTML:    html,
		Text:    text,
	}
	if err := m.Validate(); err != nil {
		return Message{}, err
	}
	return m, nil
}

// Validate checks the message is well-formed.
//
// Rules:
//   - To must parse as an RFC 5322 address.
//   - From, if non-empty, must parse as an RFC 5322 address.
//   - Subject must be non-empty.
//   - At least one of HTML or Text must be non-empty.
func (m Message) Validate() error {
	if strings.TrimSpace(m.To) == "" {
		return fmt.Errorf("%w: to is required", ErrInvalidMessage)
	}
	if _, err := mail.ParseAddress(m.To); err != nil {
		return fmt.Errorf("%w: invalid to address %q: %v", ErrInvalidMessage, m.To, err)
	}
	if strings.TrimSpace(m.From) != "" {
		if _, err := mail.ParseAddress(m.From); err != nil {
			return fmt.Errorf("%w: invalid from address %q: %v", ErrInvalidMessage, m.From, err)
		}
	}
	if strings.TrimSpace(m.Subject) == "" {
		return fmt.Errorf("%w: subject is required", ErrInvalidMessage)
	}
	if strings.TrimSpace(m.HTML) == "" && strings.TrimSpace(m.Text) == "" {
		return fmt.Errorf("%w: at least one of html or text body must be non-empty", ErrInvalidMessage)
	}
	return nil
}
