package email

import "errors"

// Sentinel errors returned by the email package. Underlying errors are wrapped
// with %w so callers can use errors.Is to test against these sentinels.
var (
	// ErrInvalidMessage is returned (wrapped) when a Message fails validation.
	ErrInvalidMessage = errors.New("email: invalid message")

	// ErrTransport is returned (wrapped) when an underlying transport fails.
	ErrTransport = errors.New("email: transport failure")
)
