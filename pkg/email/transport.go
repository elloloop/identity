package email

import "context"

// Transport is the abstraction over an email backend. Implementations must be
// safe for concurrent use and should honor ctx cancellation as best they can.
type Transport interface {
	// Send delivers m. It must validate m and return a wrapped ErrInvalidMessage
	// for malformed inputs, or a wrapped ErrTransport (or other error) for
	// backend failures.
	Send(ctx context.Context, m Message) error
}
