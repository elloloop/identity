package assurance

import "context"

// NoopVerifier is the disabled-CAPTCHA implementation: it accepts every
// token (including the empty one). It is wired when CAPTCHA is disabled or
// no provider is configured, so the handler can always call Verify
// without a nil check.
type NoopVerifier struct{}

// NewNoopVerifier returns a NoopVerifier.
func NewNoopVerifier() NoopVerifier { return NoopVerifier{} }

// Name implements Verifier.
func (NoopVerifier) Name() string { return "noop" }

// Verify implements Verifier; it always succeeds.
func (NoopVerifier) Verify(context.Context, string, string) error { return nil }
