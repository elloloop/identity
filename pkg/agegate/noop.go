package agegate

import "time"

// NoopDeterminer is the default provider used when age-gating is disabled.
// It classifies everyone as an adult and never reports a minor, so signup
// and token issuance behave exactly as they did before age-gating existed.
type NoopDeterminer struct{}

// NewNoop returns the disabled, everyone-is-an-adult provider.
func NewNoop() *NoopDeterminer { return &NoopDeterminer{} }

// Name implements Determiner.
func (NoopDeterminer) Name() string { return "noop" }

// Enabled implements Determiner; always false.
func (NoopDeterminer) Enabled() bool { return false }

// Determine implements Determiner; always returns the adult, non-minor,
// no-DOB decision regardless of the supplied date of birth.
func (NoopDeterminer) Determine(int64, time.Time) Decision {
	return Decision{Band: BandUnknown, IsMinor: false, HasDOB: false}
}
