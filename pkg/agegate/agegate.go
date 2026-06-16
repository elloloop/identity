// Package agegate defines the pluggable age-determination provider used to
// support COPPA-style age-gating at signup. A deployment that leaves
// age-gating disabled gets the no-op provider, which classifies everyone as
// an adult and never flags a minor — so signup behaves exactly as it did
// before this package existed.
//
// The interface is intentionally narrow: it maps a date of birth to an
// AgeBand (and the derived minor flag) given a reference instant ("now").
// The derived band/minor status are NOT persisted; they are recomputed from
// the stored date of birth and the deployment's configured threshold, so the
// threshold can change without a data backfill.
package agegate

import "time"

// AgeBand is the coarse age classification derived from a date of birth.
type AgeBand string

const (
	// BandUnknown is returned when no date of birth is available (the
	// zero-value / un-collected case). The service treats an unknown band
	// as non-minor.
	BandUnknown AgeBand = ""
	// BandChild is a user at or below the configured child-max age (the
	// COPPA-protected band).
	BandChild AgeBand = "CHILD"
	// BandTeen is a user above the child-max age but still a minor (below
	// the adult age).
	BandTeen AgeBand = "TEEN"
	// BandAdult is a user at or above the adult age.
	BandAdult AgeBand = "ADULT"
)

// Decision is the result of classifying a date of birth.
type Decision struct {
	Band    AgeBand
	IsMinor bool
	// HasDOB is false when no usable date of birth was supplied, in which
	// case Band is BandUnknown and IsMinor is false.
	HasDOB bool
}

// Determiner classifies a date of birth into an AgeBand. The service holds
// exactly one Determiner for the lifetime of the process.
type Determiner interface {
	// Name returns the provider identifier ("noop" or "threshold").
	Name() string

	// Enabled reports whether age-gating is active. When false the service
	// skips all age-band derivation and consent gating.
	Enabled() bool

	// Determine classifies dobMs (date of birth as epoch milliseconds; 0 =
	// unknown) relative to now. A zero or future dobMs yields BandUnknown /
	// HasDOB=false.
	Determine(dobMs int64, now time.Time) Decision
}
