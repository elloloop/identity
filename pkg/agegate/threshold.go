package agegate

import (
	"fmt"
	"time"
)

// ThresholdDeterminer classifies a date of birth using two configured age
// boundaries:
//
//   - childMaxAge: a user whose age is <= childMaxAge is in BandChild (the
//     COPPA-protected band). 12 is the conventional value (under-13).
//   - adultAge: a user whose age is >= adultAge is in BandAdult. A user
//     between childMaxAge and adultAge is in BandTeen.
//
// IsMinor is true for any user below adultAge (CHILD or TEEN).
type ThresholdDeterminer struct {
	childMaxAge int
	adultAge    int
}

// NewThreshold builds the enabled, threshold-based provider. It validates the
// invariant 0 <= childMaxAge < adultAge so a misconfiguration is caught at
// startup rather than silently classifying every user as a child.
func NewThreshold(childMaxAge, adultAge int) (*ThresholdDeterminer, error) {
	if childMaxAge < 0 {
		return nil, fmt.Errorf("agegate: childMaxAge must be >= 0, got %d", childMaxAge)
	}
	if adultAge <= childMaxAge {
		return nil, fmt.Errorf("agegate: adultAge (%d) must be greater than childMaxAge (%d)", adultAge, childMaxAge)
	}
	return &ThresholdDeterminer{childMaxAge: childMaxAge, adultAge: adultAge}, nil
}

// Name implements Determiner.
func (ThresholdDeterminer) Name() string { return "threshold" }

// Enabled implements Determiner; always true.
func (ThresholdDeterminer) Enabled() bool { return true }

// Determine implements Determiner. A zero or future dobMs yields an
// unknown, non-minor decision (HasDOB=false).
func (d ThresholdDeterminer) Determine(dobMs int64, now time.Time) Decision {
	if dobMs <= 0 {
		return Decision{Band: BandUnknown, IsMinor: false, HasDOB: false}
	}
	dob := time.UnixMilli(dobMs).UTC()
	if dob.After(now.UTC()) {
		return Decision{Band: BandUnknown, IsMinor: false, HasDOB: false}
	}
	age := wholeYearsBetween(dob, now.UTC())
	switch {
	case age <= d.childMaxAge:
		return Decision{Band: BandChild, IsMinor: true, HasDOB: true}
	case age < d.adultAge:
		return Decision{Band: BandTeen, IsMinor: true, HasDOB: true}
	default:
		return Decision{Band: BandAdult, IsMinor: false, HasDOB: true}
	}
}

// wholeYearsBetween returns the number of full years elapsed from dob to now
// (i.e. the person's age), accounting for whether this year's birthday has
// occurred yet.
func wholeYearsBetween(dob, now time.Time) int {
	years := now.Year() - dob.Year()
	// If this year's birthday hasn't happened yet, subtract one.
	anniv := time.Date(now.Year(), dob.Month(), dob.Day(), 0, 0, 0, 0, time.UTC)
	if now.Before(anniv) {
		years--
	}
	if years < 0 {
		years = 0
	}
	return years
}
