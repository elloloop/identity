package service

import (
	"time"

	"github.com/elloloop/identity/pkg/agegate"
)

// MinorDataMinimizer encapsulates the COPPA data-minimization decision: given a
// user's stored date of birth, should the server refuse to collect or persist
// non-essential PII because the account is a COPPA-protected child?
//
// It is a small value type (not an interface) shared by every service that
// touches optional PII — auth signup, profile updates, phone verification, and
// identity verification — so the "is this a minimized child?" rule lives in
// exactly one place. Only the CHILD band triggers minimization; teens and
// adults are unaffected, matching the COPPA scope (issue #257).
//
// When minimization is disabled (the default) BlocksChild always returns false,
// so behavior is identical to a deployment that never heard of the feature.
type MinorDataMinimizer struct {
	enabled    bool
	determiner agegate.Determiner
	now        func() time.Time
}

// NewMinorDataMinimizer builds the minimizer from the resolved age-gate
// determiner and the GATEWAY_MINOR_DATA_MINIMIZATION flag. now supplies the
// reference instant for age math; when nil it defaults to time.Now.
//
// Minimization is only ever active when the age gate itself is enabled — a
// CHILD band can only be derived from a DOB under an enabled gate — so a caller
// that flips GATEWAY_MINOR_DATA_MINIMIZATION on without age-gating gets a safe
// no-op rather than a half-wired control.
func NewMinorDataMinimizer(enabled bool, determiner agegate.Determiner, now func() time.Time) MinorDataMinimizer {
	if now == nil {
		now = time.Now
	}
	if determiner == nil {
		determiner = agegate.NewNoop()
	}
	return MinorDataMinimizer{
		enabled:    enabled && determiner.Enabled(),
		determiner: determiner,
		now:        now,
	}
}

// Enabled reports whether data-minimization is active for this deployment.
func (m MinorDataMinimizer) Enabled() bool { return m.enabled }

// BlocksChild reports whether the account identified by dobMs is a
// COPPA-protected child whose optional PII must not be collected/persisted.
// Always false when minimization is disabled.
func (m MinorDataMinimizer) BlocksChild(dobMs int64) bool {
	if !m.enabled {
		return false
	}
	return m.determiner.Determine(dobMs, m.now()).Band == agegate.BandChild
}
