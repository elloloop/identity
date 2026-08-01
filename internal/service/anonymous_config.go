package service

import (
	"fmt"

	"github.com/elloloop/identity/internal/config"
)

// ProjectAnonymousConfig is a project's anonymous-sign-in policy.
//
// It is deliberately ORTHOGONAL to ProjectAccessConfig, matching Firebase:
// `access.mode` (open/allowlist/invite/closed) governs which EMAIL-IDENTIFIED
// humans may sign up and log in, and says nothing about anonymous sessions.
// A project may run mode:closed — admitting no new identified users at all —
// while still handing out anonymous sessions to its app, because the two
// answer different questions. Anonymous sign-in is instead gated by its own
// switch here (default OFF, so the capability never appears without an
// explicit decision) and, when configured, by the assurance layer.
type ProjectAnonymousConfig struct {
	// Enabled turns SignInAnonymously on for the project. Absent/false means
	// the RPC is refused with ErrAnonymousDisabled.
	Enabled bool `json:"enabled"`

	// RetentionDays overrides the deployment-wide retention window for THIS
	// project's anonymous users. 0 means "use the deployment default"
	// (GATEWAY_ANONYMOUS_RETENTION_DAYS); a negative value is rejected.
	// The window is measured from a user's last activity, and an upgraded
	// account leaves the window's reach entirely.
	RetentionDays int `json:"retention_days,omitempty"`
}

// validate rejects a retention override that could never be honoured. The
// enabled flag needs no validation — both values are meaningful.
func (a ProjectAnonymousConfig) validate() error {
	if a.RetentionDays < 0 {
		return fmt.Errorf("%w: anonymous.retention_days must be >= 0, got %d", ErrInvalidArgument, a.RetentionDays)
	}
	// The per-project override is bounded by the SAME cap as the
	// deployment-wide knob — one rule, one constant — so a project cannot
	// pin its anonymous users forever, nor overflow the cutoff duration.
	if a.RetentionDays > config.MaxAnonymousRetentionDays {
		return fmt.Errorf("%w: anonymous.retention_days must be <= %d, got %d",
			ErrInvalidArgument, config.MaxAnonymousRetentionDays, a.RetentionDays)
	}
	return nil
}
