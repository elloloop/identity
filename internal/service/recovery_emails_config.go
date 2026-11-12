package service

import (
	"fmt"
	"time"
)

const (
	// defaultRecoveryEmailsMax is how many recovery emails an account may
	// hold when its project sets no cap.
	defaultRecoveryEmailsMax = 5
	// maxRecoveryEmailsMax bounds the cap a project may set: each address is
	// one more mailbox a sign-in notice goes to.
	maxRecoveryEmailsMax = 20
	// defaultRecoveryEmailsReauthMaxAgeSeconds is how recent a sign-in a
	// change to the list requires when the project sets none. It is longer
	// than a merge's window because adding an address waits on an email.
	defaultRecoveryEmailsReauthMaxAgeSeconds = 900
	// maxRecoveryEmailsReauthMaxAgeSeconds caps the window, as a merge's is
	// capped: past an hour a sign-in is no longer recent.
	maxRecoveryEmailsReauthMaxAgeSeconds = 3600
)

// ProjectRecoveryEmailsConfig is a project's policy for the additional
// addresses its accounts may prove and keep. Default OFF: a project that
// configures none refuses RequestRecoveryEmail and VerifyRecoveryEmail.
// Turning it off later keeps the addresses already held, which their owners
// can still list and remove.
type ProjectRecoveryEmailsConfig struct {
	// Enabled lets a signed-in user add recovery emails.
	Enabled bool `json:"enabled"`
	// Max caps the recovery emails one account holds. 0 selects 5; at most 20.
	Max int `json:"max"`
	// ReauthMaxAgeSeconds bounds how long ago the caller may have signed in
	// to add or remove an address. 0 selects 900; at most 3600. The check
	// cannot be turned off.
	ReauthMaxAgeSeconds int `json:"reauth_max_age_seconds"`
}

func (c ProjectRecoveryEmailsConfig) validate() error {
	if c.Max < 0 || c.Max > maxRecoveryEmailsMax {
		return fmt.Errorf("%w: recovery_emails.max must be between 0 and %d (0 selects %d)",
			ErrInvalidArgument, maxRecoveryEmailsMax, defaultRecoveryEmailsMax)
	}
	if c.ReauthMaxAgeSeconds < 0 || c.ReauthMaxAgeSeconds > maxRecoveryEmailsReauthMaxAgeSeconds {
		return fmt.Errorf("%w: recovery_emails.reauth_max_age_seconds must be between 0 and %d (0 selects %d)",
			ErrInvalidArgument, maxRecoveryEmailsReauthMaxAgeSeconds, defaultRecoveryEmailsReauthMaxAgeSeconds)
	}
	return nil
}

func (c ProjectRecoveryEmailsConfig) max() int {
	if c.Max > 0 {
		return c.Max
	}
	return defaultRecoveryEmailsMax
}

func (c ProjectRecoveryEmailsConfig) reauthMaxAge() time.Duration {
	if c.ReauthMaxAgeSeconds > 0 {
		return time.Duration(c.ReauthMaxAgeSeconds) * time.Second
	}
	return defaultRecoveryEmailsReauthMaxAgeSeconds * time.Second
}

// recoveryEmailsConfig is the request's project's recovery-email policy; the
// zero (disabled) policy when the request carries no project scope.
func recoveryEmailsConfig(scope *ProjectScope) ProjectRecoveryEmailsConfig {
	if scope == nil {
		return ProjectRecoveryEmailsConfig{}
	}
	return scope.RecoveryEmails
}
