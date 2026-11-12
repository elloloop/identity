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
	// defaultRecoveryHoldSeconds is how long a sign-in by a recovery email
	// holds the account's recovery settings when the project sets no length:
	// seven days, time for the owner to read the notice and act.
	defaultRecoveryHoldSeconds = 7 * 24 * 60 * 60
	// maxRecoveryHoldSeconds bounds the hold at thirty days: past that it
	// locks the owner out of their own settings more than it protects them.
	maxRecoveryHoldSeconds = 30 * 24 * 60 * 60
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
	// SignIn lets an emailed code or link sent to a recovery email sign in
	// to the account that holds it. Default OFF: such an address then signs
	// in to nothing and is refused like a wrong code.
	SignIn bool `json:"sign_in"`
	// HoldSeconds is how long after a sign-in by a recovery email the
	// account may not remove a recovery email or change its phone number.
	// 0 selects 604800 (seven days); at most 2592000. It cannot be turned
	// off.
	HoldSeconds int `json:"hold_seconds"`
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
	if c.HoldSeconds < 0 || c.HoldSeconds > maxRecoveryHoldSeconds {
		return fmt.Errorf("%w: recovery_emails.hold_seconds must be between 0 and %d (0 selects %d)",
			ErrInvalidArgument, maxRecoveryHoldSeconds, defaultRecoveryHoldSeconds)
	}
	return nil
}

func (c ProjectRecoveryEmailsConfig) hold() time.Duration {
	if c.HoldSeconds > 0 {
		return time.Duration(c.HoldSeconds) * time.Second
	}
	return defaultRecoveryHoldSeconds * time.Second
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
