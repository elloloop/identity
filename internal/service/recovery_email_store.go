package service

import "errors"

// RecoveryEmail is an additional address an account has proved it controls.
// Within a project an address is held once: as one account's primary email
// or as one account's recovery email, never both and never by two accounts.
type RecoveryEmail struct {
	UserID string
	// Email is the canonical address (canonicalMailbox), unique under
	// FoldEmail like a primary email.
	Email      string
	VerifiedAt int64 // epoch ms
}

// RecoveryEmailCodeRecord is the emailed code that proves a recovery address
// before it is stored. It is keyed by UserID (at most one live code per
// account); a new request overwrites the previous one. CodeHash is sha256 of
// the 6-digit code. AttemptCount tracks failed verifies; once it reaches
// MaxAttempts the code is invalidated.
type RecoveryEmailCodeRecord struct {
	NodeID       string
	UserID       string
	Email        string
	CodeHash     string
	ExpiresAt    int64 // epoch ms
	CreatedAt    int64 // epoch ms
	ConsumedAt   int64 // epoch ms; 0 = unconsumed
	AttemptCount int64
	MaxAttempts  int64
}

var (
	// ErrRecoveryEmailsDisabled is returned by the recovery-email RPCs when
	// the caller's project has not turned them on (recovery_emails.enabled).
	// Mapped to CodeFailedPrecondition.
	ErrRecoveryEmailsDisabled = errors.New("this project does not keep recovery emails")
	// ErrRecoveryReauthenticationRequired is returned by the calls that
	// change an account's recovery settings when the caller's session was not
	// opened by a sign-in within the project's
	// recovery_emails.reauth_max_age_seconds. Mapped to
	// CodeFailedPrecondition; its message leads with the stable
	// `reauthentication_required` token clients match on to sign the user in
	// again and retry, as ErrReauthenticationRequired's does.
	ErrRecoveryReauthenticationRequired = errors.New("reauthentication_required: sign in again to change your recovery settings")
	// ErrRecoveryEmailCodeInvalid is returned when a recovery-email code is
	// missing, expired, already consumed, the wrong code, sent to another
	// address, or has exhausted its attempt budget. Mapped to
	// CodeUnauthenticated, one answer for every case.
	ErrRecoveryEmailCodeInvalid = errors.New("recovery email code is invalid or expired")
	// ErrRecoveryEmailTaken is returned when the address is already an
	// account's primary or recovery email in the project. It is only ever
	// returned to a caller who proved control of the address. Mapped to
	// CodeAlreadyExists.
	ErrRecoveryEmailTaken = errors.New("that address already belongs to an account")
	// ErrRecoveryEmailLimit is returned when the account already holds the
	// project's cap of recovery emails (recovery_emails.max). Mapped to
	// CodeResourceExhausted.
	ErrRecoveryEmailLimit = errors.New("this account has the most recovery emails it may hold")
)
