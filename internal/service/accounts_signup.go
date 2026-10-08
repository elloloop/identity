package service

import (
	"fmt"
	"strings"
)

// Who creates a project's accounts of one kind (ProjectAccountsConfig's
// EmailSignup / UsernameSignup). The kinds are independent: a consumer
// product keeps email self-signup and leaves usernames off; a workplace sets
// email "off" and usernames "admin", so every account is one its admins made,
// with an address on the project's domain.
const (
	// SignupSelf lets a person create their own account of this kind.
	SignupSelf = "self"
	// SignupAdmin lets only a project admin create accounts of this kind.
	// People sign in to the accounts an admin made; self-signup is refused
	// with ErrSignupByInvitationOnly.
	SignupAdmin = "admin"
	// SignupOff means the project has no accounts of this kind to create:
	// self-signup and admin creation are both refused. Accounts of the kind
	// that already exist keep signing in.
	SignupOff = "off"
)

func canonicalSignupMode(mode string) string {
	return strings.ToLower(strings.TrimSpace(mode))
}

func validateSignupMode(field, mode string) error {
	switch canonicalSignupMode(mode) {
	case "", SignupSelf, SignupAdmin, SignupOff:
		return nil
	}
	return fmt.Errorf("%s: %q is not one of %q, %q or %q", field, mode, SignupSelf, SignupAdmin, SignupOff)
}

// EmailAccountsOff reports whether the project has turned email accounts off
// (accounts.email_signup "off"): no one, person or admin, creates one. The
// SCIM store, outside this package, refuses provisioning by it.
func (a ProjectAccountsConfig) EmailAccountsOff() bool {
	return a.emailSignup() == SignupOff
}

// emailSignup is who creates email accounts. Unset means "self", so a project
// that configures nothing keeps today's email self-signup.
func (a ProjectAccountsConfig) emailSignup() string {
	if m := canonicalSignupMode(a.EmailSignup); m != "" {
		return m
	}
	return SignupSelf
}

// usernameSignup is who creates username accounts. Unset means "off": a
// project gains username accounts only by choosing them.
func (a ProjectAccountsConfig) usernameSignup() string {
	if m := canonicalSignupMode(a.UsernameSignup); m != "" {
		return m
	}
	return SignupOff
}

// accountsFor returns the request's project account policy, or the zero
// policy (email self-signup, no usernames, no domain) when no project is in
// scope — the same "no scope imposes no gate" rule as the access guard.
func accountsFor(scope *ProjectScope) ProjectAccountsConfig {
	if scope == nil {
		return ProjectAccountsConfig{}
	}
	return scope.Accounts
}

// selfSignupRefusal is the refusal a person gets for creating their own
// account of a kind whose mode is mode: none under "self", invitation-only
// under "admin", and ErrAccountKindOff under "off".
func selfSignupRefusal(mode string) error {
	switch mode {
	case SignupSelf:
		return nil
	case SignupAdmin:
		return ErrSignupByInvitationOnly
	default:
		return ErrAccountKindOff
	}
}
