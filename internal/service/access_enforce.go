package service

import (
	"context"

	"go.uber.org/zap"
)

// enforceProjectAccessSignup gates a SELF-SIGNUP (account-creation) attempt
// against the resolved project's access mode. It is the guard the by-email
// creation chokepoints call: PasswordSignup, CompletePasskeySignup, and the
// create branch of resolveOrCreateUserByEmail (OAuth/native/passwordless JIT).
//
// In invite mode self-signup is DENIED (the distinguishing behavior of that
// mode) while login and invitation acceptance are still allowed.
func (s *AuthService) enforceProjectAccessSignup(ctx context.Context, email string) error {
	return s.enforceProjectAccess(ctx, email, true)
}

// enforceProjectAccessLogin gates a LOGIN (or invitation acceptance) by an
// already-provisioned user against the resolved project's access mode. It is
// the guard every login-completion path calls (password, oauth + native oauth
// fast path, passwordless/OTP, passkey assertion), the resolve-existing branch
// of resolveOrCreateUserByEmail, and AcceptInvitation.
//
// In invite mode this PERMITS (an existing/invited user gets in); it differs
// from the signup guard only there — every other mode behaves identically for
// both contexts.
func (s *AuthService) enforceProjectAccessLogin(ctx context.Context, email string) error {
	return s.enforceProjectAccess(ctx, email, false)
}

// enforceProjectAccess is the shared core. It reads the resolved project's
// access mode off the request scope and decides whether email may proceed in
// the given context (isSignup selects self-signup vs login/invite semantics).
//
// The mode matrix:
//
//	mode        self-signup          login / invitation-accept
//	open        permit               permit
//	allowlist   permit iff on list   permit iff on list
//	invite      DENY                 permit
//	closed      DENY                 DENY
//	unset/other DENY                 DENY   (default-DENY, fail-closed)
//
// Scope resolution and fail direction:
//   - No scope in context (a direct service call, or a deployment with neither
//     a control plane nor a default project) imposes NO gate — there is no
//     project to gate against. In a served deployment the project-resolution
//     middleware ALWAYS injects a scope (a resolved project, or the default
//     project pinned with its env-configured access mode), so this nil case is
//     not a production auth path.
//   - A scope WITH an unset/empty/unrecognized mode DENIES. This is the
//     default-DENY inversion: a project (or the env default project) that was
//     never explicitly opened cannot authenticate anyone. A malformed access
//     block never reaches here as "open" — ParseProjectConfig rejects it and the
//     resolver refuses the project.
//
// The email is canonicalized here rather than trusting the caller, so every
// entry point compares like-against-like regardless of how far each path had
// normalized the address. Denials are generic and account-agnostic
// (anti-enumeration): they reveal neither account existence nor the allowlist's
// contents; a self-signup blocked by invite mode returns ErrSignupByInvitationOnly,
// every other denial returns ErrAccessNotAllowed.
func (s *AuthService) enforceProjectAccess(ctx context.Context, email string, isSignup bool) error {
	scope := ProjectScopeFromContext(ctx)
	if scope == nil {
		return nil
	}
	access := scope.Access
	if accessPermits(access, email, isSignup) {
		return nil
	}
	s.logger.Info("project_access_denied",
		zap.String("project_id", s.projectID(ctx)),
		zap.String("mode", access.mode()),
		zap.Bool("signup", isSignup),
		zap.String("email_domain", emailDomain(canonicalizeEmail(email))))
	if isSignup && access.mode() == AccessModeInvite {
		return ErrSignupByInvitationOnly
	}
	return ErrAccessNotAllowed
}

// accessPermits applies the mode matrix to a single (email, context) pair. It is
// a pure decision function (no I/O) so it is unit-testable in isolation.
func accessPermits(access ProjectAccessConfig, email string, isSignup bool) bool {
	switch access.mode() {
	case AccessModeOpen:
		return true
	case AccessModeAllowlist:
		return access.permits(canonicalizeEmail(email))
	case AccessModeInvite:
		// Self-signup is the one thing invite-only forbids; login and invitation
		// acceptance (isSignup=false) are how an invited user gets in.
		return !isSignup
	default:
		// AccessModeClosed and any unset/unrecognized mode: default-DENY.
		return false
	}
}
