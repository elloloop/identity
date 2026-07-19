package service

import (
	"context"

	"go.uber.org/zap"
)

// enforceProjectAccessSignup gates a SELF-SIGNUP (account-creation) attempt
// against the resolved project's access mode. In invite mode self-signup is
// DENIED (its distinguishing behavior); open permits, closed/unset deny, and
// allowlist permits only a listed email.
func (s *AuthService) enforceProjectAccessSignup(ctx context.Context, email string) error {
	return s.enforceProjectAccess(ctx, email, true)
}

// enforceProjectAccessLogin gates a LOGIN or invitation acceptance by an
// already-provisioned user against the resolved project's access mode. In invite
// mode it PERMITS (an existing/invited user gets in) — the only mode where it
// diverges from the signup guard; open permits, closed/unset deny, and allowlist
// permits only a listed email.
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

// accessAllowsCodeSend reports whether a request-phase LOGIN credential email (a
// passwordless OTP or magic link) may be dispatched to email under the resolved
// project's access mode. It exists for the login endpoints that must stay
// enumeration-safe: a fail-fast denial there would leak account existence, so
// instead the send is silently skipped while the response is unchanged, and the
// authoritative deny happens at redemption. (Self-signup endpoints do not use
// this — they fail fast, since their access check is DB-free and leaks nothing.)
//
// It gates spam/SMTP-abuse — a closed or off-list allowlist project must not
// emit credential mail to arbitrary addresses. Invite mode may send only to an
// already-provisioned user, because self-signup is denied at redemption anyway
// and an OTP to a stranger would be undeliverable spam.
//
// It fails CLOSED: no permit → no send, and a user-existence lookup error also
// suppresses the send.
func (s *AuthService) accessAllowsCodeSend(ctx context.Context, email string) bool {
	scope := ProjectScopeFromContext(ctx)
	if scope == nil {
		return true
	}
	switch scope.Access.mode() {
	case AccessModeOpen:
		return true
	case AccessModeAllowlist:
		return scope.Access.permits(canonicalizeEmail(email))
	case AccessModeInvite:
		return s.userExists(ctx, email)
	default:
		// AccessModeClosed and any unset/unrecognized mode: never send.
		return false
	}
}

// userExists treats a lookup error as "does not exist" so the caller fails
// closed on the DB-error path rather than admitting a send as though an account
// were present.
func (s *AuthService) userExists(ctx context.Context, email string) bool {
	u, err := s.repo(ctx).FindUserByEmail(ctx, email)
	if err != nil {
		s.logger.Warn("access_send_user_lookup_failed", zap.Error(err))
		return false
	}
	return u != nil
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
