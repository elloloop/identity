package service

import (
	"context"

	"github.com/elloloop/identity/internal/config"

	"go.uber.org/zap"
)

// enforceProjectAccessSignup gates a SELF-SIGNUP (account-creation) attempt
// against the resolved project's access policy. In invite mode self-signup is
// DENIED (its distinguishing behavior); open permits, closed/unset deny, and
// allowlist permits only a listed email — and whatever the mode admits, the
// project's deny layer then subtracts from (ProjectAccessConfig.denies), so
// "open" is not by itself a guarantee of admission.
func (s *AuthService) enforceProjectAccessSignup(ctx context.Context, email canonicalEmail) error {
	return s.enforceProjectAccess(ctx, email, true)
}

// enforceProjectAccessLogin gates a LOGIN or invitation acceptance by an
// already-provisioned user against the resolved project's access policy. In
// invite mode it PERMITS (an existing/invited user gets in) — the only mode
// where it diverges from the signup guard; open permits, closed/unset deny, and
// allowlist permits only a listed email. The deny layer then subtracts from
// whatever the mode admitted, on login exactly as on signup.
func (s *AuthService) enforceProjectAccessLogin(ctx context.Context, email canonicalEmail) error {
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
// The matrix is only the first half. Whatever it admits, the project's deny
// layer then subtracts from — see ProjectAccessConfig.denies — so a "permit"
// above means "not refused by the mode", not "admitted".
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
// The email is a canonicalEmail — canonicalized exactly once by the caller (the
// type makes a raw string a compile error here), so every entry point compares
// like-against-like regardless of how far each path had normalized the address,
// with no redundant re-canonicalization on the auth hot path. Denials are
// generic and account-agnostic (anti-enumeration): they reveal neither account
// existence nor the allowlist's contents; a self-signup blocked by invite mode
// returns ErrSignupByInvitationOnly, every other denial returns
// ErrAccessNotAllowed.
func (s *AuthService) enforceProjectAccess(ctx context.Context, email canonicalEmail, isSignup bool) error {
	scope := ProjectScopeFromContext(ctx)
	if scope == nil {
		return nil
	}
	access := scope.Access
	if accessPermits(s.cfg, access, email, isSignup) {
		return nil
	}
	// Name WHICH half refused. With a deny layer configured, a refusal on an
	// open project logs mode=open beside a denial, which reads as a
	// contradiction and sends the operator to the wrong config field — the
	// allowlist-composition case is worse still, where the mode admitted the
	// address and only the deny layer refused it.
	s.logger.Info("project_access_denied",
		zap.String("project_id", s.projectID(ctx)),
		zap.String("mode", access.mode()),
		zap.Bool("deny_layer", access.denies(s.cfg, email)),
		zap.Bool("signup", isSignup),
		zap.String("email_domain", emailDomain(string(email))))
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
func (s *AuthService) accessAllowsCodeSend(ctx context.Context, email canonicalEmail) bool {
	scope := ProjectScopeFromContext(ctx)
	if scope == nil {
		return true
	}
	// A denied address must not receive credential mail either — otherwise a
	// blocked domain still costs SMTP reputation and tells the recipient the
	// project knows them.
	if scope.Access.denies(s.cfg, email) {
		return false
	}
	switch scope.Access.mode() {
	case AccessModeOpen:
		return true
	case AccessModeAllowlist:
		return scope.Access.permits(email)
	case AccessModeInvite:
		// The existence check uses the same canonical key accounts are stored
		// under — otherwise a real user requesting with non-canonical casing/dots
		// would miss and have their OTP silently dropped. The caller canonicalized
		// once; the type carries that guarantee here. Mirrors the allowlist branch.
		return s.userExists(ctx, email)
	default:
		// AccessModeClosed and any unset/unrecognized mode: never send.
		return false
	}
}

// userExists treats a lookup error as "does not exist" so the caller fails
// closed on the DB-error path rather than admitting a send as though an account
// were present.
func (s *AuthService) userExists(ctx context.Context, email canonicalEmail) bool {
	u, err := s.repo(ctx).FindUserByEmail(ctx, string(email))
	if err != nil {
		s.logger.Warn("access_send_user_lookup_failed", zap.Error(err))
		return false
	}
	return u != nil
}

// accessPermits applies the mode matrix and then the deny layer to a single
// (email, context) pair. It is
// a pure decision function (no I/O) so it is unit-testable in isolation. The
// email is already canonical (the type enforces it), so it never re-normalizes.
func accessPermits(cfg *config.Config, access ProjectAccessConfig, email canonicalEmail, isSignup bool) bool {
	if !modeAdmits(access, email, isSignup) {
		return false
	}
	// The deny layer subtracts from whatever the mode admitted, and runs on
	// BOTH signup and login. Gating only signup would leave the restriction
	// permanently half-applied: a project that switches to work-email-only
	// keeps authenticating every consumer address that registered before the
	// switch, with no path to convergence. This mirrors the allowlist, which
	// has always gated login as well as signup.
	return !access.denies(cfg, email)
}

// modeAdmits applies the mode matrix alone — the "who may enter" half, before
// the deny layer subtracts from it.
func modeAdmits(access ProjectAccessConfig, email canonicalEmail, isSignup bool) bool {
	switch access.mode() {
	case AccessModeOpen:
		return true
	case AccessModeAllowlist:
		return access.permits(email)
	case AccessModeInvite:
		// Self-signup is the one thing invite-only forbids; login and invitation
		// acceptance (isSignup=false) are how an invited user gets in.
		return !isSignup
	default:
		// AccessModeClosed and any unset/unrecognized mode: default-DENY.
		return false
	}
}
