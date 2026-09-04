package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/elloloop/identity/pkg/agegate"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// ── Parental account management ─────────────────────────────────────────
//
// The guardian-authorized management surface over a child account: the
// day-to-day operations a parent owns once they created (or consented for)
// the account — read the profile, set the password, change the username, cut
// the sessions, deactivate, reactivate, erase. None of them requires the
// child's own credentials (a parent typing a young child's password teaches
// exactly the wrong habit) and none requires an admin credential (no parent
// has one, and none should).
//
// Every operation passes through ONE guard, authorizeGuardianAction, rather
// than re-implementing the checks per RPC — so an operation added later is
// gated by construction. The guard requires BOTH:
//
//  1. an ACTIVE guardianOf EDGE from the caller to the child. The caller is
//     the authenticated session user, never a request field. Revoking
//     parental consent deletes the edge, so revocation takes effect on the
//     very next call: no cached authorization, no grace period.
//  2. a STEP-UP RE-AUTHENTICATION at the moment of action — the same bar
//     GrantParentalConsent sets, for the same reason: a stolen session token
//     must not be enough to take over a child's account.
//
// A caller with no edge is refused with an account-agnostic
// ErrPermissionDenied — identical whether or not the child account exists,
// so the surface is not an enumeration oracle over children.

// ErrGuardianRightsExpired is returned when the target of a guardian
// management operation has aged past the adult threshold that applies to it.
// A guardian edge to an adult confers no management rights: an adult's
// account is their own. Mapped to CodeFailedPrecondition.
var ErrGuardianRightsExpired = errors.New("the managed account has reached the adult age band; guardian management rights no longer apply")

// guardianOperation is one guardian-authorized management operation, named by
// the audit event it emits on success AND on refusal. The refusal detail says
// which check failed; the event type already says which operation it was.
type guardianOperation struct {
	event audit.EventType
}

var (
	guardianOpViewProfile    = guardianOperation{audit.EventGuardianChildProfileViewed}
	guardianOpSetPassword    = guardianOperation{audit.EventGuardianChildPasswordSet}
	guardianOpSetUsername    = guardianOperation{audit.EventGuardianChildUsernameChanged}
	guardianOpRevokeSessions = guardianOperation{audit.EventGuardianChildSessionsRevoked}
	guardianOpDeactivate     = guardianOperation{audit.EventGuardianChildDeactivated}
	guardianOpReactivate     = guardianOperation{audit.EventGuardianChildReactivated}
	guardianOpDeleteChild    = guardianOperation{audit.EventGuardianChildDeleted}

	// guardianRefusalNotAllowed is the ONE message every non-guardian refusal
	// carries, whether the child exists or not.
	guardianRefusalNotAllowed = "caller is not a guardian of this account"
)

// auditGuardianAction records one guardian management operation. Refusals
// carry the failing step so probing a child account is as visible in the
// trail as managing one.
func (s *AuthService) auditGuardianAction(
	ctx context.Context, op guardianOperation, guardianUserID, childUserID string, ok bool, ip, userAgent string, details map[string]any,
) {
	opts := []audit.Option{
		audit.WithActor(guardianUserID), audit.WithTarget(childUserID),
		audit.WithIP(ip), audit.WithUserAgent(userAgent), audit.WithSuccess(ok),
	}
	if len(details) > 0 {
		opts = append(opts, audit.WithDetails(details))
	}
	s.audit.Log(ctx, op.event, opts...)
}

// stepUp is the one guardian step-up rule. admitted is whether the caller may
// proceed; reauthenticated is whether they actually proved a password, which
// the consent record persists as evidence and so must never be inferred from
// admitted alone. The two differ only under GuardianStepUpAllowNoPassword,
// which admits an account holding no password hash without any proof — an
// account that does hold a hash must still present the matching password.
func (s *AuthService) stepUp(user *User, stepUpPassword string) (admitted, reauthenticated bool) {
	if user.PasswordHash == "" {
		return s.cfg.GuardianStepUpAllowNoPassword, false
	}
	ok := stepUpPassword != "" && passwords.Verify(stepUpPassword, user.PasswordHash)
	return ok, ok
}

// authorizeGuardianAction is the single chokepoint every guardian management
// operation passes through. It returns the guardian and the child on
// success; on refusal it audits the failing step and returns the error the
// caller propagates unchanged.
//
// The order of checks is deliberate. The edge lookup runs first and keys on
// (caller, child) without touching the users table, so a stranger probing a
// child id — real or invented — gets the identical ErrPermissionDenied and
// learns nothing. Only a caller who already holds the edge reaches the
// step-up check, and only a stepped-up guardian reaches the band check.
func (s *AuthService) authorizeGuardianAction(
	ctx context.Context, op guardianOperation, guardianUserID, childUserID, stepUpPassword, ip, userAgent string,
) (*User, *User, error) {
	if guardianUserID == "" {
		return nil, nil, ErrUnauthenticated
	}
	childUserID = strings.TrimSpace(childUserID)
	if childUserID == "" {
		return nil, nil, fmt.Errorf("%w: child_user_id is required", ErrInvalidArgument)
	}
	repo := s.repo(ctx)

	// (1) The guardian edge. Its absence is the account-agnostic denial.
	edge, err := repo.GetGuardianEdge(ctx, guardianUserID, childUserID)
	if err != nil {
		return nil, nil, fmt.Errorf("check guardian edge: %w", err)
	}
	if edge == nil {
		s.auditGuardianAction(ctx, op, guardianUserID, childUserID, false, ip, userAgent,
			map[string]any{"step": "not_guardian"})
		return nil, nil, fmt.Errorf("%w: %s", ErrPermissionDenied, guardianRefusalNotAllowed)
	}

	guardian, err := repo.GetUser(ctx, guardianUserID)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch guardian: %w", err)
	}
	// An edge whose guardian account no longer exists authorizes nothing, and
	// the refusal stays account-agnostic.
	if guardian == nil {
		s.auditGuardianAction(ctx, op, guardianUserID, childUserID, false, ip, userAgent,
			map[string]any{"step": "not_guardian"})
		return nil, nil, fmt.Errorf("%w: %s", ErrPermissionDenied, guardianRefusalNotAllowed)
	}
	if !isActiveConsentingAccount(guardian.Status) {
		s.auditGuardianAction(ctx, op, guardianUserID, childUserID, false, ip, userAgent,
			map[string]any{"step": "guardian_inactive"})
		return nil, nil, ErrAccountNotActive
	}

	// (2) Step-up re-authentication, verified before any state change.
	if admitted, _ := s.stepUp(guardian, stepUpPassword); !admitted {
		s.auditGuardianAction(ctx, op, guardianUserID, childUserID, false, ip, userAgent,
			map[string]any{"step": "step_up"})
		return nil, nil, ErrParentalConsentStepUpFailed
	}

	child, err := repo.GetUser(ctx, childUserID)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch managed child: %w", err)
	}
	if child == nil {
		// The FK cascade removes edges with the account; a stale edge
		// authorizes nothing and discloses nothing.
		s.auditGuardianAction(ctx, op, guardianUserID, childUserID, false, ip, userAgent,
			map[string]any{"step": "not_guardian"})
		return nil, nil, fmt.Errorf("%w: %s", ErrPermissionDenied, guardianRefusalNotAllowed)
	}

	// (3) Scope: minors only. The band is re-derived on every call — no
	// cached authorization — so rights lapse on the birthday itself. Only a
	// DEFINITIVE adult band refuses: an unknown band (no date of birth on
	// file, or the age gate off) leaves the edge as the authority, which is
	// the same "unknown age passes" posture the product age gate takes.
	if dec := s.determinerForUser(ctx, child).Determine(child.DateOfBirthMs, s.nowFunc()); dec.Band == agegate.BandAdult {
		s.auditGuardianAction(ctx, op, guardianUserID, childUserID, false, ip, userAgent,
			map[string]any{"step": "aged_out"})
		return nil, nil, ErrGuardianRightsExpired
	}

	return guardian, child, nil
}

// GetManagedChildProfile returns the managed child's stored account record.
// Nothing is added to what is stored: a COPPA-protected child's record
// deliberately holds very little (minor data-minimization suppresses the
// optional PII at every write path), and the guardian sees exactly that.
func (s *AuthService) GetManagedChildProfile(
	ctx context.Context, guardianUserID, childUserID, stepUpPassword, ip, userAgent string,
) (*User, error) {
	_, child, err := s.authorizeGuardianAction(ctx, guardianOpViewProfile, guardianUserID, childUserID, stepUpPassword, ip, userAgent)
	if err != nil {
		return nil, err
	}
	s.stampAgeBand(ctx, child)
	s.auditGuardianAction(ctx, guardianOpViewProfile, guardianUserID, child.ID, true, ip, userAgent, nil)
	return child, nil
}

// SetManagedChildPassword sets the child's password directly — no email
// round-trip, because a managed child account may have no email of its own.
// The new password is validated against the same policy the self-service
// paths enforce, and the child's sessions are cut so a device the guardian
// is locking out cannot keep using an old token.
func (s *AuthService) SetManagedChildPassword(
	ctx context.Context, guardianUserID, childUserID, newPassword, stepUpPassword, ip, userAgent string,
) error {
	_, child, err := s.authorizeGuardianAction(ctx, guardianOpSetPassword, guardianUserID, childUserID, stepUpPassword, ip, userAgent)
	if err != nil {
		return err
	}
	// The username stands in for the email in the policy's
	// identifier-similarity check, exactly as at account creation.
	if err := s.validatePasswordStrengthForEmail(ctx, child.Username, newPassword); err != nil {
		return err
	}
	hash, err := passwords.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}
	now := s.nowMs()
	repo := s.repo(ctx)
	if err := repo.UpdateUser(ctx, child.ID, map[string]any{
		"password_hash": hash,
		"updated_at":    now,
		// Clear the lockout with the credential, exactly as the self-service
		// ResetPassword does: whoever tripped it is usually the person the
		// new password is for, and this is the ONLY recovery path an
		// email-less managed child has — leaving the lockout would keep the
		// account unusable behind a password that is already correct.
		"failed_login_count": 0,
		"locked_until":       int64(0),
	}); err != nil {
		return fmt.Errorf("set managed child password: %w", err)
	}
	if err := revokeAllUserSessions(ctx, repo, child.ID, now); err != nil {
		return fmt.Errorf("set managed child password: %w", err)
	}
	s.auditGuardianAction(ctx, guardianOpSetPassword, guardianUserID, child.ID, true, ip, userAgent, nil)
	return nil
}

// SetManagedChildUsername changes the child's project-unique handle. Format
// and uniqueness are the ones CreateManagedChildAccount enforces — one rule,
// one implementation. A duplicate is ErrAlreadyExists whether the
// pre-check or the storage unique index catches it.
func (s *AuthService) SetManagedChildUsername(
	ctx context.Context, guardianUserID, childUserID, username, stepUpPassword, ip, userAgent string,
) (*User, error) {
	_, child, err := s.authorizeGuardianAction(ctx, guardianOpSetUsername, guardianUserID, childUserID, stepUpPassword, ip, userAgent)
	if err != nil {
		return nil, err
	}
	username = normalizeUsername(username)
	if err := validateUsernameFormat(username); err != nil {
		return nil, err
	}
	repo := s.repo(ctx)
	if username == child.Username {
		// Idempotent: the handle is already this account's.
		s.stampAgeBand(ctx, child)
		s.auditGuardianAction(ctx, guardianOpSetUsername, guardianUserID, child.ID, true, ip, userAgent,
			map[string]any{"username": username, "unchanged": true})
		return child, nil
	}
	existing, err := repo.FindUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("check username: %w", err)
	}
	if existing != nil {
		s.auditGuardianAction(ctx, guardianOpSetUsername, guardianUserID, child.ID, false, ip, userAgent,
			map[string]any{"step": "duplicate_username"})
		return nil, fmt.Errorf("%w: username %q is already taken", ErrAlreadyExists, username)
	}

	previous := child.Username
	now := s.nowMs()
	if err := repo.UpdateUser(ctx, child.ID, map[string]any{
		"username":   username,
		"updated_at": now,
	}); err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			// A racing create/rename won the unique index.
			s.auditGuardianAction(ctx, guardianOpSetUsername, guardianUserID, child.ID, false, ip, userAgent,
				map[string]any{"step": "duplicate_username"})
			return nil, fmt.Errorf("%w: username %q is already taken", ErrAlreadyExists, username)
		}
		return nil, fmt.Errorf("set managed child username: %w", err)
	}
	child.Username = username
	child.UpdatedAt = msToTime(now)
	s.stampAgeBand(ctx, child)
	s.auditGuardianAction(ctx, guardianOpSetUsername, guardianUserID, child.ID, true, ip, userAgent,
		map[string]any{"previous_username": previous, "username": username})
	return child, nil
}

// RevokeManagedChildSessions invalidates every session and refresh token of
// the child immediately — the lost-tablet case. A revoked session cannot
// refresh: the refresh tokens are deleted, not merely expired.
func (s *AuthService) RevokeManagedChildSessions(
	ctx context.Context, guardianUserID, childUserID, stepUpPassword, ip, userAgent string,
) error {
	_, child, err := s.authorizeGuardianAction(ctx, guardianOpRevokeSessions, guardianUserID, childUserID, stepUpPassword, ip, userAgent)
	if err != nil {
		return err
	}
	if err := revokeAllUserSessions(ctx, s.repo(ctx), child.ID, s.nowMs()); err != nil {
		return fmt.Errorf("revoke managed child sessions: %w", err)
	}
	s.auditGuardianAction(ctx, guardianOpRevokeSessions, guardianUserID, child.ID, true, ip, userAgent, nil)
	return nil
}

// DeactivateManagedChildAccount suspends the child's account and cuts its
// access at once. It is reversible by the same guardian via
// ReactivateManagedChildAccount. Deactivating an already-deactivated account
// is a no-op; an account in any other non-active state (awaiting parental
// consent, pending deletion) is refused rather than having its state machine
// overwritten.
func (s *AuthService) DeactivateManagedChildAccount(
	ctx context.Context, guardianUserID, childUserID, reason, stepUpPassword, ip, userAgent string,
) error {
	_, child, err := s.authorizeGuardianAction(ctx, guardianOpDeactivate, guardianUserID, childUserID, stepUpPassword, ip, userAgent)
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(child.Status)) {
	case StatusDeactivated:
		// Already deactivated — but the status write and the session cut are
		// separate statements, so a first attempt can have stored the status
		// and then failed to revoke. Re-run the revocation (it is idempotent)
		// rather than reporting success on a child whose old token still
		// works: session-mode auth reads the session row, not the status.
		if err := revokeAllUserSessions(ctx, s.repo(ctx), child.ID, s.nowMs()); err != nil {
			return fmt.Errorf("deactivate managed child account: %w", err)
		}
		s.auditGuardianAction(ctx, guardianOpDeactivate, guardianUserID, child.ID, true, ip, userAgent,
			map[string]any{"reason": reason, "unchanged": true})
		return nil
	case "", StatusActive:
		// eligible — fall through
	default:
		s.auditGuardianAction(ctx, guardianOpDeactivate, guardianUserID, child.ID, false, ip, userAgent,
			map[string]any{"step": "child_status", "status": child.Status})
		return fmt.Errorf("%w: account is %s", ErrAccountNotActive, child.Status)
	}

	now := s.nowMs()
	repo := s.repo(ctx)
	if err := repo.UpdateUser(ctx, child.ID, map[string]any{
		"status":     StatusDeactivated,
		"updated_at": now,
	}); err != nil {
		return fmt.Errorf("deactivate managed child account: %w", err)
	}
	if err := revokeAllUserSessions(ctx, repo, child.ID, now); err != nil {
		return fmt.Errorf("deactivate managed child account: %w", err)
	}
	s.auditGuardianAction(ctx, guardianOpDeactivate, guardianUserID, child.ID, true, ip, userAgent,
		map[string]any{"reason": reason})
	return nil
}

// ReactivateManagedChildAccount returns a guardian-deactivated child account
// to active. It refuses to move an account out of
// pending_parental_consent — the only valid exit from that state is
// GrantParentalConsent, so reactivation can never bypass the consent gate
// (the same rule the admin reactivation path enforces).
func (s *AuthService) ReactivateManagedChildAccount(
	ctx context.Context, guardianUserID, childUserID, stepUpPassword, ip, userAgent string,
) error {
	_, child, err := s.authorizeGuardianAction(ctx, guardianOpReactivate, guardianUserID, childUserID, stepUpPassword, ip, userAgent)
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(child.Status)) {
	case "", StatusActive:
		s.auditGuardianAction(ctx, guardianOpReactivate, guardianUserID, child.ID, true, ip, userAgent,
			map[string]any{"unchanged": true})
		return nil
	case StatusDeactivated:
		// eligible — fall through
	case StatusPendingParentalConsent:
		s.auditGuardianAction(ctx, guardianOpReactivate, guardianUserID, child.ID, false, ip, userAgent,
			map[string]any{"step": "child_status", "status": child.Status})
		return ErrParentalConsentRequired
	default:
		s.auditGuardianAction(ctx, guardianOpReactivate, guardianUserID, child.ID, false, ip, userAgent,
			map[string]any{"step": "child_status", "status": child.Status})
		return fmt.Errorf("%w: account is %s", ErrAccountNotActive, child.Status)
	}

	if err := s.repo(ctx).UpdateUser(ctx, child.ID, map[string]any{
		"status":     StatusActive,
		"updated_at": s.nowMs(),
	}); err != nil {
		return fmt.Errorf("reactivate managed child account: %w", err)
	}
	s.auditGuardianAction(ctx, guardianOpReactivate, guardianUserID, child.ID, true, ip, userAgent, nil)
	return nil
}

// DeleteManagedChildAccount erases the child account — the parent exercising
// the right to erasure on their child's behalf. It runs the SAME hard-delete
// cascade as the admin DeleteUser RPC and the account-deletion sweeper (the
// injected AccountPurger), so the three can never drift: sessions and refresh
// tokens die first, then the account and its owned records. The parental
// consent record and the audit trail survive by design — they are the
// evidence that the consent, and this erasure, happened.
func (s *AuthService) DeleteManagedChildAccount(
	ctx context.Context, guardianUserID, childUserID, stepUpPassword, ip, userAgent string,
) error {
	_, child, err := s.authorizeGuardianAction(ctx, guardianOpDeleteChild, guardianUserID, childUserID, stepUpPassword, ip, userAgent)
	if err != nil {
		return err
	}
	if s.purger == nil {
		return fmt.Errorf("%w: account erasure is not wired on this deployment", ErrServiceUnavailable)
	}
	if err := s.purger.PurgeAccount(ctx, guardianUserID, child); err != nil {
		return fmt.Errorf("delete managed child account: %w", err)
	}
	s.auditGuardianAction(ctx, guardianOpDeleteChild, guardianUserID, child.ID, true, ip, userAgent, nil)
	return nil
}
