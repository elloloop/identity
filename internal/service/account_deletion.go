package service

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/events"
)

// DefaultAccountDeletionGraceDays is the fallback self-service deletion grace
// window used when the wired value is non-positive. It guarantees a
// misconfiguration can never schedule a grace-less (immediate) purge.
const DefaultAccountDeletionGraceDays = 30

// msPerDay is the milliseconds-in-a-day multiplier used to turn the configured
// grace window (days) into the epoch-ms purge instant.
const msPerDay int64 = 24 * 60 * 60 * 1000

// accountDeletionSweeperActor is the audit actor recorded when the background
// sweeper purges an account whose grace window has elapsed. It is a system
// principal, distinct from any end-user or admin.
const accountDeletionSweeperActor = "system:account-deletion-sweeper"

// revokeAllUserSessions immediately invalidates a user's access by deleting
// their refresh tokens and revoking their active sessions, so a status change
// (admin deactivation, self-service deletion request, hard delete) takes effect
// at once rather than at the next token's natural expiry. Callers pass the same
// nowMs used for the surrounding mutation so the revocation timestamp matches.
//
// It is the one implementation of the "cut off access now" step, shared by
// AdminService.DeactivateUser, the delete cascade, and
// ProfileService.DeleteMyAccount, so the three never drift.
func revokeAllUserSessions(ctx context.Context, repo Repository, userID string, nowMs int64) error {
	if err := repo.DeleteRefreshTokensForUser(ctx, userID); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	if err := repo.RevokeSessionsForUser(ctx, userID, nowMs); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	return nil
}

// WithAccountDeletionGraceDays wires the self-service deletion grace window and
// returns the service for chaining. A non-positive value keeps the safe default
// (DefaultAccountDeletionGraceDays).
func (s *ProfileService) WithAccountDeletionGraceDays(days int) *ProfileService {
	s.accountDeletionGraceDays = days
	return s
}

// graceDays returns the effective grace window, clamping a non-positive
// configured value to the safe default.
func (s *ProfileService) graceDays() int {
	if s.accountDeletionGraceDays < 1 {
		return DefaultAccountDeletionGraceDays
	}
	return s.accountDeletionGraceDays
}

// DeleteMyAccount schedules self-service deletion of the CALLER's own account
// (GDPR Art 17). It sets status = PENDING_DELETION and a purge instant one grace
// window in the future, then immediately revokes the caller's sessions and
// refresh tokens so access ends at once. The account is retained (and fully
// recoverable via CancelAccountDeletion or a login) until the sweeper purges it.
//
// It is idempotent for an already-pending account: the existing scheduled time
// is returned without rescheduling. An account an admin has DEACTIVATED or
// SUSPENDED cannot be self-deleted (ErrAccountDeletionNotAllowed) — the admin
// action takes precedence. The household/teardown concern for a sole admin lives
// in the relay, not here.
//
// Returns the epoch-ms instant the account is scheduled to be purged.
func (s *ProfileService) DeleteMyAccount(ctx context.Context, actorID, reason string) (int64, error) {
	if actorID == "" {
		return 0, ErrUnauthenticated
	}
	repo := s.repo(ctx)
	if repo == nil {
		return 0, ErrServiceUnavailable
	}

	user, err := repo.GetUser(ctx, actorID)
	if err != nil {
		return 0, fmt.Errorf("fetch user: %w", err)
	}
	if user == nil {
		return 0, fmt.Errorf("%w: user not found", ErrNotFound)
	}

	switch strings.ToLower(user.Status) {
	case StatusPendingDeletion:
		// Already scheduled — return the existing instant idempotently.
		return user.DeletionScheduledAtMs, nil
	case "", StatusActive:
		// eligible — fall through
	default:
		return 0, fmt.Errorf("%w: account is %s", ErrAccountDeletionNotAllowed, user.Status)
	}

	now := nowMs()
	scheduledAt := now + int64(s.graceDays())*msPerDay
	if err := repo.UpdateUser(ctx, actorID, map[string]any{
		"status":                   StatusPendingDeletion,
		"deletion_scheduled_at_ms": scheduledAt,
		"updated_at":               now,
	}); err != nil {
		return 0, fmt.Errorf("schedule account deletion: %w", err)
	}

	if err := revokeAllUserSessions(ctx, repo, actorID, now); err != nil {
		return 0, fmt.Errorf("schedule account deletion: %w", err)
	}

	s.audit.Log(
		ctx, audit.EventAccountDeletionRequested,
		audit.WithActor(actorID), audit.WithTarget(actorID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"reason":                   reason,
			"deletion_scheduled_at_ms": scheduledAt,
		}),
	)
	return scheduledAt, nil
}

// CancelAccountDeletion calls off a pending self-service deletion for the
// CALLER, restoring status = ACTIVE and clearing the scheduled purge. It is
// idempotent: an account that is not pending deletion is returned unchanged
// without error. Returns the resulting status.
func (s *ProfileService) CancelAccountDeletion(ctx context.Context, actorID string) (string, error) {
	if actorID == "" {
		return "", ErrUnauthenticated
	}
	repo := s.repo(ctx)
	if repo == nil {
		return "", ErrServiceUnavailable
	}

	user, err := repo.GetUser(ctx, actorID)
	if err != nil {
		return "", fmt.Errorf("fetch user: %w", err)
	}
	if user == nil {
		return "", fmt.Errorf("%w: user not found", ErrNotFound)
	}
	if strings.ToLower(user.Status) != StatusPendingDeletion {
		// Not pending — nothing to cancel; report the current status.
		return user.Status, nil
	}

	if err := clearPendingDeletion(ctx, repo, actorID); err != nil {
		return "", fmt.Errorf("cancel account deletion: %w", err)
	}
	s.audit.Log(
		ctx, audit.EventAccountDeletionCancelled,
		audit.WithActor(actorID), audit.WithTarget(actorID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"trigger": "explicit"}),
	)
	return StatusActive, nil
}

// clearPendingDeletion restores an account from PENDING_DELETION back to ACTIVE
// and clears the scheduled purge instant in one write. Shared by the explicit
// cancel and the login-time auto-cancel so the restore is defined once.
func clearPendingDeletion(ctx context.Context, repo Repository, userID string) error {
	now := nowMs()
	return repo.UpdateUser(ctx, userID, map[string]any{
		"status":                   StatusActive,
		"deletion_scheduled_at_ms": int64(0),
		"updated_at":               now,
	})
}

// cancelPendingDeletionOnLogin auto-cancels a pending self-service deletion when
// its owner authenticates during the grace window. It runs on the shared
// interactive-login path (issueTokens) BEFORE tokens are minted, so a returning
// owner always reclaims the account. Best-effort: a failed restore is logged and
// does not block the login the user already completed — the account stays
// pending and the sweeper will retry cancellation semantics on the next login.
func (s *AuthService) cancelPendingDeletionOnLogin(ctx context.Context, user *User) {
	if user == nil || strings.ToLower(user.Status) != StatusPendingDeletion {
		return
	}
	if err := clearPendingDeletion(ctx, s.repo(ctx), user.ID); err != nil {
		s.logger.Warn("account_deletion_auto_cancel_failed",
			zap.String("user_id", user.ID), zap.Error(err))
		return
	}
	user.Status = StatusActive
	user.DeletionScheduledAtMs = 0
	s.audit.Log(
		ctx, audit.EventAccountDeletionCancelled,
		audit.WithActor(user.ID), audit.WithTarget(user.ID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"trigger": "login"}),
	)
}

// PurgeExpiredPendingDeletions hard-deletes every account whose self-service
// deletion grace window has elapsed (status = pending_deletion and
// deletion_scheduled_at_ms <= cutoffMs), up to limit accounts. It reuses the
// exact admin delete cascade — session/token revocation, group-edge cleanup,
// the repo cascade, the user_deleted audit entry, and the downstream
// user.deactivated + user.deleted events — so external services (the Nesta
// relay) cascade identically to an admin delete. Returns the number of accounts
// purged.
//
// A per-account failure is logged and skipped rather than aborting the batch, so
// one poisoned row cannot stall the whole sweep.
func (s *AdminService) PurgeExpiredPendingDeletions(ctx context.Context, cutoffMs int64, limit int) (int, error) {
	users, err := s.repo(ctx).ListUsersPendingDeletionBefore(ctx, cutoffMs, limit)
	if err != nil {
		return 0, fmt.Errorf("list pending-deletion users: %w", err)
	}
	purged := 0
	for _, u := range users {
		if err := s.purgeUser(ctx, accountDeletionSweeperActor, u); err != nil {
			s.logger.Warn("account_deletion_purge_failed",
				zap.String("user_id", u.ID), zap.Error(err))
			continue
		}
		purged++
	}
	return purged, nil
}

// purgeUser runs the hard-delete cascade for a single already-resolved user and
// records auditActorID as the acting principal. It is the shared core of the
// admin DeleteUser RPC and the account-deletion sweeper: neither reimplements
// the cascade. Callers own the authorization / eligibility checks before calling
// it. Sessions and refresh tokens are revoked BEFORE the cascade so any in-flight
// access token dies immediately.
func (s *AdminService) purgeUser(ctx context.Context, auditActorID string, u *User) error {
	now := nowMs()
	if err := revokeAllUserSessions(ctx, s.repo(ctx), u.ID, now); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	// Group membership is a graph MEMBER_OF edge, not a Repository record, so
	// the repo cascade below cannot reach it. Drain the edges first so a deleted
	// user never leaves dangling memberships on the graph backend.
	if err := s.deleteGroupMembershipsForUser(ctx, u.ID); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if err := s.repo(ctx).DeleteUser(ctx, u.ID); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	s.audit.Log(ctx, audit.EventUserDeleted,
		audit.WithActor(auditActorID), audit.WithTarget(u.ID), audit.WithSuccess(true))

	// Best-effort, both emitted on a purge (no-op when eventing is disabled):
	// user.deactivated is the deprovision signal legacy SCIM subscribers already
	// act on and must keep firing on delete; user.deleted is the distinct
	// permanent-erasure signal a consumer (the Nesta relay) uses to tear down
	// data that must survive a reversible deactivation but not a real deletion.
	u.Status = "deactivated"
	EmitUserEvent(ctx, s.publisher, s.logger, s.projectID(ctx), s.cfg.DefaultTenantID, events.EventUserDeactivated, u)
	EmitUserEvent(ctx, s.publisher, s.logger, s.projectID(ctx), s.cfg.DefaultTenantID, events.EventUserDeleted, u)
	return nil
}
