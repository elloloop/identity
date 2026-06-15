package postgres

import (
	"context"
	"fmt"
)

// Each DeleteExpired* method runs a batched delete of ephemeral rows
// whose expires_at_ms is strictly less than beforeMs, capped at
// `limit` rows per call. Postgres has no native DELETE ... LIMIT, so
// we pin the batch with a subquery that selects ids and orders by
// expires_at_ms ASC; this also makes the work deterministic across
// retries when a batch errors mid-delete.
//
// limit <= 0 is rejected: a sweeper batch with no cap could lock a
// hot table for an unbounded window.
//
// Return value is only error: tenant-shard-db v1.14.0's
// OpDeleteWhere primitive (#540) does not return a deleted-row count,
// so the Repository contract drops the count to keep all three
// backends (memory, postgres, entdb) on a single signature. The
// postgres-specific `tag.RowsAffected()` is therefore not surfaced.

func (r *pgRepository) deleteExpiredBatch(ctx context.Context, op, table string, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("postgres: %s: limit must be > 0, got %d", op, limit)
	}
	q := fmt.Sprintf(`
		DELETE FROM %s
		 WHERE id IN (
		     SELECT id FROM %s
		      WHERE project_id = $1 AND expires_at_ms < $2
		      ORDER BY expires_at_ms ASC
		      LIMIT $3
		 )`, table, table)
	if _, err := r.pool.Exec(ctx, q, r.projectID, beforeMs, limit); err != nil {
		return wrapPgErr(op, err)
	}
	return nil
}

func (r *pgRepository) DeleteExpiredWebAuthnChallenges(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredWebAuthnChallenges", "passkey_challenges", beforeMs, limit)
}

func (r *pgRepository) DeleteExpiredEmailVerificationTokens(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredEmailVerificationTokens", "email_verification_tokens", beforeMs, limit)
}

func (r *pgRepository) DeleteExpiredPasswordResetTokens(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredPasswordResetTokens", "password_reset_tokens", beforeMs, limit)
}

func (r *pgRepository) DeleteExpiredEmailChangeTokens(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredEmailChangeTokens", "email_change_tokens", beforeMs, limit)
}

func (r *pgRepository) DeleteExpiredLoginChallenges(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredLoginChallenges", "login_challenges", beforeMs, limit)
}

func (r *pgRepository) DeleteExpiredOAuthOneTimeCodes(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredOAuthOneTimeCodes", "oauth_one_time_codes", beforeMs, limit)
}

func (r *pgRepository) DeleteExpiredEmailLoginCodes(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredEmailLoginCodes", "email_login_codes", beforeMs, limit)
}

func (r *pgRepository) DeleteExpiredMagicLinkTokens(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredMagicLinkTokens", "magic_link_tokens", beforeMs, limit)
}

func (r *pgRepository) DeleteExpiredPhoneVerificationCodes(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredPhoneVerificationCodes", "phone_verification_codes", beforeMs, limit)
}

func (r *pgRepository) DeleteExpiredQrLoginSessions(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredQrLoginSessions", "qr_login_sessions", beforeMs, limit)
}

func (r *pgRepository) DeleteExpiredInvitations(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredInvitations", "user_invitations", beforeMs, limit)
}
