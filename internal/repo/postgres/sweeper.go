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

func (r *pgRepository) deleteExpiredBatch(ctx context.Context, op, table string, beforeMs int64, limit int) (int, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("postgres: %s: limit must be > 0, got %d", op, limit)
	}
	q := fmt.Sprintf(`
		DELETE FROM %s
		 WHERE id IN (
		     SELECT id FROM %s
		      WHERE tenant_id = $1 AND expires_at_ms < $2
		      ORDER BY expires_at_ms ASC
		      LIMIT $3
		 )`, table, table)
	tag, err := r.pool.Exec(ctx, q, r.tenantID, beforeMs, limit)
	if err != nil {
		return 0, wrapPgErr(op, err)
	}
	return int(tag.RowsAffected()), nil
}

func (r *pgRepository) DeleteExpiredWebAuthnChallenges(ctx context.Context, beforeMs int64, limit int) (int, error) {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredWebAuthnChallenges", "passkey_challenges", beforeMs, limit)
}

func (r *pgRepository) DeleteExpiredEmailVerificationTokens(ctx context.Context, beforeMs int64, limit int) (int, error) {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredEmailVerificationTokens", "email_verification_tokens", beforeMs, limit)
}

func (r *pgRepository) DeleteExpiredPasswordResetTokens(ctx context.Context, beforeMs int64, limit int) (int, error) {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredPasswordResetTokens", "password_reset_tokens", beforeMs, limit)
}

func (r *pgRepository) DeleteExpiredEmailChangeTokens(ctx context.Context, beforeMs int64, limit int) (int, error) {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredEmailChangeTokens", "email_change_tokens", beforeMs, limit)
}

func (r *pgRepository) DeleteExpiredLoginChallenges(ctx context.Context, beforeMs int64, limit int) (int, error) {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredLoginChallenges", "login_challenges", beforeMs, limit)
}
