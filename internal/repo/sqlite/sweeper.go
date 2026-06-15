package sqlite

import (
	"context"
	"fmt"
)

// Each DeleteExpired* method runs a batched delete of ephemeral rows whose
// expires_at_ms is strictly less than beforeMs, capped at `limit` rows per
// call. SQLite (compiled without SQLITE_ENABLE_UPDATE_DELETE_LIMIT, as the
// pure-Go build is) has no DELETE … LIMIT, so we pin the batch with a
// subquery that selects ids ordered by expires_at_ms ASC — the same shape
// as the postgres driver, so behaviour and the (project_id, expires_at_ms)
// index usage match.
//
// limit <= 0 is rejected: an uncapped sweep could lock the table for an
// unbounded window. Return value is only error, matching the Repository
// contract across every backend.

func (r *sqliteRepository) deleteExpiredBatch(ctx context.Context, op, table string, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("sqlite: %s: limit must be > 0, got %d", op, limit)
	}
	q := fmt.Sprintf(`
		DELETE FROM %s
		 WHERE id IN (
		     SELECT id FROM %s
		      WHERE project_id = $1 AND expires_at_ms < $2
		      ORDER BY expires_at_ms ASC
		      LIMIT $3
		 )`, table, table)
	if _, err := r.db.Exec(ctx, q, r.projectID, beforeMs, limit); err != nil {
		return wrapErr(op, err)
	}
	return nil
}

func (r *sqliteRepository) DeleteExpiredWebAuthnChallenges(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredWebAuthnChallenges", "passkey_challenges", beforeMs, limit)
}

func (r *sqliteRepository) DeleteExpiredEmailVerificationTokens(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredEmailVerificationTokens", "email_verification_tokens", beforeMs, limit)
}

func (r *sqliteRepository) DeleteExpiredPasswordResetTokens(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredPasswordResetTokens", "password_reset_tokens", beforeMs, limit)
}

func (r *sqliteRepository) DeleteExpiredEmailChangeTokens(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredEmailChangeTokens", "email_change_tokens", beforeMs, limit)
}

func (r *sqliteRepository) DeleteExpiredLoginChallenges(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredLoginChallenges", "login_challenges", beforeMs, limit)
}

func (r *sqliteRepository) DeleteExpiredOAuthOneTimeCodes(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredOAuthOneTimeCodes", "oauth_one_time_codes", beforeMs, limit)
}

func (r *sqliteRepository) DeleteExpiredEmailLoginCodes(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredEmailLoginCodes", "email_login_codes", beforeMs, limit)
}

func (r *sqliteRepository) DeleteExpiredMagicLinkTokens(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredMagicLinkTokens", "magic_link_tokens", beforeMs, limit)
}

func (r *sqliteRepository) DeleteExpiredPhoneVerificationCodes(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredPhoneVerificationCodes", "phone_verification_codes", beforeMs, limit)
}

func (r *sqliteRepository) DeleteExpiredQrLoginSessions(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredQrLoginSessions", "qr_login_sessions", beforeMs, limit)
}

func (r *sqliteRepository) DeleteExpiredInvitations(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredInvitations", "user_invitations", beforeMs, limit)
}
