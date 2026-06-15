package postgres

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

// ── Phone verification codes (SMS OTP) ────────────────────────────────

// UpsertPhoneVerificationCode replaces any existing code for the user so
// at most one is live per user. The (project_id, user_id) unique index is
// the upsert target: ON CONFLICT overwrites the hash, expiry, and
// attempt counters in place, which both invalidates the previous code
// and resets the attempt budget for the fresh one.
func (r *pgRepository) UpsertPhoneVerificationCode(ctx context.Context, c *service.PhoneVerificationCodeRecord) (string, error) {
	if c == nil {
		return "", errors.New("postgres: UpsertPhoneVerificationCode: nil record")
	}
	id := c.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO phone_verification_codes (
			id, project_id, user_id, phone_number, code_hash,
			expires_at_ms, created_at_ms, consumed_at_ms,
			attempt_count, max_attempts
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (project_id, user_id) DO UPDATE SET
			phone_number   = EXCLUDED.phone_number,
			code_hash      = EXCLUDED.code_hash,
			expires_at_ms  = EXCLUDED.expires_at_ms,
			created_at_ms  = EXCLUDED.created_at_ms,
			consumed_at_ms = EXCLUDED.consumed_at_ms,
			attempt_count  = EXCLUDED.attempt_count,
			max_attempts   = EXCLUDED.max_attempts
		RETURNING id`
	var outID string
	err := r.pool.QueryRow(
		ctx, q,
		id, r.projectID, c.UserID, c.PhoneNumber, c.CodeHash,
		c.ExpiresAt, c.CreatedAt, c.ConsumedAt,
		c.AttemptCount, c.MaxAttempts,
	).Scan(&outID)
	if err != nil {
		return "", wrapPgErr("UpsertPhoneVerificationCode", err)
	}
	c.NodeID = outID
	return outID, nil
}

func (r *pgRepository) FindPhoneVerificationCodeByUser(ctx context.Context, userID string) (*service.PhoneVerificationCodeRecord, error) {
	const q = `
		SELECT id, user_id, phone_number, code_hash, expires_at_ms,
		       created_at_ms, consumed_at_ms, attempt_count, max_attempts
		  FROM phone_verification_codes
		 WHERE project_id = $1 AND user_id = $2`
	var c service.PhoneVerificationCodeRecord
	err := r.pool.QueryRow(ctx, q, r.projectID, userID).Scan(
		&c.NodeID, &c.UserID, &c.PhoneNumber, &c.CodeHash, &c.ExpiresAt,
		&c.CreatedAt, &c.ConsumedAt, &c.AttemptCount, &c.MaxAttempts,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("FindPhoneVerificationCodeByUser", err)
	}
	return &c, nil
}

func (r *pgRepository) IncrementPhoneVerificationCodeAttempts(ctx context.Context, nodeID string) error {
	const q = `
		UPDATE phone_verification_codes
		   SET attempt_count = attempt_count + 1
		 WHERE project_id = $1 AND id = $2`
	tag, err := r.pool.Exec(ctx, q, r.projectID, nodeID)
	if err != nil {
		return wrapPgErr("IncrementPhoneVerificationCodeAttempts", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("postgres: IncrementPhoneVerificationCodeAttempts: no such row")
	}
	return nil
}

// ConsumePhoneVerificationCode atomically marks an unconsumed, unexpired
// code consumed via a single CAS UPDATE keyed by user_id. A replay, an
// expired code, or a missing code all hit zero rows and return
// ErrPhoneCodeInvalid.
func (r *pgRepository) ConsumePhoneVerificationCode(ctx context.Context, userID string, atMs int64) (*service.PhoneVerificationCodeRecord, error) {
	if userID == "" {
		return nil, service.ErrPhoneCodeInvalid
	}
	const q = `
		UPDATE phone_verification_codes
		   SET consumed_at_ms = $3
		 WHERE project_id = $1 AND user_id = $2
		   AND consumed_at_ms = 0 AND expires_at_ms > $3
		RETURNING id, user_id, phone_number, code_hash, expires_at_ms,
		          created_at_ms, consumed_at_ms, attempt_count, max_attempts`
	var c service.PhoneVerificationCodeRecord
	err := r.pool.QueryRow(ctx, q, r.projectID, userID, atMs).Scan(
		&c.NodeID, &c.UserID, &c.PhoneNumber, &c.CodeHash, &c.ExpiresAt,
		&c.CreatedAt, &c.ConsumedAt, &c.AttemptCount, &c.MaxAttempts,
	)
	if noRows(err) {
		return nil, service.ErrPhoneCodeInvalid
	}
	if err != nil {
		return nil, wrapPgErr("ConsumePhoneVerificationCode", err)
	}
	return &c, nil
}
