package sqlite

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

// ── Phone verification codes (SMS OTP) ────────────────────────────────

func (r *sqliteRepository) UpsertPhoneVerificationCode(ctx context.Context, c *service.PhoneVerificationCodeRecord) (string, error) {
	if c == nil {
		return "", errors.New("sqlite: UpsertPhoneVerificationCode: nil record")
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
			phone_number   = excluded.phone_number,
			code_hash      = excluded.code_hash,
			expires_at_ms  = excluded.expires_at_ms,
			created_at_ms  = excluded.created_at_ms,
			consumed_at_ms = excluded.consumed_at_ms,
			attempt_count  = excluded.attempt_count,
			max_attempts   = excluded.max_attempts
		RETURNING id`
	var outID string
	err := r.db.QueryRow(
		ctx, q,
		id, r.projectID, c.UserID, c.PhoneNumber, c.CodeHash,
		c.ExpiresAt, c.CreatedAt, c.ConsumedAt,
		c.AttemptCount, c.MaxAttempts,
	).Scan(&outID)
	if err != nil {
		return "", wrapErr("UpsertPhoneVerificationCode", err)
	}
	c.NodeID = outID
	return outID, nil
}

// CountPhoneVerificationCodeAttempt counts the guess and reads the code in
// one conditional UPDATE, so concurrent guesses never pass the cap between
// a read and an increment.
func (r *sqliteRepository) CountPhoneVerificationCodeAttempt(ctx context.Context, userID string, atMs int64) (*service.PhoneVerificationCodeRecord, error) {
	const q = `
		UPDATE phone_verification_codes
		   SET attempt_count = attempt_count + 1
		 WHERE project_id = $1 AND user_id = $2
		   AND consumed_at_ms = 0 AND expires_at_ms > $3
		   AND (max_attempts = 0 OR attempt_count < max_attempts)
		RETURNING id, user_id, phone_number, code_hash, expires_at_ms,
		          created_at_ms, consumed_at_ms, attempt_count, max_attempts`
	var c service.PhoneVerificationCodeRecord
	err := r.db.QueryRow(ctx, q, r.projectID, userID, atMs).Scan(
		&c.NodeID, &c.UserID, &c.PhoneNumber, &c.CodeHash, &c.ExpiresAt,
		&c.CreatedAt, &c.ConsumedAt, &c.AttemptCount, &c.MaxAttempts,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("CountPhoneVerificationCodeAttempt", err)
	}
	return &c, nil
}

func (r *sqliteRepository) ConsumePhoneVerificationCode(ctx context.Context, userID string, atMs int64) (*service.PhoneVerificationCodeRecord, error) {
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
	err := r.db.QueryRow(ctx, q, r.projectID, userID, atMs).Scan(
		&c.NodeID, &c.UserID, &c.PhoneNumber, &c.CodeHash, &c.ExpiresAt,
		&c.CreatedAt, &c.ConsumedAt, &c.AttemptCount, &c.MaxAttempts,
	)
	if noRows(err) {
		return nil, service.ErrPhoneCodeInvalid
	}
	if err != nil {
		return nil, wrapErr("ConsumePhoneVerificationCode", err)
	}
	return &c, nil
}
