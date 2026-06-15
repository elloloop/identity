package sqlite

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

// ── Email login codes (passwordless OTP) ──────────────────────────────

func (r *sqliteRepository) UpsertEmailLoginCode(ctx context.Context, c *service.EmailLoginCodeRecord) (string, error) {
	if c == nil {
		return "", errors.New("sqlite: UpsertEmailLoginCode: nil record")
	}
	id := c.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO email_login_codes (
			id, project_id, email, code_hash,
			expires_at_ms, created_at_ms, consumed_at_ms,
			attempt_count, max_attempts
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (project_id, email) DO UPDATE SET
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
		id, r.projectID, c.Email, c.CodeHash,
		c.ExpiresAt, c.CreatedAt, c.ConsumedAt,
		c.AttemptCount, c.MaxAttempts,
	).Scan(&outID)
	if err != nil {
		return "", wrapErr("UpsertEmailLoginCode", err)
	}
	c.NodeID = outID
	return outID, nil
}

func (r *sqliteRepository) FindEmailLoginCodeByEmail(ctx context.Context, email string) (*service.EmailLoginCodeRecord, error) {
	const q = `
		SELECT id, email, code_hash, expires_at_ms, created_at_ms,
		       consumed_at_ms, attempt_count, max_attempts
		  FROM email_login_codes
		 WHERE project_id = $1 AND email = $2`
	var c service.EmailLoginCodeRecord
	err := r.db.QueryRow(ctx, q, r.projectID, email).Scan(
		&c.NodeID, &c.Email, &c.CodeHash, &c.ExpiresAt, &c.CreatedAt,
		&c.ConsumedAt, &c.AttemptCount, &c.MaxAttempts,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("FindEmailLoginCodeByEmail", err)
	}
	return &c, nil
}

func (r *sqliteRepository) IncrementEmailLoginCodeAttempts(ctx context.Context, nodeID string) error {
	const q = `
		UPDATE email_login_codes SET attempt_count = attempt_count + 1
		 WHERE project_id = $1 AND id = $2`
	tag, err := r.db.Exec(ctx, q, r.projectID, nodeID)
	if err != nil {
		return wrapErr("IncrementEmailLoginCodeAttempts", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("sqlite: IncrementEmailLoginCodeAttempts: no such row")
	}
	return nil
}

func (r *sqliteRepository) ConsumeEmailLoginCode(ctx context.Context, email string, atMs int64) (*service.EmailLoginCodeRecord, error) {
	if email == "" {
		return nil, service.ErrEmailLoginCodeInvalid
	}
	const q = `
		UPDATE email_login_codes
		   SET consumed_at_ms = $3
		 WHERE project_id = $1 AND email = $2
		   AND consumed_at_ms = 0 AND expires_at_ms > $3
		RETURNING id, email, code_hash, expires_at_ms, created_at_ms,
		          consumed_at_ms, attempt_count, max_attempts`
	var c service.EmailLoginCodeRecord
	err := r.db.QueryRow(ctx, q, r.projectID, email, atMs).Scan(
		&c.NodeID, &c.Email, &c.CodeHash, &c.ExpiresAt, &c.CreatedAt,
		&c.ConsumedAt, &c.AttemptCount, &c.MaxAttempts,
	)
	if noRows(err) {
		return nil, service.ErrEmailLoginCodeInvalid
	}
	if err != nil {
		return nil, wrapErr("ConsumeEmailLoginCode", err)
	}
	return &c, nil
}

// ── Magic link tokens (passwordless) ──────────────────────────────────

func (r *sqliteRepository) CreateMagicLinkToken(ctx context.Context, t *service.MagicLinkTokenRecord) (string, error) {
	if t == nil {
		return "", errors.New("sqlite: CreateMagicLinkToken: nil record")
	}
	id := t.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO magic_link_tokens (
			id, project_id, token_hash, email, return_to,
			expires_at_ms, created_at_ms, consumed_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := r.db.Exec(ctx, q, id, r.projectID, t.TokenHash, t.Email, t.ReturnTo, t.ExpiresAt, t.CreatedAt, t.ConsumedAt)
	if err != nil {
		return "", wrapErr("CreateMagicLinkToken", err)
	}
	t.NodeID = id
	return id, nil
}

func (r *sqliteRepository) ConsumeMagicLinkToken(ctx context.Context, tokenHash string, atMs int64) (*service.MagicLinkTokenRecord, error) {
	if tokenHash == "" {
		return nil, service.ErrMagicLinkInvalid
	}
	const q = `
		UPDATE magic_link_tokens
		   SET consumed_at_ms = $3
		 WHERE project_id = $1 AND token_hash = $2
		   AND consumed_at_ms = 0 AND expires_at_ms > $3
		RETURNING id, token_hash, email, return_to, expires_at_ms, created_at_ms, consumed_at_ms`
	var t service.MagicLinkTokenRecord
	err := r.db.QueryRow(ctx, q, r.projectID, tokenHash, atMs).Scan(
		&t.NodeID, &t.TokenHash, &t.Email, &t.ReturnTo, &t.ExpiresAt, &t.CreatedAt, &t.ConsumedAt,
	)
	if noRows(err) {
		return nil, service.ErrMagicLinkInvalid
	}
	if err != nil {
		return nil, wrapErr("ConsumeMagicLinkToken", err)
	}
	return &t, nil
}
