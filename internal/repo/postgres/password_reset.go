package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

func scanPasswordReset(row pgx.Row) (*service.PasswordResetToken, error) {
	var t service.PasswordResetToken
	if err := row.Scan(
		&t.NodeID, &t.TokenHash, &t.UserID,
		&t.ExpiresAt, &t.CreatedAt, &t.ConsumedAt,
	); err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *pgRepository) CreatePasswordResetToken(ctx context.Context, t *service.PasswordResetToken) error {
	if t == nil {
		return errors.New("postgres: CreatePasswordResetToken: nil record")
	}
	id := t.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO password_reset_tokens (
			id, project_id, token_hash, user_id, email,
			expires_at_ms, created_at_ms, consumed_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.projectID, t.TokenHash, t.UserID, "",
		t.ExpiresAt, t.CreatedAt, t.ConsumedAt,
	)
	if err != nil {
		return wrapPgErr("CreatePasswordResetToken", err)
	}
	t.NodeID = id
	return nil
}

func (r *pgRepository) FindPasswordResetTokenByHash(ctx context.Context, tokenHash string) (*service.PasswordResetToken, error) {
	if tokenHash == "" {
		return nil, nil
	}
	const q = `
		SELECT id, token_hash, user_id, expires_at_ms, created_at_ms, consumed_at_ms
		  FROM password_reset_tokens
		 WHERE project_id = $1 AND token_hash = $2
		 LIMIT 1`
	row := r.pool.QueryRow(ctx, q, r.projectID, tokenHash)
	t, err := scanPasswordReset(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("FindPasswordResetTokenByHash", err)
	}
	return t, nil
}

func (r *pgRepository) MarkPasswordResetTokenConsumed(ctx context.Context, tokenID string, atMs int64) error {
	if tokenID == "" {
		return errors.New("postgres: MarkPasswordResetTokenConsumed: missing token id")
	}
	const q = `
		UPDATE password_reset_tokens
		   SET consumed_at_ms = $3
		 WHERE project_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, tokenID, atMs); err != nil {
		return wrapPgErr("MarkPasswordResetTokenConsumed", err)
	}
	return nil
}
