package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

func scanEmailChange(row pgx.Row) (*service.EmailChangeToken, error) {
	var t service.EmailChangeToken
	if err := row.Scan(
		&t.NodeID, &t.TokenHash, &t.UserID, &t.OldEmail, &t.NewEmail,
		&t.ExpiresAt, &t.CreatedAt, &t.ConsumedAt,
	); err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *pgRepository) CreateEmailChangeToken(ctx context.Context, t *service.EmailChangeToken) error {
	if t == nil {
		return errors.New("postgres: CreateEmailChangeToken: nil record")
	}
	id := t.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO email_change_tokens (
			id, project_id, token_hash, user_id, old_email, new_email,
			expires_at_ms, created_at_ms, consumed_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.projectID, t.TokenHash, t.UserID, t.OldEmail, t.NewEmail,
		t.ExpiresAt, t.CreatedAt, t.ConsumedAt,
	)
	if err != nil {
		return wrapPgErr("CreateEmailChangeToken", err)
	}
	t.NodeID = id
	return nil
}

func (r *pgRepository) FindEmailChangeTokenByHash(ctx context.Context, tokenHash string) (*service.EmailChangeToken, error) {
	if tokenHash == "" {
		return nil, nil
	}
	const q = `
		SELECT id, token_hash, user_id, old_email, new_email,
		       expires_at_ms, created_at_ms, consumed_at_ms
		  FROM email_change_tokens
		 WHERE project_id = $1 AND token_hash = $2
		 LIMIT 1`
	row := r.pool.QueryRow(ctx, q, r.projectID, tokenHash)
	t, err := scanEmailChange(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("FindEmailChangeTokenByHash", err)
	}
	return t, nil
}

func (r *pgRepository) MarkEmailChangeTokenConsumed(ctx context.Context, tokenID string, atMs int64) error {
	if tokenID == "" {
		return errors.New("postgres: MarkEmailChangeTokenConsumed: missing token id")
	}
	const q = `
		UPDATE email_change_tokens
		   SET consumed_at_ms = $3
		 WHERE project_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, tokenID, atMs); err != nil {
		return wrapPgErr("MarkEmailChangeTokenConsumed", err)
	}
	return nil
}
