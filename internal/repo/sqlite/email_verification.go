package sqlite

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

func scanEmailVerification(s scanner) (*service.EmailVerificationToken, error) {
	var t service.EmailVerificationToken
	if err := s.Scan(
		&t.NodeID, &t.TokenHash, &t.UserID, &t.Email, &t.ExpiresAt, &t.CreatedAt, &t.ConsumedAt,
	); err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *sqliteRepository) CreateEmailVerificationToken(ctx context.Context, t *service.EmailVerificationToken) error {
	if t == nil {
		return errors.New("sqlite: CreateEmailVerificationToken: nil record")
	}
	id := t.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO email_verification_tokens (
			id, project_id, token_hash, user_id, email,
			expires_at_ms, created_at_ms, consumed_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := r.db.Exec(ctx, q, id, r.projectID, t.TokenHash, t.UserID, t.Email, t.ExpiresAt, t.CreatedAt, t.ConsumedAt)
	if err != nil {
		return wrapErr("CreateEmailVerificationToken", err)
	}
	t.NodeID = id
	return nil
}

func (r *sqliteRepository) FindEmailVerificationTokenByHash(ctx context.Context, tokenHash string) (*service.EmailVerificationToken, error) {
	if tokenHash == "" {
		return nil, nil
	}
	const q = `
		SELECT id, token_hash, user_id, email, expires_at_ms, created_at_ms, consumed_at_ms
		  FROM email_verification_tokens
		 WHERE project_id = $1 AND token_hash = $2
		 LIMIT 1`
	t, err := scanEmailVerification(r.db.QueryRow(ctx, q, r.projectID, tokenHash))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("FindEmailVerificationTokenByHash", err)
	}
	return t, nil
}

func (r *sqliteRepository) MarkEmailVerificationTokenConsumed(ctx context.Context, tokenID string, atMs int64) error {
	if tokenID == "" {
		return errors.New("sqlite: MarkEmailVerificationTokenConsumed: missing token id")
	}
	const q = `UPDATE email_verification_tokens SET consumed_at_ms = $3 WHERE project_id = $1 AND id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, tokenID, atMs); err != nil {
		return wrapErr("MarkEmailVerificationTokenConsumed", err)
	}
	return nil
}
