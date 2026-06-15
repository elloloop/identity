package sqlite

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

func (r *sqliteRepository) CreateOAuthOneTimeCode(ctx context.Context, c *service.OAuthOneTimeCodeRecord) (string, error) {
	if c == nil {
		return "", errors.New("sqlite: CreateOAuthOneTimeCode: nil record")
	}
	id := c.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO oauth_one_time_codes (
			id, project_id, code_hash, user_id, expires_at_ms, created_at_ms, consumed_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.db.Exec(ctx, q, id, r.projectID, c.CodeHash, c.UserID, c.ExpiresAt, c.CreatedAt, c.ConsumedAt)
	if err != nil {
		return "", wrapErr("CreateOAuthOneTimeCode", err)
	}
	c.NodeID = id
	return id, nil
}

func (r *sqliteRepository) ConsumeOAuthOneTimeCode(ctx context.Context, codeHash string, atMs int64) (*service.OAuthOneTimeCodeRecord, error) {
	if codeHash == "" {
		return nil, service.ErrOAuthCodeInvalid
	}
	const q = `
		UPDATE oauth_one_time_codes
		   SET consumed_at_ms = $3
		 WHERE project_id = $1 AND code_hash = $2
		   AND consumed_at_ms = 0 AND expires_at_ms > $3
		RETURNING id, code_hash, user_id, expires_at_ms, created_at_ms, consumed_at_ms`
	var c service.OAuthOneTimeCodeRecord
	err := r.db.QueryRow(ctx, q, r.projectID, codeHash, atMs).Scan(
		&c.NodeID, &c.CodeHash, &c.UserID, &c.ExpiresAt, &c.CreatedAt, &c.ConsumedAt,
	)
	if noRows(err) {
		return nil, service.ErrOAuthCodeInvalid
	}
	if err != nil {
		return nil, wrapErr("ConsumeOAuthOneTimeCode", err)
	}
	return &c, nil
}
