package postgres

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

func (r *pgRepository) CreateOAuthOneTimeCode(ctx context.Context, c *service.OAuthOneTimeCodeRecord) (string, error) {
	if c == nil {
		return "", errors.New("postgres: CreateOAuthOneTimeCode: nil record")
	}
	id := c.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO oauth_one_time_codes (
			id, project_id, code_hash, user_id,
			expires_at_ms, created_at_ms, consumed_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.projectID, c.CodeHash, c.UserID,
		c.ExpiresAt, c.CreatedAt, c.ConsumedAt,
	)
	if err != nil {
		return "", wrapPgErr("CreateOAuthOneTimeCode", err)
	}
	c.NodeID = id
	return id, nil
}

// ConsumeOAuthOneTimeCode atomically marks an unconsumed, unexpired
// code consumed via a single UPDATE gated on the current state. The
// `WHERE consumed_at_ms = 0 AND expires_at_ms > $3` clause is the CAS
// predicate; RETURNING hands back the bound record in the same
// statement so exactly one concurrent caller wins. A replay, an
// expired code, or a missing code all hit zero rows and return
// ErrOAuthCodeInvalid.
func (r *pgRepository) ConsumeOAuthOneTimeCode(ctx context.Context, codeHash string, atMs int64) (*service.OAuthOneTimeCodeRecord, error) {
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
	err := r.pool.QueryRow(ctx, q, r.projectID, codeHash, atMs).Scan(
		&c.NodeID, &c.CodeHash, &c.UserID,
		&c.ExpiresAt, &c.CreatedAt, &c.ConsumedAt,
	)
	if noRows(err) {
		return nil, service.ErrOAuthCodeInvalid
	}
	if err != nil {
		return nil, wrapPgErr("ConsumeOAuthOneTimeCode", err)
	}
	return &c, nil
}
