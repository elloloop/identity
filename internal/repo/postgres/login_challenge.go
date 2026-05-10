package postgres

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

func (r *pgRepository) CreateLoginChallenge(ctx context.Context, c *service.LoginChallengeRecord) (string, error) {
	if c == nil {
		return "", errors.New("postgres: CreateLoginChallenge: nil record")
	}
	id := c.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO login_challenges (
			id, tenant_id, challenge_id, user_id, expires_at_ms, created_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.tenantID, c.ChallengeID, c.UserID, c.ExpiresAt, c.CreatedAt,
	)
	if err != nil {
		return "", wrapPgErr("CreateLoginChallenge", err)
	}
	c.NodeID = id
	return id, nil
}

func (r *pgRepository) GetLoginChallengeByChallengeID(ctx context.Context, challengeID string) (*service.LoginChallengeRecord, error) {
	if challengeID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, challenge_id, user_id, expires_at_ms, created_at_ms
		  FROM login_challenges
		 WHERE tenant_id = $1 AND challenge_id = $2
		 LIMIT 1`
	var c service.LoginChallengeRecord
	err := r.pool.QueryRow(ctx, q, r.tenantID, challengeID).Scan(
		&c.NodeID, &c.ChallengeID, &c.UserID, &c.ExpiresAt, &c.CreatedAt,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetLoginChallengeByChallengeID", err)
	}
	return &c, nil
}

func (r *pgRepository) DeleteLoginChallenge(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	const q = `DELETE FROM login_challenges WHERE tenant_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.tenantID, nodeID); err != nil {
		return wrapPgErr("DeleteLoginChallenge", err)
	}
	return nil
}
