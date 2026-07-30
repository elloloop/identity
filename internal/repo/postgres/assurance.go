package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/elloloop/identity/internal/service"
)

func (r *pgRepository) CreateAttestedDevice(ctx context.Context, d *service.AttestedDeviceRecord) (string, error) {
	if d == nil {
		return "", errors.New("postgres: CreateAttestedDevice: nil record")
	}
	id := d.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO attested_devices (
			id, project_id, platform, key_id, public_key_spki,
			sign_count, environment, created_at_ms, last_used_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.projectID, d.Platform, d.KeyID, d.PublicKeySPKI,
		d.SignCount, d.Environment, d.CreatedAt, d.LastUsedAt,
	)
	if err != nil {
		return "", wrapPgErr("CreateAttestedDevice", err)
	}
	d.NodeID = id
	return id, nil
}

func (r *pgRepository) GetAttestedDeviceByKeyID(ctx context.Context, keyID string) (*service.AttestedDeviceRecord, error) {
	if keyID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, platform, key_id, public_key_spki, sign_count,
		       environment, created_at_ms, last_used_at_ms
		  FROM attested_devices
		 WHERE project_id = $1 AND key_id = $2`
	var d service.AttestedDeviceRecord
	err := r.pool.QueryRow(ctx, q, r.projectID, keyID).Scan(
		&d.NodeID, &d.Platform, &d.KeyID, &d.PublicKeySPKI, &d.SignCount,
		&d.Environment, &d.CreatedAt, &d.LastUsedAt,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetAttestedDeviceByKeyID", err)
	}
	return &d, nil
}

func (r *pgRepository) UpdateAttestedDeviceCounter(ctx context.Context, nodeID string, fromCount, toCount, lastUsedAtMs int64) error {
	if nodeID == "" {
		return fmt.Errorf("%w: attested device", service.ErrNotFound)
	}
	// The WHERE sign_count = $3 clause is the compare-and-swap: a
	// concurrent assertion that already advanced the counter makes this
	// update match zero rows.
	const q = `
		UPDATE attested_devices
		   SET sign_count = $4, last_used_at_ms = $5
		 WHERE project_id = $1 AND id = $2 AND sign_count = $3`
	tag, err := r.pool.Exec(ctx, q, r.projectID, nodeID, fromCount, toCount, lastUsedAtMs)
	if err != nil {
		return wrapPgErr("UpdateAttestedDeviceCounter", err)
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	// Zero rows: distinguish a lost CAS from a deleted device.
	const exists = `SELECT 1 FROM attested_devices WHERE project_id = $1 AND id = $2`
	var one int
	err = r.pool.QueryRow(ctx, exists, r.projectID, nodeID).Scan(&one)
	if noRows(err) {
		return fmt.Errorf("%w: attested device", service.ErrNotFound)
	}
	if err != nil {
		return wrapPgErr("UpdateAttestedDeviceCounter", err)
	}
	return service.ErrCounterStale
}

func (r *pgRepository) CreateAssuranceChallenge(ctx context.Context, c *service.AssuranceChallengeRecord) (string, error) {
	if c == nil {
		return "", errors.New("postgres: CreateAssuranceChallenge: nil record")
	}
	id := c.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO assurance_challenges (
			id, project_id, challenge, platform, expires_at_ms, created_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := r.pool.Exec(ctx, q, id, r.projectID, c.Challenge, c.Platform, c.ExpiresAt, c.CreatedAt)
	if err != nil {
		return "", wrapPgErr("CreateAssuranceChallenge", err)
	}
	c.NodeID = id
	return id, nil
}

func (r *pgRepository) ConsumeAssuranceChallenge(ctx context.Context, nodeID string) (*service.AssuranceChallengeRecord, error) {
	if nodeID == "" {
		return nil, nil
	}
	// DELETE ... RETURNING makes redemption atomic: exactly one caller
	// can ever observe the row.
	const q = `
		DELETE FROM assurance_challenges
		 WHERE project_id = $1 AND id = $2
		RETURNING id, challenge, platform, expires_at_ms, created_at_ms`
	var c service.AssuranceChallengeRecord
	err := r.pool.QueryRow(ctx, q, r.projectID, nodeID).Scan(
		&c.NodeID, &c.Challenge, &c.Platform, &c.ExpiresAt, &c.CreatedAt,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("ConsumeAssuranceChallenge", err)
	}
	return &c, nil
}

func (r *pgRepository) DeleteExpiredAssuranceChallenges(ctx context.Context, beforeMs int64, limit int) error {
	return r.deleteExpiredBatch(ctx, "DeleteExpiredAssuranceChallenges", "assurance_challenges", beforeMs, limit)
}
