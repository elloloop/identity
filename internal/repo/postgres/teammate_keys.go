package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

const teammateKeyColumns = `id,claim_id,teammate_id,company_id,workstation_id,public_key,algorithm,created_at_ms,revoked_at_ms,revocation_reason`

func scanTeammateKey(row pgx.Row) (*service.TeammateKey, error) {
	var key service.TeammateKey
	err := row.Scan(&key.ID, &key.ClaimID, &key.TeammateID, &key.CompanyID, &key.WorkstationID, &key.PublicKey, &key.Algorithm, &key.CreatedAtMs, &key.RevokedAtMs, &key.RevocationReason)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func (r *pgRepository) RegisterTeammateKey(ctx context.Context, key *service.TeammateKey) (*service.TeammateKey, error) {
	_, err := r.pool.Exec(ctx, `INSERT INTO teammate_keys(project_id,`+teammateKeyColumns+`) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,0,'') ON CONFLICT (project_id,claim_id) DO NOTHING`, r.projectID, key.ID, key.ClaimID, key.TeammateID, key.CompanyID, key.WorkstationID, key.PublicKey, key.Algorithm, key.CreatedAtMs)
	if err != nil && !isUniqueViolation(err) {
		return nil, wrapPgErr("RegisterTeammateKey", err)
	}
	stored, readErr := scanTeammateKey(r.pool.QueryRow(ctx, `SELECT `+teammateKeyColumns+` FROM teammate_keys WHERE project_id=$1 AND claim_id=$2`, r.projectID, key.ClaimID))
	if noRows(readErr) && err != nil {
		return nil, wrapPgErr("RegisterTeammateKey", err)
	}
	return stored, readErr
}

func (r *pgRepository) GetTeammateKey(ctx context.Context, id string) (*service.TeammateKey, error) {
	key, err := scanTeammateKey(r.pool.QueryRow(ctx, `SELECT `+teammateKeyColumns+` FROM teammate_keys WHERE project_id=$1 AND id=$2`, r.projectID, id))
	if noRows(err) {
		return nil, nil
	}
	return key, err
}

func (r *pgRepository) RevokeTeammateKey(ctx context.Context, claimID, reason string, atMs int64) (bool, error) {
	var id string
	err := r.pool.QueryRow(ctx, `WITH revoked AS (UPDATE teammate_keys SET revoked_at_ms=$3,revocation_reason=$4 WHERE project_id=$1 AND claim_id=$2 AND revoked_at_ms=0 RETURNING id)
 , cleared AS (DELETE FROM teammate_key_challenges WHERE project_id=$1 AND key_id IN (SELECT id FROM revoked))
 SELECT id FROM revoked`, r.projectID, claimID, atMs, reason).Scan(&id)
	if noRows(err) {
		return false, nil
	}
	if err != nil {
		return false, wrapPgErr("RevokeTeammateKey", err)
	}
	return true, nil
}

func (r *pgRepository) CreateTeammateKeyChallenge(ctx context.Context, challenge *service.TeammateKeyChallenge) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var revoked int64
	err = tx.QueryRow(ctx, `SELECT revoked_at_ms FROM teammate_keys WHERE project_id=$1 AND id=$2 FOR UPDATE`, r.projectID, challenge.KeyID).Scan(&revoked)
	if noRows(err) || err == nil && revoked != 0 {
		return service.ErrUnauthenticated
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM teammate_key_challenges WHERE project_id=$1 AND key_id=$2 AND expires_at_ms<=$3`, r.projectID, challenge.KeyID, challenge.CreatedAtMs); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT COUNT(*) FROM teammate_key_challenges WHERE project_id=$1 AND key_id=$2`, r.projectID, challenge.KeyID).Scan(&count); err != nil {
		return err
	}
	if count >= service.MaxTeammateKeyChallenges {
		return service.ErrTeammateKeyChallengeLimit
	}
	if _, err = tx.Exec(ctx, `INSERT INTO teammate_key_challenges(project_id,id,key_id,message,created_at_ms,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6)`, r.projectID, challenge.ID, challenge.KeyID, challenge.Message, challenge.CreatedAtMs, challenge.ExpiresAtMs); err != nil {
		return wrapPgErr("CreateTeammateKeyChallenge", err)
	}
	return tx.Commit(ctx)
}

func (r *pgRepository) GetTeammateKeyChallenge(ctx context.Context, id string) (*service.TeammateKeyChallenge, error) {
	var challenge service.TeammateKeyChallenge
	err := r.pool.QueryRow(ctx, `SELECT id,key_id,message,created_at_ms,expires_at_ms FROM teammate_key_challenges WHERE project_id=$1 AND id=$2`, r.projectID, id).Scan(&challenge.ID, &challenge.KeyID, &challenge.Message, &challenge.CreatedAtMs, &challenge.ExpiresAtMs)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &challenge, nil
}

func (r *pgRepository) ConsumeTeammateKeyChallenge(ctx context.Context, id, keyID string, now int64) (bool, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM teammate_key_challenges c USING teammate_keys k WHERE c.project_id=$1 AND c.id=$2 AND c.key_id=$3 AND c.created_at_ms<=$4 AND c.expires_at_ms>$4 AND k.project_id=c.project_id AND k.id=c.key_id AND k.revoked_at_ms=0`, r.projectID, id, keyID, now)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (r *pgRepository) DeleteExpiredTeammateKeyChallenges(ctx context.Context, before int64, limit int) error {
	if limit < 1 || limit > 10000 {
		return service.ErrInvalidArgument
	}
	_, err := r.pool.Exec(ctx, `DELETE FROM teammate_key_challenges WHERE project_id=$1 AND id IN (SELECT id FROM teammate_key_challenges WHERE project_id=$1 AND expires_at_ms<=$2 ORDER BY expires_at_ms,id LIMIT $3)`, r.projectID, before, limit)
	return err
}

func (r *pgRepository) DeleteTeammateKeysRevokedBefore(ctx context.Context, before int64, limit int) error {
	if limit < 1 || limit > 10000 {
		return service.ErrInvalidArgument
	}
	_, err := r.pool.Exec(ctx, `DELETE FROM teammate_keys WHERE project_id=$1 AND id IN (SELECT id FROM teammate_keys WHERE project_id=$1 AND revoked_at_ms<>0 AND revoked_at_ms<$2 ORDER BY revoked_at_ms,id LIMIT $3)`, r.projectID, before, limit)
	return err
}
