package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

const teammateKeyColumns = `id,claim_id,teammate_id,company_id,workstation_id,public_key,algorithm,grant_id,owner_user_id,created_at_ms,revoked_at_ms,revocation_reason`

func scanTeammateKey(row pgx.Row) (*service.TeammateKey, error) {
	var key service.TeammateKey
	err := row.Scan(&key.ID, &key.ClaimID, &key.TeammateID, &key.CompanyID, &key.WorkstationID, &key.PublicKey, &key.Algorithm, &key.GrantID, &key.OwnerUserID, &key.CreatedAtMs, &key.RevokedAtMs, &key.RevocationReason)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func (r *pgRepository) CreateHireGrant(ctx context.Context, grant *service.HireGrant) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO hire_grants(project_id,id,owner_user_id,teammate_id,placement_id,company_id,created_at_ms,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, r.projectID, grant.ID, grant.OwnerUserID, grant.TeammateID, grant.PlacementID, grant.CompanyID, grant.CreatedAtMs, grant.ExpiresAtMs)
	return wrapPgErr("CreateHireGrant", err)
}

func (r *pgRepository) RegisterTeammateKey(ctx context.Context, key *service.TeammateKey, placementID string) (*service.TeammateKey, error) {
	inserted, err := r.registerGrantedTeammateKey(ctx, key, placementID)
	if err != nil && !errors.Is(err, service.ErrHireGrantRefused) {
		return nil, err
	}
	if inserted {
		return r.teammateKeyOfClaim(ctx, key.ClaimID)
	}
	stored, readErr := r.teammateKeyOfClaim(ctx, key.ClaimID)
	switch {
	case readErr != nil:
		return nil, readErr
	case stored != nil:
		return stored, nil
	case err != nil:
		return nil, err
	}
	return nil, fmt.Errorf("postgres: RegisterTeammateKey: claim %q lost its key during registration", key.ClaimID)
}

// registerGrantedTeammateKey consumes the grant and inserts the key in one
// transaction, and reports whether it did. Consuming the grant first holds
// its row, so a concurrent registration of the same claim waits and then
// finds the grant used and the key stored. A claim that already has a key
// leaves the grant unused.
func (r *pgRepository) registerGrantedTeammateKey(ctx context.Context, key *service.TeammateKey, placementID string) (bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var owner string
	err = tx.QueryRow(ctx, `UPDATE hire_grants SET used_at_ms=$3,used_claim_id=$4 WHERE project_id=$1 AND id=$2 AND used_claim_id='' AND expires_at_ms>$3 AND teammate_id=$5 AND placement_id=$6 AND company_id=$7 RETURNING owner_user_id`,
		r.projectID, key.GrantID, key.CreatedAtMs, key.ClaimID, key.TeammateID, placementID, key.CompanyID).Scan(&owner)
	if noRows(err) {
		return false, service.ErrHireGrantRefused
	}
	if err != nil {
		return false, wrapPgErr("RegisterTeammateKey", err)
	}
	tag, err := tx.Exec(ctx, `INSERT INTO teammate_keys(project_id,`+teammateKeyColumns+`) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,0,'') ON CONFLICT (project_id,claim_id) DO NOTHING`,
		r.projectID, key.ID, key.ClaimID, key.TeammateID, key.CompanyID, key.WorkstationID, key.PublicKey, key.Algorithm, key.GrantID, owner, key.CreatedAtMs)
	if err != nil {
		return false, wrapPgErr("RegisterTeammateKey", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	if err = tx.Commit(ctx); err != nil {
		return false, wrapPgErr("RegisterTeammateKey", err)
	}
	return true, nil
}

func (r *pgRepository) teammateKeyOfClaim(ctx context.Context, claimID string) (*service.TeammateKey, error) {
	key, err := scanTeammateKey(r.pool.QueryRow(ctx, `SELECT `+teammateKeyColumns+` FROM teammate_keys WHERE project_id=$1 AND claim_id=$2`, r.projectID, claimID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("RegisterTeammateKey", err)
	}
	return key, nil
}

func (r *pgRepository) GetTeammateKey(ctx context.Context, id string) (*service.TeammateKey, error) {
	key, err := scanTeammateKey(r.pool.QueryRow(ctx, `SELECT `+teammateKeyColumns+` FROM teammate_keys WHERE project_id=$1 AND id=$2`, r.projectID, id))
	if noRows(err) {
		return nil, nil
	}
	return key, err
}

func (r *pgRepository) RevokeTeammateKey(ctx context.Context, claimID, reason string, atMs, nowMs int64) (int64, bool, error) {
	var stopsAt int64
	err := r.pool.QueryRow(ctx, `WITH revoked AS (UPDATE teammate_keys SET revoked_at_ms=$3,revocation_reason=$4 WHERE project_id=$1 AND claim_id=$2 AND (revoked_at_ms=0 OR revoked_at_ms>$3) RETURNING id,revoked_at_ms)
 , cleared AS (DELETE FROM teammate_key_challenges WHERE project_id=$1 AND $3<=$5 AND key_id IN (SELECT id FROM revoked))
 SELECT revoked_at_ms FROM revoked`, r.projectID, claimID, atMs, reason, nowMs).Scan(&stopsAt)
	if err == nil {
		return stopsAt, true, nil
	}
	if !noRows(err) {
		return 0, false, wrapPgErr("RevokeTeammateKey", err)
	}
	err = r.pool.QueryRow(ctx, `SELECT revoked_at_ms FROM teammate_keys WHERE project_id=$1 AND claim_id=$2`, r.projectID, claimID).Scan(&stopsAt)
	if noRows(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, wrapPgErr("RevokeTeammateKey", err)
	}
	return stopsAt, false, nil
}

func (r *pgRepository) CreateTeammateKeyChallenge(ctx context.Context, challenge *service.TeammateKeyChallenge) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var revoked int64
	err = tx.QueryRow(ctx, `SELECT revoked_at_ms FROM teammate_keys WHERE project_id=$1 AND id=$2 FOR UPDATE`, r.projectID, challenge.KeyID).Scan(&revoked)
	if noRows(err) || err == nil && revoked != 0 && revoked <= challenge.CreatedAtMs {
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
	tag, err := r.pool.Exec(ctx, `DELETE FROM teammate_key_challenges c USING teammate_keys k WHERE c.project_id=$1 AND c.id=$2 AND c.key_id=$3 AND c.created_at_ms<=$4 AND c.expires_at_ms>$4 AND k.project_id=c.project_id AND k.id=c.key_id AND (k.revoked_at_ms=0 OR k.revoked_at_ms>$4)`, r.projectID, id, keyID, now)
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

func (r *pgRepository) DeleteHireGrantsExpiredBefore(ctx context.Context, before int64, limit int) error {
	if limit < 1 || limit > 10000 {
		return service.ErrInvalidArgument
	}
	_, err := r.pool.Exec(ctx, `DELETE FROM hire_grants WHERE project_id=$1 AND id IN (SELECT id FROM hire_grants WHERE project_id=$1 AND expires_at_ms<=$2 ORDER BY expires_at_ms,id LIMIT $3)`, r.projectID, before, limit)
	return err
}

func (r *pgRepository) DeleteTeammateKeysRevokedBefore(ctx context.Context, before int64, limit int) error {
	if limit < 1 || limit > 10000 {
		return service.ErrInvalidArgument
	}
	_, err := r.pool.Exec(ctx, `DELETE FROM teammate_keys WHERE project_id=$1 AND id IN (SELECT id FROM teammate_keys WHERE project_id=$1 AND revoked_at_ms<>0 AND revoked_at_ms<$2 ORDER BY revoked_at_ms,id LIMIT $3)`, r.projectID, before, limit)
	return err
}
