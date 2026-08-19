package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

func scanParentalConsent(row pgx.Row) (*service.ParentalConsentRecord, error) {
	var r service.ParentalConsentRecord
	if err := row.Scan(
		&r.ConsentID, &r.ProjectID, &r.ChildUserID, &r.ConsentingUserID,
		&r.PolicyVersion, &r.Factors, &r.SteppedUp,
		&r.ConsentIP, &r.ConsentUserAgent,
		&r.GrantedAt, &r.RevokedAt, &r.RevokedByUserID,
	); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *pgRepository) CreateParentalConsent(ctx context.Context, rec *service.ParentalConsentRecord) error {
	if rec == nil {
		return errors.New("postgres: CreateParentalConsent: nil record")
	}
	if rec.ConsentID == "" {
		return errors.New("postgres: CreateParentalConsent: missing consent id")
	}
	const q = `
		INSERT INTO parental_consents (
			id, project_id, child_user_id, consenting_user_id,
			policy_version, factors, stepped_up,
			consent_ip, consent_user_agent,
			granted_at_ms, revoked_at_ms, revoked_by_user_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
	_, err := r.pool.Exec(
		ctx, q,
		rec.ConsentID, r.projectID, rec.ChildUserID, rec.ConsentingUserID,
		rec.PolicyVersion, rec.Factors, rec.SteppedUp,
		rec.ConsentIP, rec.ConsentUserAgent,
		rec.GrantedAt, rec.RevokedAt, rec.RevokedByUserID,
	)
	if err != nil {
		return wrapPgErr("CreateParentalConsent", err)
	}
	rec.ProjectID = r.projectID
	return nil
}

func (r *pgRepository) GetActiveParentalConsentForChild(ctx context.Context, childUserID string) (*service.ParentalConsentRecord, error) {
	if childUserID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, project_id, child_user_id, consenting_user_id,
		       policy_version, factors, stepped_up,
		       consent_ip, consent_user_agent,
		       granted_at_ms, revoked_at_ms, revoked_by_user_id
		  FROM parental_consents
		 WHERE project_id = $1 AND child_user_id = $2 AND revoked_at_ms = 0
		 ORDER BY granted_at_ms DESC
		 LIMIT 1`
	rec, err := scanParentalConsent(r.pool.QueryRow(ctx, q, r.projectID, childUserID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetActiveParentalConsentForChild", err)
	}
	return rec, nil
}

func (r *pgRepository) MarkParentalConsentRevoked(ctx context.Context, consentID, revokedByUserID string, atMs int64) error {
	if consentID == "" {
		return errors.New("postgres: MarkParentalConsentRevoked: missing consent id")
	}
	const q = `
		UPDATE parental_consents
		   SET revoked_at_ms = $3, revoked_by_user_id = $4
		 WHERE project_id = $1 AND id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, consentID, atMs, revokedByUserID); err != nil {
		return wrapPgErr("MarkParentalConsentRevoked", err)
	}
	return nil
}
