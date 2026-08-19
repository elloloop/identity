package sqlite

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

func scanParentalConsent(s scanner) (*service.ParentalConsentRecord, error) {
	var rec service.ParentalConsentRecord
	if err := s.Scan(
		&rec.ConsentID, &rec.ProjectID, &rec.ChildUserID, &rec.ConsentingUserID,
		&rec.PolicyVersion, &rec.Factors, &rec.SteppedUp,
		&rec.ConsentIP, &rec.ConsentUserAgent,
		&rec.GrantedAt, &rec.RevokedAt, &rec.RevokedByUserID,
	); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (r *sqliteRepository) CreateParentalConsent(ctx context.Context, rec *service.ParentalConsentRecord) error {
	if rec == nil {
		return errors.New("sqlite: CreateParentalConsent: nil record")
	}
	if rec.ConsentID == "" {
		return errors.New("sqlite: CreateParentalConsent: missing consent id")
	}
	const q = `
		INSERT INTO parental_consents (
			id, project_id, child_user_id, consenting_user_id,
			policy_version, factors, stepped_up,
			consent_ip, consent_user_agent,
			granted_at_ms, revoked_at_ms, revoked_by_user_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
	_, err := r.db.Exec(
		ctx, q,
		rec.ConsentID, r.projectID, rec.ChildUserID, rec.ConsentingUserID,
		rec.PolicyVersion, rec.Factors, rec.SteppedUp,
		rec.ConsentIP, rec.ConsentUserAgent,
		rec.GrantedAt, rec.RevokedAt, rec.RevokedByUserID,
	)
	if err != nil {
		return wrapErr("CreateParentalConsent", err)
	}
	rec.ProjectID = r.projectID
	return nil
}

func (r *sqliteRepository) GetActiveParentalConsentForChild(ctx context.Context, childUserID string) (*service.ParentalConsentRecord, error) {
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
	rec, err := scanParentalConsent(r.db.QueryRow(ctx, q, r.projectID, childUserID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("GetActiveParentalConsentForChild", err)
	}
	return rec, nil
}

func (r *sqliteRepository) MarkParentalConsentRevoked(ctx context.Context, consentID, revokedByUserID string, atMs int64) error {
	if consentID == "" {
		return errors.New("sqlite: MarkParentalConsentRevoked: missing consent id")
	}
	const q = `
		UPDATE parental_consents
		   SET revoked_at_ms = $3, revoked_by_user_id = $4
		 WHERE project_id = $1 AND id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, consentID, atMs, revokedByUserID); err != nil {
		return wrapErr("MarkParentalConsentRevoked", err)
	}
	return nil
}
