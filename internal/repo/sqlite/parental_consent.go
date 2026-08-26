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
		&rec.Market,
	); err != nil {
		return nil, err
	}
	return &rec, nil
}

// insertParentalConsentQuery + insertParentalConsentArgs are shared by
// CreateParentalConsent and the transactional CreateManagedChildAccount so the
// two never drift on column order — the same reason insertUserQuery exists.
// The child id is passed separately because the managed-child path only learns
// it inside its transaction.
const insertParentalConsentQuery = `
	INSERT INTO parental_consents (
		id, project_id, child_user_id, consenting_user_id,
		policy_version, factors, stepped_up,
		consent_ip, consent_user_agent,
		granted_at_ms, revoked_at_ms, revoked_by_user_id,
		market
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

func insertParentalConsentArgs(projectID, childUserID string, rec *service.ParentalConsentRecord) []any {
	return []any{
		rec.ConsentID, projectID, childUserID, rec.ConsentingUserID,
		rec.PolicyVersion, rec.Factors, rec.SteppedUp,
		rec.ConsentIP, rec.ConsentUserAgent,
		rec.GrantedAt, rec.RevokedAt, rec.RevokedByUserID,
		rec.Market,
	}
}

func (r *sqliteRepository) CreateParentalConsent(ctx context.Context, rec *service.ParentalConsentRecord) error {
	if rec == nil {
		return errors.New("sqlite: CreateParentalConsent: nil record")
	}
	if rec.ConsentID == "" {
		return errors.New("sqlite: CreateParentalConsent: missing consent id")
	}
	_, err := r.db.Exec(ctx, insertParentalConsentQuery,
		insertParentalConsentArgs(r.projectID, rec.ChildUserID, rec)...)
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
		       granted_at_ms, revoked_at_ms, revoked_by_user_id,
		       market
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

// ListActiveParentalConsentsForChild returns every non-revoked consent for the
// child, newest grant first.
func (r *sqliteRepository) ListActiveParentalConsentsForChild(ctx context.Context, childUserID string) ([]*service.ParentalConsentRecord, error) {
	if childUserID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, project_id, child_user_id, consenting_user_id,
		       policy_version, factors, stepped_up,
		       consent_ip, consent_user_agent,
		       granted_at_ms, revoked_at_ms, revoked_by_user_id,
		       market
		  FROM parental_consents
		 WHERE project_id = $1 AND child_user_id = $2 AND revoked_at_ms = 0
		 ORDER BY granted_at_ms DESC, id ASC`
	rows, err := r.db.Query(ctx, q, r.projectID, childUserID)
	if err != nil {
		return nil, wrapErr("ListActiveParentalConsentsForChild", err)
	}
	defer rows.Close()

	out := make([]*service.ParentalConsentRecord, 0, 2)
	for rows.Next() {
		rec, scanErr := scanParentalConsent(rows)
		if scanErr != nil {
			return nil, wrapErr("ListActiveParentalConsentsForChild", scanErr)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr("ListActiveParentalConsentsForChild", err)
	}
	return out, nil
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
