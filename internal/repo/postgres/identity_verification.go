package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

func scanIdentityVerification(row pgx.Row) (*service.IdentityVerificationRecord, error) {
	var r service.IdentityVerificationRecord
	if err := row.Scan(
		&r.NodeID, &r.VerificationID, &r.UserID, &r.TenantID,
		&r.Provider, &r.ProviderSessionID, &r.Status,
		&r.CreatedAt, &r.UpdatedAt, &r.CompletedAt, &r.RejectionReason,
	); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *pgRepository) CreateIdentityVerification(ctx context.Context, rec *service.IdentityVerificationRecord) error {
	if rec == nil {
		return errors.New("postgres: CreateIdentityVerification: nil record")
	}
	if rec.VerificationID == "" {
		return errors.New("postgres: CreateIdentityVerification: missing verification id")
	}
	id := rec.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO identity_verifications (
			id, tenant_id, verification_id, user_id,
			provider, provider_session_id, status,
			created_at_ms, updated_at_ms, completed_at_ms, rejection_reason
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.tenantID, rec.VerificationID, rec.UserID,
		rec.Provider, rec.ProviderSessionID, rec.Status,
		rec.CreatedAt, rec.UpdatedAt, rec.CompletedAt, rec.RejectionReason,
	)
	if err != nil {
		return wrapPgErr("CreateIdentityVerification", err)
	}
	rec.NodeID = id
	return nil
}

func (r *pgRepository) GetIdentityVerification(ctx context.Context, verificationID string) (*service.IdentityVerificationRecord, error) {
	if verificationID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, verification_id, user_id, tenant_id,
		       provider, provider_session_id, status,
		       created_at_ms, updated_at_ms, completed_at_ms, rejection_reason
		  FROM identity_verifications
		 WHERE tenant_id = $1 AND verification_id = $2
		 LIMIT 1`
	row := r.pool.QueryRow(ctx, q, r.tenantID, verificationID)
	rec, err := scanIdentityVerification(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetIdentityVerification", err)
	}
	return rec, nil
}

func (r *pgRepository) GetLatestIdentityVerificationForUser(ctx context.Context, userID string) (*service.IdentityVerificationRecord, error) {
	if userID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, verification_id, user_id, tenant_id,
		       provider, provider_session_id, status,
		       created_at_ms, updated_at_ms, completed_at_ms, rejection_reason
		  FROM identity_verifications
		 WHERE tenant_id = $1 AND user_id = $2
		 ORDER BY created_at_ms DESC
		 LIMIT 1`
	row := r.pool.QueryRow(ctx, q, r.tenantID, userID)
	rec, err := scanIdentityVerification(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetLatestIdentityVerificationForUser", err)
	}
	return rec, nil
}

func (r *pgRepository) UpdateIdentityVerificationStatus(ctx context.Context, verificationID, status, rejectionReason string, completedAtMs, updatedAtMs int64) error {
	if verificationID == "" {
		return errors.New("postgres: UpdateIdentityVerificationStatus: missing verification id")
	}
	const q = `
		UPDATE identity_verifications
		   SET status = $3,
		       rejection_reason = $4,
		       completed_at_ms = $5,
		       updated_at_ms = $6
		 WHERE tenant_id = $1 AND verification_id = $2`
	if _, err := r.pool.Exec(
		ctx, q,
		r.tenantID, verificationID, status, rejectionReason, completedAtMs, updatedAtMs,
	); err != nil {
		return wrapPgErr("UpdateIdentityVerificationStatus", err)
	}
	return nil
}
