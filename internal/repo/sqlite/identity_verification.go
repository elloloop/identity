package sqlite

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

func scanIdentityVerification(s scanner) (*service.IdentityVerificationRecord, error) {
	var rec service.IdentityVerificationRecord
	if err := s.Scan(
		&rec.NodeID, &rec.VerificationID, &rec.UserID, &rec.ProjectID,
		&rec.Provider, &rec.ProviderSessionID, &rec.Status,
		&rec.CreatedAt, &rec.UpdatedAt, &rec.CompletedAt, &rec.RejectionReason,
	); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (r *sqliteRepository) CreateIdentityVerification(ctx context.Context, rec *service.IdentityVerificationRecord) error {
	if rec == nil {
		return errors.New("sqlite: CreateIdentityVerification: nil record")
	}
	if rec.VerificationID == "" {
		return errors.New("sqlite: CreateIdentityVerification: missing verification id")
	}
	id := rec.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO identity_verifications (
			id, project_id, verification_id, user_id,
			provider, provider_session_id, status,
			created_at_ms, updated_at_ms, completed_at_ms, rejection_reason
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err := r.db.Exec(
		ctx, q,
		id, r.projectID, rec.VerificationID, rec.UserID,
		rec.Provider, rec.ProviderSessionID, rec.Status,
		rec.CreatedAt, rec.UpdatedAt, rec.CompletedAt, rec.RejectionReason,
	)
	if err != nil {
		return wrapErr("CreateIdentityVerification", err)
	}
	rec.NodeID = id
	return nil
}

func (r *sqliteRepository) GetIdentityVerification(ctx context.Context, verificationID string) (*service.IdentityVerificationRecord, error) {
	if verificationID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, verification_id, user_id, project_id,
		       provider, provider_session_id, status,
		       created_at_ms, updated_at_ms, completed_at_ms, rejection_reason
		  FROM identity_verifications
		 WHERE project_id = $1 AND verification_id = $2
		 LIMIT 1`
	rec, err := scanIdentityVerification(r.db.QueryRow(ctx, q, r.projectID, verificationID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("GetIdentityVerification", err)
	}
	return rec, nil
}

func (r *sqliteRepository) GetLatestIdentityVerificationForUser(ctx context.Context, userID string) (*service.IdentityVerificationRecord, error) {
	if userID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, verification_id, user_id, project_id,
		       provider, provider_session_id, status,
		       created_at_ms, updated_at_ms, completed_at_ms, rejection_reason
		  FROM identity_verifications
		 WHERE project_id = $1 AND user_id = $2
		 ORDER BY created_at_ms DESC
		 LIMIT 1`
	rec, err := scanIdentityVerification(r.db.QueryRow(ctx, q, r.projectID, userID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("GetLatestIdentityVerificationForUser", err)
	}
	return rec, nil
}

func (r *sqliteRepository) UpdateIdentityVerificationStatus(ctx context.Context, verificationID, status, rejectionReason string, completedAtMs, updatedAtMs int64) error {
	if verificationID == "" {
		return errors.New("sqlite: UpdateIdentityVerificationStatus: missing verification id")
	}
	const q = `
		UPDATE identity_verifications
		   SET status = $3, rejection_reason = $4, completed_at_ms = $5, updated_at_ms = $6
		 WHERE project_id = $1 AND verification_id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, verificationID, status, rejectionReason, completedAtMs, updatedAtMs); err != nil {
		return wrapErr("UpdateIdentityVerificationStatus", err)
	}
	return nil
}
