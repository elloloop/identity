package sqlite

import (
	"context"
	"errors"
	"fmt"

	"github.com/elloloop/identity/internal/service"
)

func scanGuardianEdge(s scanner) (*service.GuardianEdge, error) {
	var e service.GuardianEdge
	if err := s.Scan(&e.ProjectID, &e.GuardianUserID, &e.ChildUserID, &e.CreatedAtMs); err != nil {
		return nil, err
	}
	return &e, nil
}

func (r *sqliteRepository) UpsertGuardianEdge(ctx context.Context, e *service.GuardianEdge) error {
	if e == nil {
		return errors.New("sqlite: UpsertGuardianEdge: nil edge")
	}
	if e.GuardianUserID == "" || e.ChildUserID == "" {
		return errors.New("sqlite: UpsertGuardianEdge: missing guardian or child user id")
	}
	// DO NOTHING (not an update): a re-upsert must preserve the original
	// created_at_ms.
	const q = `
		INSERT INTO guardian_edges (project_id, guardian_user_id, child_user_id, created_at_ms)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING`
	if _, err := r.db.Exec(ctx, q, r.projectID, e.GuardianUserID, e.ChildUserID, e.CreatedAtMs); err != nil {
		return wrapErr("UpsertGuardianEdge", err)
	}
	e.ProjectID = r.projectID
	return nil
}

func (r *sqliteRepository) DeleteGuardianEdge(ctx context.Context, guardianUserID, childUserID string) error {
	const q = `
		DELETE FROM guardian_edges
		 WHERE project_id = $1 AND guardian_user_id = $2 AND child_user_id = $3`
	if _, err := r.db.Exec(ctx, q, r.projectID, guardianUserID, childUserID); err != nil {
		return wrapErr("DeleteGuardianEdge", err)
	}
	return nil
}

func (r *sqliteRepository) GetGuardianEdge(ctx context.Context, guardianUserID, childUserID string) (*service.GuardianEdge, error) {
	if guardianUserID == "" || childUserID == "" {
		return nil, nil
	}
	const q = `
		SELECT project_id, guardian_user_id, child_user_id, created_at_ms
		  FROM guardian_edges
		 WHERE project_id = $1 AND guardian_user_id = $2 AND child_user_id = $3`
	e, err := scanGuardianEdge(r.db.QueryRow(ctx, q, r.projectID, guardianUserID, childUserID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("GetGuardianEdge", err)
	}
	return e, nil
}

func (r *sqliteRepository) ListGuardiansOfChild(ctx context.Context, childUserID string, limit, offset int) ([]*service.GuardianEdge, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("sqlite: ListGuardiansOfChild: limit must be > 0, got %d", limit)
	}
	if offset < 0 {
		offset = 0
	}
	const q = `
		SELECT project_id, guardian_user_id, child_user_id, created_at_ms
		  FROM guardian_edges
		 WHERE project_id = $1 AND child_user_id = $2
		 ORDER BY guardian_user_id
		 LIMIT $3 OFFSET $4`
	rows, err := r.db.Query(ctx, q, r.projectID, childUserID, limit, offset)
	if err != nil {
		return nil, wrapErr("ListGuardiansOfChild", err)
	}
	defer rows.Close()
	var out []*service.GuardianEdge
	for rows.Next() {
		e, err := scanGuardianEdge(rows)
		if err != nil {
			return nil, wrapErr("ListGuardiansOfChild", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr("ListGuardiansOfChild", err)
	}
	return out, nil
}

func (r *sqliteRepository) ListChildrenOfGuardian(ctx context.Context, guardianUserID string, limit, offset int) ([]*service.GuardianEdge, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("sqlite: ListChildrenOfGuardian: limit must be > 0, got %d", limit)
	}
	if offset < 0 {
		offset = 0
	}
	const q = `
		SELECT project_id, guardian_user_id, child_user_id, created_at_ms
		  FROM guardian_edges
		 WHERE project_id = $1 AND guardian_user_id = $2
		 ORDER BY child_user_id
		 LIMIT $3 OFFSET $4`
	rows, err := r.db.Query(ctx, q, r.projectID, guardianUserID, limit, offset)
	if err != nil {
		return nil, wrapErr("ListChildrenOfGuardian", err)
	}
	defer rows.Close()
	var out []*service.GuardianEdge
	for rows.Next() {
		e, err := scanGuardianEdge(rows)
		if err != nil {
			return nil, wrapErr("ListChildrenOfGuardian", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr("ListChildrenOfGuardian", err)
	}
	return out, nil
}
