package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

func scanGuardianEdge(row pgx.Row) (*service.GuardianEdge, error) {
	var e service.GuardianEdge
	if err := row.Scan(&e.ProjectID, &e.GuardianUserID, &e.ChildUserID, &e.CreatedAtMs); err != nil {
		return nil, err
	}
	return &e, nil
}

func (r *pgRepository) UpsertGuardianEdge(ctx context.Context, e *service.GuardianEdge) error {
	if e == nil {
		return errors.New("postgres: UpsertGuardianEdge: nil edge")
	}
	if e.GuardianUserID == "" || e.ChildUserID == "" {
		return errors.New("postgres: UpsertGuardianEdge: missing guardian or child user id")
	}
	// DO NOTHING (not DO UPDATE): a re-upsert must preserve the original
	// created_at_ms.
	const q = `
		INSERT INTO guardian_edges (project_id, guardian_user_id, child_user_id, created_at_ms)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING`
	if _, err := r.pool.Exec(ctx, q, r.projectID, e.GuardianUserID, e.ChildUserID, e.CreatedAtMs); err != nil {
		return wrapPgErr("UpsertGuardianEdge", err)
	}
	e.ProjectID = r.projectID
	return nil
}

func (r *pgRepository) DeleteGuardianEdge(ctx context.Context, guardianUserID, childUserID string) error {
	const q = `
		DELETE FROM guardian_edges
		 WHERE project_id = $1 AND guardian_user_id = $2 AND child_user_id = $3`
	if _, err := r.pool.Exec(ctx, q, r.projectID, guardianUserID, childUserID); err != nil {
		return wrapPgErr("DeleteGuardianEdge", err)
	}
	return nil
}

func (r *pgRepository) GetGuardianEdge(ctx context.Context, guardianUserID, childUserID string) (*service.GuardianEdge, error) {
	if guardianUserID == "" || childUserID == "" {
		return nil, nil
	}
	const q = `
		SELECT project_id, guardian_user_id, child_user_id, created_at_ms
		  FROM guardian_edges
		 WHERE project_id = $1 AND guardian_user_id = $2 AND child_user_id = $3`
	e, err := scanGuardianEdge(r.pool.QueryRow(ctx, q, r.projectID, guardianUserID, childUserID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetGuardianEdge", err)
	}
	return e, nil
}

func (r *pgRepository) ListGuardiansOfChild(ctx context.Context, childUserID string) ([]*service.GuardianEdge, error) {
	const q = `
		SELECT project_id, guardian_user_id, child_user_id, created_at_ms
		  FROM guardian_edges
		 WHERE project_id = $1 AND child_user_id = $2
		 ORDER BY guardian_user_id`
	rows, err := r.pool.Query(ctx, q, r.projectID, childUserID)
	if err != nil {
		return nil, wrapPgErr("ListGuardiansOfChild", err)
	}
	defer rows.Close()
	var out []*service.GuardianEdge
	for rows.Next() {
		e, err := scanGuardianEdge(rows)
		if err != nil {
			return nil, wrapPgErr("ListGuardiansOfChild", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListGuardiansOfChild", err)
	}
	return out, nil
}

func (r *pgRepository) ListChildrenOfGuardian(ctx context.Context, guardianUserID string) ([]*service.GuardianEdge, error) {
	const q = `
		SELECT project_id, guardian_user_id, child_user_id, created_at_ms
		  FROM guardian_edges
		 WHERE project_id = $1 AND guardian_user_id = $2
		 ORDER BY child_user_id`
	rows, err := r.pool.Query(ctx, q, r.projectID, guardianUserID)
	if err != nil {
		return nil, wrapPgErr("ListChildrenOfGuardian", err)
	}
	defer rows.Close()
	var out []*service.GuardianEdge
	for rows.Next() {
		e, err := scanGuardianEdge(rows)
		if err != nil {
			return nil, wrapPgErr("ListChildrenOfGuardian", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListChildrenOfGuardian", err)
	}
	return out, nil
}
