package postgres

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

// ── RBAC: custom roles + per-user role assignments ─────────────────────

func (r *pgRepository) CreateRole(ctx context.Context, rec *service.RoleRecord) (string, error) {
	if rec == nil {
		return "", errors.New("postgres: CreateRole: nil record")
	}
	id := rec.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO rbac_roles (
			id, project_id, name, description, permissions,
			created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.pool.Exec(
		ctx, q,
		id, r.projectID, rec.Name, rec.Description, rec.Permissions,
		rec.CreatedAt, rec.UpdatedAt,
	)
	if err != nil {
		return "", wrapPgErr("CreateRole", err)
	}
	rec.NodeID = id
	return id, nil
}

func (r *pgRepository) GetRoleByName(ctx context.Context, name string) (*service.RoleRecord, error) {
	if name == "" {
		return nil, nil
	}
	const q = `
		SELECT id, name, description, permissions, created_at_ms, updated_at_ms
		  FROM rbac_roles
		 WHERE project_id = $1 AND name = $2
		 LIMIT 1`
	var rec service.RoleRecord
	err := r.pool.QueryRow(ctx, q, r.projectID, name).Scan(
		&rec.NodeID, &rec.Name, &rec.Description, &rec.Permissions,
		&rec.CreatedAt, &rec.UpdatedAt,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetRoleByName", err)
	}
	return &rec, nil
}

func (r *pgRepository) ListRoles(ctx context.Context) ([]*service.RoleRecord, error) {
	const q = `
		SELECT id, name, description, permissions, created_at_ms, updated_at_ms
		  FROM rbac_roles
		 WHERE project_id = $1
		 ORDER BY name ASC`
	rows, err := r.pool.Query(ctx, q, r.projectID)
	if err != nil {
		return nil, wrapPgErr("ListRoles", err)
	}
	defer rows.Close()
	var out []*service.RoleRecord
	for rows.Next() {
		var rec service.RoleRecord
		if err := rows.Scan(
			&rec.NodeID, &rec.Name, &rec.Description, &rec.Permissions,
			&rec.CreatedAt, &rec.UpdatedAt,
		); err != nil {
			return nil, wrapPgErr("ListRoles(scan)", err)
		}
		out = append(out, &rec)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListRoles(rows)", err)
	}
	return out, nil
}

func (r *pgRepository) DeleteRole(ctx context.Context, name string) error {
	if name == "" {
		return nil
	}
	// Assignments FK to rbac_roles(project_id, name) ON DELETE CASCADE,
	// so deleting the role drops the dangling assignments automatically.
	const q = `DELETE FROM rbac_roles WHERE project_id = $1 AND name = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, name); err != nil {
		return wrapPgErr("DeleteRole", err)
	}
	return nil
}

func (r *pgRepository) SetUserRoleAssignment(ctx context.Context, userID, roleName string, atMs int64) error {
	if userID == "" {
		return errors.New("postgres: SetUserRoleAssignment: missing user id")
	}
	const q = `
		INSERT INTO rbac_role_assignments (id, project_id, user_id, role_name, created_at_ms)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (project_id, user_id)
		DO UPDATE SET role_name = EXCLUDED.role_name, created_at_ms = EXCLUDED.created_at_ms`
	if _, err := r.pool.Exec(ctx, q, newID(), r.projectID, userID, roleName, atMs); err != nil {
		return wrapPgErr("SetUserRoleAssignment", err)
	}
	return nil
}

func (r *pgRepository) GetUserRoleAssignment(ctx context.Context, userID string) (*service.RoleAssignmentRecord, error) {
	if userID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, user_id, role_name, created_at_ms
		  FROM rbac_role_assignments
		 WHERE project_id = $1 AND user_id = $2
		 LIMIT 1`
	var rec service.RoleAssignmentRecord
	err := r.pool.QueryRow(ctx, q, r.projectID, userID).Scan(
		&rec.NodeID, &rec.UserID, &rec.RoleName, &rec.CreatedAt,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetUserRoleAssignment", err)
	}
	return &rec, nil
}

func (r *pgRepository) DeleteUserRoleAssignment(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	const q = `DELETE FROM rbac_role_assignments WHERE project_id = $1 AND user_id = $2`
	if _, err := r.pool.Exec(ctx, q, r.projectID, userID); err != nil {
		return wrapPgErr("DeleteUserRoleAssignment", err)
	}
	return nil
}
