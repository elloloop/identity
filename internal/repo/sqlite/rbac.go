package sqlite

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

// ── RBAC: custom roles + per-user role assignments ─────────────────────
//
// SQLite has no native array type, so a role's permission set is stored
// as a JSON text column and (de)serialised at the driver boundary. The
// canonical ordering is established by the service layer before write, so
// round-tripping preserves it.

func marshalPermissions(perms []string) (string, error) {
	if perms == nil {
		perms = []string{}
	}
	b, err := json.Marshal(perms)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unmarshalPermissions(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *sqliteRepository) CreateRole(ctx context.Context, rec *service.RoleRecord) (string, error) {
	if rec == nil {
		return "", errors.New("sqlite: CreateRole: nil record")
	}
	id := rec.NodeID
	if id == "" {
		id = newID()
	}
	permsJSON, err := marshalPermissions(rec.Permissions)
	if err != nil {
		return "", wrapErr("CreateRole(marshal)", err)
	}
	const q = `
		INSERT INTO rbac_roles (
			id, project_id, name, description, permissions, created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	if _, err := r.db.Exec(ctx, q, id, r.projectID, rec.Name, rec.Description, permsJSON, rec.CreatedAt, rec.UpdatedAt); err != nil {
		return "", wrapErr("CreateRole", err)
	}
	rec.NodeID = id
	return id, nil
}

func (r *sqliteRepository) GetRoleByName(ctx context.Context, name string) (*service.RoleRecord, error) {
	if name == "" {
		return nil, nil
	}
	const q = `
		SELECT id, name, description, permissions, created_at_ms, updated_at_ms
		  FROM rbac_roles
		 WHERE project_id = $1 AND name = $2
		 LIMIT 1`
	var (
		rec       service.RoleRecord
		permsJSON string
	)
	err := r.db.QueryRow(ctx, q, r.projectID, name).Scan(
		&rec.NodeID, &rec.Name, &rec.Description, &permsJSON, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("GetRoleByName", err)
	}
	if rec.Permissions, err = unmarshalPermissions(permsJSON); err != nil {
		return nil, wrapErr("GetRoleByName(unmarshal)", err)
	}
	return &rec, nil
}

func (r *sqliteRepository) ListRoles(ctx context.Context) ([]*service.RoleRecord, error) {
	const q = `
		SELECT id, name, description, permissions, created_at_ms, updated_at_ms
		  FROM rbac_roles
		 WHERE project_id = $1
		 ORDER BY name ASC`
	rows, err := r.db.Query(ctx, q, r.projectID)
	if err != nil {
		return nil, wrapErr("ListRoles", err)
	}
	defer rows.Close()
	var out []*service.RoleRecord
	for rows.Next() {
		var (
			rec       service.RoleRecord
			permsJSON string
		)
		if err := rows.Scan(&rec.NodeID, &rec.Name, &rec.Description, &permsJSON, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
			return nil, wrapErr("ListRoles(scan)", err)
		}
		if rec.Permissions, err = unmarshalPermissions(permsJSON); err != nil {
			return nil, wrapErr("ListRoles(unmarshal)", err)
		}
		out = append(out, &rec)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr("ListRoles(rows)", err)
	}
	return out, nil
}

func (r *sqliteRepository) DeleteRole(ctx context.Context, name string) error {
	if name == "" {
		return nil
	}
	const q = `DELETE FROM rbac_roles WHERE project_id = $1 AND name = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, name); err != nil {
		return wrapErr("DeleteRole", err)
	}
	return nil
}

func (r *sqliteRepository) SetUserRoleAssignment(ctx context.Context, userID, roleName string, atMs int64) error {
	if userID == "" {
		return errors.New("sqlite: SetUserRoleAssignment: missing user id")
	}
	const q = `
		INSERT INTO rbac_role_assignments (id, project_id, user_id, role_name, created_at_ms)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (project_id, user_id)
		DO UPDATE SET role_name = excluded.role_name, created_at_ms = excluded.created_at_ms`
	if _, err := r.db.Exec(ctx, q, newID(), r.projectID, userID, roleName, atMs); err != nil {
		return wrapErr("SetUserRoleAssignment", err)
	}
	return nil
}

func (r *sqliteRepository) GetUserRoleAssignment(ctx context.Context, userID string) (*service.RoleAssignmentRecord, error) {
	if userID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, user_id, role_name, created_at_ms
		  FROM rbac_role_assignments
		 WHERE project_id = $1 AND user_id = $2
		 LIMIT 1`
	var rec service.RoleAssignmentRecord
	err := r.db.QueryRow(ctx, q, r.projectID, userID).Scan(
		&rec.NodeID, &rec.UserID, &rec.RoleName, &rec.CreatedAt,
	)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("GetUserRoleAssignment", err)
	}
	return &rec, nil
}

func (r *sqliteRepository) DeleteUserRoleAssignment(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	const q = `DELETE FROM rbac_role_assignments WHERE project_id = $1 AND user_id = $2`
	if _, err := r.db.Exec(ctx, q, r.projectID, userID); err != nil {
		return wrapErr("DeleteUserRoleAssignment", err)
	}
	return nil
}
