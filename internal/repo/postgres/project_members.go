package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

// projectCreateLockNamespace names the advisory lock that serializes one
// account's project creations, so the per-account limit is counted and
// spent under one lock.
const projectCreateLockNamespace = "project_create"

// memberProjectQuery selects a project as one of its members sees it: the
// project, the member's role, and the project's oldest active publishable
// credential (” when it has none). Only an ACTIVE project is returned: a
// suspended project serves nothing, its console included. Callers append the
// rest of the WHERE clause and the ordering.
const memberProjectQuery = `
	SELECT p.id, p.name, m.role, p.created_at_ms,
	       COALESCE((
	           SELECT c.public_id FROM project_credentials c
	           WHERE c.project_id = p.id AND c.kind = '` + service.CredentialKindPublishable + `'
	             AND c.status = '` + credentialStatusActive + `'
	           ORDER BY c.created_at_ms, c.id
	           LIMIT 1
	       ), '')
	FROM project_members m
	JOIN projects p ON p.id = m.project_id
	WHERE m.user_id = $1 AND p.status = '` + projectStatusActive + `'`

func scanMemberProject(row pgx.Row) (*service.MemberProject, error) {
	var p service.MemberProject
	if err := row.Scan(&p.ID, &p.Name, &p.Role, &p.CreatedAtMs, &p.PublishableKey); err != nil {
		return nil, err
	}
	return &p, nil
}

// CreateOwnedProject creates a project, its creator's owner membership and
// its first publishable credential in one transaction, so a project is never
// left without an owner or without the key an application selects it by.
//
// The projects req.OwnerID already owns are counted under a
// transaction-scoped advisory lock keyed on the owner, so two concurrent
// requests from one account are serialized and cannot both pass a limit only
// one of them fits under. Suspended projects count: suspending one does not
// hand its owner another.
//
// The project is its own storage scope: storage_scope_id is the new project's
// id, which is unique because the id is.
func (s *ProjectStore) CreateOwnedProject(ctx context.Context, req service.OwnedProjectRequest) (*service.MemberProject, error) {
	if req.OwnerID == "" || req.Name == "" || req.PublishableKey == "" {
		return nil, fmt.Errorf("%w: owner_id, name and publishable_key are required", service.ErrInvalidArgument)
	}
	if req.MaxOwned <= 0 {
		return nil, fmt.Errorf("%w: max_owned must be positive", service.ErrInvalidArgument)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, wrapPgErr("CreateOwnedProject", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := lockXact(ctx, tx, "CreateOwnedProject", advisoryKey(projectCreateLockNamespace, req.OwnerID)); err != nil {
		return nil, err
	}

	var owned int
	if err := tx.QueryRow(
		ctx, `SELECT count(*) FROM project_members WHERE user_id = $1 AND role = $2`,
		req.OwnerID, service.ProjectRoleOwner,
	).Scan(&owned); err != nil {
		return nil, wrapPgErr("CreateOwnedProject(count)", err)
	}
	if owned >= req.MaxOwned {
		return nil, service.ErrProjectCreationLimited
	}

	now := req.NowMs
	if now == 0 {
		now = nowMs()
	}
	project := &service.MemberProject{
		ID:             newID(),
		Name:           req.Name,
		Role:           service.ProjectRoleOwner,
		PublishableKey: req.PublishableKey,
		CreatedAtMs:    now,
	}
	if _, err := tx.Exec(
		ctx, `
		INSERT INTO projects (
			id, storage_scope_id, name, status, config_json,
			created_at_ms, updated_at_ms
		) VALUES ($1, $1, $2, $3, '{}'::jsonb, $4, $4)`,
		project.ID, project.Name, projectStatusActive, now,
	); err != nil {
		return nil, wrapPgErr("CreateOwnedProject(project)", err)
	}
	if _, err := tx.Exec(
		ctx, `
		INSERT INTO project_members (project_id, user_id, role, created_at_ms)
		VALUES ($1, $2, $3, $4)`,
		project.ID, req.OwnerID, project.Role, now,
	); err != nil {
		return nil, wrapPgErr("CreateOwnedProject(member)", err)
	}
	if _, err := tx.Exec(
		ctx, `
		INSERT INTO project_credentials (
			id, project_id, kind, public_id, secret_hash, status,
			created_at_ms, last_used_at_ms, revoked_at_ms
		) VALUES ($1, $2, $3, $4, '', $5, $6, 0, 0)`,
		newID(), project.ID, service.CredentialKindPublishable, project.PublishableKey,
		credentialStatusActive, now,
	); err != nil {
		return nil, wrapPgErr("CreateOwnedProject(credential)", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, wrapPgErr("CreateOwnedProject(commit)", err)
	}
	return project, nil
}

// ListMemberProjects returns the active projects userID is a member of,
// oldest first.
func (s *ProjectStore) ListMemberProjects(ctx context.Context, userID string) ([]*service.MemberProject, error) {
	rows, err := s.pool.Query(ctx, memberProjectQuery+` ORDER BY p.created_at_ms, p.id`, userID)
	if err != nil {
		return nil, wrapPgErr("ListMemberProjects", err)
	}
	defer rows.Close()
	var out []*service.MemberProject
	for rows.Next() {
		p, err := scanMemberProject(rows)
		if err != nil {
			return nil, wrapPgErr("ListMemberProjects scan", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListMemberProjects rows", err)
	}
	return out, nil
}

// GetMemberProject returns projectID as its member userID sees it, or
// (nil, nil) when userID is not a member of it, the project does not exist,
// or it is suspended: the three are one answer, so a caller cannot tell a
// project they do not belong to from one that is not there.
func (s *ProjectStore) GetMemberProject(ctx context.Context, projectID, userID string) (*service.MemberProject, error) {
	p, err := scanMemberProject(s.pool.QueryRow(ctx, memberProjectQuery+` AND p.id = $2`, userID, projectID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetMemberProject", err)
	}
	return p, nil
}
