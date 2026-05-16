package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

// organizationColumns is the canonical SELECT list, expressed with a
// qualifier prefix so the JOIN in ListOrganizationsForUser does not
// trip ambiguous-column errors. The placeholder `{q}` is substituted
// by the caller with either “ (no prefix) or `o.` etc.
const organizationColumns = `id, slug, display_name, owner_user_id, created_at_ms, updated_at_ms`

func scanOrganization(row pgx.Row) (*service.Organization, error) {
	var o service.Organization
	if err := row.Scan(
		&o.ID, &o.Slug, &o.DisplayName, &o.OwnerUserID,
		&o.CreatedAtMs, &o.UpdatedAtMs,
	); err != nil {
		return nil, err
	}
	return &o, nil
}

func (r *pgRepository) CreateOrganization(ctx context.Context, o *service.Organization) (string, error) {
	if o == nil {
		return "", errors.New("postgres: CreateOrganization: nil organization")
	}
	if o.Slug == "" {
		return "", fmt.Errorf("%w: missing slug", service.ErrInvalidArgument)
	}
	if o.DisplayName == "" {
		return "", fmt.Errorf("%w: missing display_name", service.ErrInvalidArgument)
	}
	if o.OwnerUserID == "" {
		return "", fmt.Errorf("%w: missing owner_user_id", service.ErrInvalidArgument)
	}
	now := nowMs()
	if o.CreatedAtMs == 0 {
		o.CreatedAtMs = now
	}
	if o.UpdatedAtMs == 0 {
		o.UpdatedAtMs = o.CreatedAtMs
	}
	id := o.ID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO organizations (
			id, tenant_id, slug, display_name, owner_user_id,
			created_at_ms, updated_at_ms
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)`
	if _, err := r.pool.Exec(
		ctx, q,
		id, r.tenantID, o.Slug, o.DisplayName, o.OwnerUserID,
		o.CreatedAtMs, o.UpdatedAtMs,
	); err != nil {
		return "", wrapPgErr("CreateOrganization", err)
	}
	o.ID = id
	return id, nil
}

func (r *pgRepository) GetOrganization(ctx context.Context, orgID string) (*service.Organization, error) {
	if orgID == "" {
		return nil, nil
	}
	const q = `SELECT ` + organizationColumns + `
		FROM organizations
		WHERE tenant_id = $1 AND id = $2`
	row := r.pool.QueryRow(ctx, q, r.tenantID, orgID)
	o, err := scanOrganization(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetOrganization", err)
	}
	return o, nil
}

func (r *pgRepository) GetOrganizationBySlug(ctx context.Context, slug string) (*service.Organization, error) {
	if slug == "" {
		return nil, nil
	}
	const q = `SELECT ` + organizationColumns + `
		FROM organizations
		WHERE tenant_id = $1 AND slug = $2`
	row := r.pool.QueryRow(ctx, q, r.tenantID, slug)
	o, err := scanOrganization(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetOrganizationBySlug", err)
	}
	return o, nil
}

func (r *pgRepository) ListOrganizationsForUser(ctx context.Context, userID string) ([]*service.Organization, error) {
	if userID == "" {
		return nil, nil
	}
	const q = `
		SELECT o.id, o.slug, o.display_name, o.owner_user_id,
		       o.created_at_ms, o.updated_at_ms
		  FROM organizations o
		  JOIN organization_members m
		    ON m.tenant_id = o.tenant_id
		   AND m.organization_id = o.id
		 WHERE o.tenant_id = $1 AND m.user_id = $2
		 ORDER BY o.created_at_ms ASC`
	rows, err := r.pool.Query(ctx, q, r.tenantID, userID)
	if err != nil {
		return nil, wrapPgErr("ListOrganizationsForUser", err)
	}
	defer rows.Close()
	var out []*service.Organization
	for rows.Next() {
		o, err := scanOrganization(rows)
		if err != nil {
			return nil, wrapPgErr("ListOrganizationsForUser scan", err)
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListOrganizationsForUser rows", err)
	}
	return out, nil
}

func (r *pgRepository) AddOrganizationMember(ctx context.Context, m *service.OrganizationMembership) (string, error) {
	if m == nil {
		return "", errors.New("postgres: AddOrganizationMember: nil membership")
	}
	if m.OrganizationID == "" || m.UserID == "" {
		return "", fmt.Errorf("%w: missing organization_id or user_id", service.ErrInvalidArgument)
	}
	role := m.Role
	if role == "" {
		role = "member"
	}
	now := nowMs()
	if m.CreatedAtMs == 0 {
		m.CreatedAtMs = now
	}
	id := m.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO organization_members (
			id, tenant_id, organization_id, user_id, role, created_at_ms
		) VALUES (
			$1, $2, $3, $4, $5, $6
		)`
	if _, err := r.pool.Exec(
		ctx, q,
		id, r.tenantID, m.OrganizationID, m.UserID, role, m.CreatedAtMs,
	); err != nil {
		return "", wrapPgErr("AddOrganizationMember", err)
	}
	m.NodeID = id
	return id, nil
}
