package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

// Postgres-backed MembershipStore + InvitationStore over migration 0013's
// tenant_memberships and tenant_invitations tables. Postgres-only and
// project-scoped like the other governance stores.

var (
	_ service.MembershipStore = (*MembershipStore)(nil)
	_ service.InvitationStore = (*InvitationStore)(nil)
)

// ── tenant_memberships ──────────────────────────────────────────────────

// MembershipStore persists TenantMemberships within a Project.
type MembershipStore struct {
	pool *tracedPool
}

// NewMembershipStore builds a store sharing the repository's pool.
func NewMembershipStore(r *pgRepository) *MembershipStore {
	return &MembershipStore{pool: r.pool}
}

const membershipColumns = `
	id, project_id, tenant_id, user_id, source, role, status,
	created_at_ms, updated_at_ms`

func scanMembership(row pgx.Row) (*service.TenantMembership, error) {
	var m service.TenantMembership
	if err := row.Scan(
		&m.ID, &m.ProjectID, &m.TenantID, &m.UserID, &m.Source, &m.Role, &m.Status,
		&m.CreatedAtMs, &m.UpdatedAtMs,
	); err != nil {
		return nil, err
	}
	return &m, nil
}

// UpsertMembership inserts or, on a (project, tenant, user) conflict,
// updates source/role/status in place (keeping id + created_at_ms) and
// stamps updated_at_ms. Returns the surviving row id.
func (s *MembershipStore) UpsertMembership(ctx context.Context, m *service.TenantMembership) (string, error) {
	if m == nil {
		return "", errors.New("postgres: UpsertMembership: nil membership")
	}
	if m.ProjectID == "" || m.TenantID == "" || m.UserID == "" {
		return "", fmt.Errorf("%w: project_id, tenant_id and user_id are required", service.ErrInvalidArgument)
	}
	now := nowMs()
	if m.CreatedAtMs == 0 {
		m.CreatedAtMs = now
	}
	id := m.ID
	if id == "" {
		id = newID()
	}
	source := m.Source
	if source == "" {
		source = service.MembershipSourceAdded
	}
	role := m.Role
	if role == "" {
		role = service.RoleMember
	}
	status := m.Status
	if status == "" {
		status = service.MembershipStatusActive
	}
	const q = `
		INSERT INTO tenant_memberships (
			id, project_id, tenant_id, user_id, source, role, status,
			created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
		ON CONFLICT (project_id, tenant_id, user_id) DO UPDATE SET
			source        = EXCLUDED.source,
			role          = EXCLUDED.role,
			status        = EXCLUDED.status,
			updated_at_ms = EXCLUDED.updated_at_ms
		RETURNING id`
	var outID string
	if err := s.pool.QueryRow(
		ctx, q,
		id, m.ProjectID, m.TenantID, m.UserID, source, role, status, now,
	).Scan(&outID); err != nil {
		return "", wrapPgErr("UpsertMembership", err)
	}
	m.ID = outID
	m.Source, m.Role, m.Status, m.UpdatedAtMs = source, role, status, now
	return outID, nil
}

// GetMembership returns the membership for (project, tenant, user), or
// (nil, nil).
func (s *MembershipStore) GetMembership(ctx context.Context, projectID, tenantID, userID string) (*service.TenantMembership, error) {
	if projectID == "" || tenantID == "" || userID == "" {
		return nil, nil
	}
	const q = `SELECT ` + membershipColumns + `
		FROM tenant_memberships
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3`
	m, err := scanMembership(s.pool.QueryRow(ctx, q, projectID, tenantID, userID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetMembership", err)
	}
	return m, nil
}

// ListMembershipsForUser returns every membership a user holds across a
// project's tenants, newest first.
func (s *MembershipStore) ListMembershipsForUser(ctx context.Context, projectID, userID string) ([]*service.TenantMembership, error) {
	if projectID == "" || userID == "" {
		return nil, nil
	}
	const q = `SELECT ` + membershipColumns + `
		FROM tenant_memberships WHERE project_id = $1 AND user_id = $2
		ORDER BY created_at_ms DESC, id DESC`
	return s.queryMemberships(ctx, "ListMembershipsForUser", q, projectID, userID)
}

// ListMembershipsForTenant returns every membership in a tenant, newest
// first.
func (s *MembershipStore) ListMembershipsForTenant(ctx context.Context, projectID, tenantID string) ([]*service.TenantMembership, error) {
	if projectID == "" || tenantID == "" {
		return nil, nil
	}
	const q = `SELECT ` + membershipColumns + `
		FROM tenant_memberships WHERE project_id = $1 AND tenant_id = $2
		ORDER BY created_at_ms DESC, id DESC`
	return s.queryMemberships(ctx, "ListMembershipsForTenant", q, projectID, tenantID)
}

func (s *MembershipStore) queryMemberships(ctx context.Context, op, q string, args ...any) ([]*service.TenantMembership, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, wrapPgErr(op, err)
	}
	defer rows.Close()
	var out []*service.TenantMembership
	for rows.Next() {
		m, err := scanMembership(rows)
		if err != nil {
			return nil, wrapPgErr(op+" scan", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr(op+" rows", err)
	}
	return out, nil
}

// RemoveMembership deletes the membership for (project, tenant, user).
// Unknown rows are a no-op.
func (s *MembershipStore) RemoveMembership(ctx context.Context, projectID, tenantID, userID string) error {
	if projectID == "" || tenantID == "" || userID == "" {
		return fmt.Errorf("%w: project_id, tenant_id and user_id are required", service.ErrInvalidArgument)
	}
	const q = `DELETE FROM tenant_memberships
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3`
	if _, err := s.pool.Exec(ctx, q, projectID, tenantID, userID); err != nil {
		return wrapPgErr("RemoveMembership", err)
	}
	return nil
}

// ── tenant_invitations ──────────────────────────────────────────────────

// InvitationStore persists TenantInvitations within a Project.
type InvitationStore struct {
	pool *tracedPool
}

// NewInvitationStore builds a store sharing the repository's pool.
func NewInvitationStore(r *pgRepository) *InvitationStore {
	return &InvitationStore{pool: r.pool}
}

const invitationColumns = `
	id, project_id, tenant_id, token_hash, email, invited_by, role, status,
	expires_at_ms, accepted_at_ms, created_at_ms`

func scanInvitation(row pgx.Row) (*service.TenantInvitation, error) {
	var v service.TenantInvitation
	if err := row.Scan(
		&v.ID, &v.ProjectID, &v.TenantID, &v.TokenHash, &v.Email, &v.InvitedBy,
		&v.Role, &v.Status, &v.ExpiresAtMs, &v.AcceptedAtMs, &v.CreatedAtMs,
	); err != nil {
		return nil, err
	}
	return &v, nil
}

// CreateInvitation atomically enforces one-open-invite: in a single
// transaction it revokes any existing pending invitation for the same
// (project, tenant, lower(email)) and inserts the new one. This is the
// authoritative enforcement (the partial unique index is defense-in-depth,
// and the memory driver — should they ever gain invitations — must
// match these revoke-then-insert semantics).
func (s *InvitationStore) CreateInvitation(ctx context.Context, inv *service.TenantInvitation) (string, error) {
	if inv == nil {
		return "", errors.New("postgres: CreateInvitation: nil invitation")
	}
	if inv.ProjectID == "" || inv.TenantID == "" {
		return "", fmt.Errorf("%w: project_id and tenant_id are required", service.ErrInvalidArgument)
	}
	if inv.Email == "" {
		return "", fmt.Errorf("%w: email is required", service.ErrInvalidArgument)
	}
	if inv.TokenHash == "" {
		return "", fmt.Errorf("%w: token_hash is required", service.ErrInvalidArgument)
	}
	if inv.ExpiresAtMs == 0 {
		return "", fmt.Errorf("%w: expires_at_ms is required", service.ErrInvalidArgument)
	}
	now := nowMs()
	if inv.CreatedAtMs == 0 {
		inv.CreatedAtMs = now
	}
	id := inv.ID
	if id == "" {
		id = newID()
	}
	role := inv.Role
	if role == "" {
		role = service.RoleMember
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", wrapPgErr("CreateInvitation", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Revoke any open invite for the same recipient first, so the new one
	// is the only pending row — one open invite per (project, tenant, email).
	if _, err := tx.Exec(
		ctx, `
		UPDATE tenant_invitations SET status = 'revoked'
		WHERE project_id = $1 AND tenant_id = $2
		  AND lower(email) = lower($3) AND status = 'pending'`,
		inv.ProjectID, inv.TenantID, inv.Email,
	); err != nil {
		return "", wrapPgErr("CreateInvitation(revoke)", err)
	}

	if _, err := tx.Exec(
		ctx, `
		INSERT INTO tenant_invitations (
			id, project_id, tenant_id, token_hash, email, invited_by, role,
			status, expires_at_ms, accepted_at_ms, created_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, 0, $9)`,
		id, inv.ProjectID, inv.TenantID, inv.TokenHash, inv.Email, inv.InvitedBy,
		role, inv.ExpiresAtMs, inv.CreatedAtMs,
	); err != nil {
		return "", wrapPgErr("CreateInvitation(insert)", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", wrapPgErr("CreateInvitation(commit)", err)
	}
	inv.ID = id
	inv.Role = role
	inv.Status = service.InvitationStatusPending
	return id, nil
}

// GetInvitationByTokenHash resolves an invitation by its hashed token
// within a project, or (nil, nil).
func (s *InvitationStore) GetInvitationByTokenHash(ctx context.Context, projectID, tokenHash string) (*service.TenantInvitation, error) {
	if projectID == "" || tokenHash == "" {
		return nil, nil
	}
	const q = `SELECT ` + invitationColumns + `
		FROM tenant_invitations WHERE project_id = $1 AND token_hash = $2`
	v, err := scanInvitation(s.pool.QueryRow(ctx, q, projectID, tokenHash))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetInvitationByTokenHash", err)
	}
	return v, nil
}

// SetInvitationStatus transitions an invitation's status and, when
// accepting, stamps accepted_at_ms (0 defaults to now on accept). Unknown
// ids are a no-op.
func (s *InvitationStore) SetInvitationStatus(ctx context.Context, projectID, invitationID, status string, acceptedAtMs int64) error {
	if projectID == "" || invitationID == "" {
		return fmt.Errorf("%w: project_id and invitation_id are required", service.ErrInvalidArgument)
	}
	if status == service.InvitationStatusAccepted && acceptedAtMs == 0 {
		acceptedAtMs = nowMs()
	}
	const q = `
		UPDATE tenant_invitations SET status = $3, accepted_at_ms = $4
		WHERE project_id = $1 AND id = $2`
	if _, err := s.pool.Exec(ctx, q, projectID, invitationID, status, acceptedAtMs); err != nil {
		return wrapPgErr("SetInvitationStatus", err)
	}
	return nil
}

// ListInvitationsForTenant returns every invitation in a tenant, newest
// first.
func (s *InvitationStore) ListInvitationsForTenant(ctx context.Context, projectID, tenantID string) ([]*service.TenantInvitation, error) {
	if projectID == "" || tenantID == "" {
		return nil, nil
	}
	const q = `SELECT ` + invitationColumns + `
		FROM tenant_invitations WHERE project_id = $1 AND tenant_id = $2
		ORDER BY created_at_ms DESC, id DESC`
	rows, err := s.pool.Query(ctx, q, projectID, tenantID)
	if err != nil {
		return nil, wrapPgErr("ListInvitationsForTenant", err)
	}
	defer rows.Close()
	var out []*service.TenantInvitation
	for rows.Next() {
		v, err := scanInvitation(rows)
		if err != nil {
			return nil, wrapPgErr("ListInvitationsForTenant scan", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListInvitationsForTenant rows", err)
	}
	return out, nil
}
