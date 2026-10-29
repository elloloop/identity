package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"

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
// stamps updated_at_ms. A membership from any source but the email's
// domain is a decision about the person, so it also deletes their removal
// record (clearRemoval). Returns the surviving row id.
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", wrapPgErr("UpsertMembership", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockMembership(ctx, tx, "UpsertMembership", m.ProjectID, m.TenantID, m.UserID); err != nil {
		return "", err
	}
	if err := clearRemoval(ctx, tx, "UpsertMembership", m.ProjectID, m.TenantID, m.UserID, source); err != nil {
		return "", err
	}
	var outID string
	if err := tx.QueryRow(
		ctx, q,
		id, m.ProjectID, m.TenantID, m.UserID, source, role, status, now,
	).Scan(&outID); err != nil {
		return "", wrapPgErr("UpsertMembership", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", wrapPgErr("UpsertMembership(commit)", err)
	}
	m.ID = outID
	m.Source, m.Role, m.Status, m.UpdatedAtMs = source, role, status, now
	return outID, nil
}

// membershipRoleRank orders the roles in SQL: owner, then admin, then member.
const membershipRoleRank = `CASE %s WHEN 'owner' THEN 3 WHEN 'admin' THEN 2 WHEN 'member' THEN 1 ELSE 0 END`

// grantHoldsRole is true when the existing membership is active at the
// granted role or a higher one.
var grantHoldsRole = `tenant_memberships.status = 'active' AND ` +
	fmt.Sprintf(membershipRoleRank, "tenant_memberships.role") + ` >= ` + fmt.Sprintf(membershipRoleRank, "EXCLUDED.role")

// grantMembershipQuery is GrantMembership's statement. A held role is kept;
// a membership that came only from the email's domain takes the grant's
// source, since such a membership counts only while that email is verified
// and on the tenant's domain, and a grant is a decision about this person;
// any other source is left alone, whether the grant raises the role,
// reactivates the membership or changes nothing. A suspended membership is
// not written: only RestoreMembership, or an operator's UpsertMembership,
// lifts a suspension.
var grantMembershipQuery = `
		INSERT INTO tenant_memberships (
			id, project_id, tenant_id, user_id, source, role, status,
			created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $7)
		ON CONFLICT (project_id, tenant_id, user_id) DO UPDATE SET
			source        = CASE WHEN tenant_memberships.source = 'domain' THEN EXCLUDED.source ELSE tenant_memberships.source END,
			role          = CASE WHEN ` + grantHoldsRole + ` THEN tenant_memberships.role ELSE EXCLUDED.role END,
			status        = 'active',
			updated_at_ms = EXCLUDED.updated_at_ms
		WHERE tenant_memberships.status <> 'suspended'
		  AND NOT (` + grantHoldsRole + `
		       AND (tenant_memberships.source <> 'domain' OR EXCLUDED.source = 'domain'))
		RETURNING ` + membershipColumns

// GrantMembership makes m.UserID an active member of m.TenantID at m.Role,
// unless they already hold an active membership there at m.Role or a higher
// role, which is then kept. It never lowers a role, so a grant cannot demote
// an owner, the last one included. A membership that came only from the
// email's domain takes the grant's source; any other source is left
// unchanged, also when the grant raises the role or reactivates it. The
// decision is the statement's own, so it holds against a concurrent grant.
// A grant from any source but the email's domain also deletes the user's
// removal record (clearRemoval), in the same transaction and under the
// membership's lock, so it cannot interleave with a removal. A suspended
// membership is service.ErrMemberSuspended and is left as it is. Returns
// the surviving row, and whether the statement wrote it.
func (s *MembershipStore) GrantMembership(ctx context.Context, m *service.TenantMembership) (*service.TenantMembership, bool, error) {
	if m == nil {
		return nil, false, errors.New("postgres: GrantMembership: nil membership")
	}
	if m.ProjectID == "" || m.TenantID == "" || m.UserID == "" {
		return nil, false, fmt.Errorf("%w: project_id, tenant_id and user_id are required", service.ErrInvalidArgument)
	}
	source := m.Source
	if source == "" {
		source = service.MembershipSourceAdded
	}
	role := m.Role
	if role == "" {
		role = service.RoleMember
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, wrapPgErr("GrantMembership", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockMembership(ctx, tx, "GrantMembership", m.ProjectID, m.TenantID, m.UserID); err != nil {
		return nil, false, err
	}
	if err := clearRemoval(ctx, tx, "GrantMembership", m.ProjectID, m.TenantID, m.UserID, source); err != nil {
		return nil, false, err
	}
	granted, changed, err := grantIn(ctx, tx, "GrantMembership", m.ProjectID, m.TenantID, m.UserID, source, role)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, wrapPgErr("GrantMembership(commit)", err)
	}
	return granted, changed, nil
}

// grantIn runs grantMembershipQuery in tx and returns the surviving
// membership and whether the statement wrote it, or
// service.ErrMemberSuspended when the membership is suspended. op names the
// caller in errors.
func grantIn(ctx context.Context, tx pgx.Tx, op, projectID, tenantID, userID, source, role string) (*service.TenantMembership, bool, error) {
	granted, err := scanMembership(tx.QueryRow(ctx, grantMembershipQuery, newID(), projectID, tenantID, userID, source, role, nowMs()))
	if err == nil {
		return granted, true, nil
	}
	if !noRows(err) {
		return nil, false, wrapPgErr(op, err)
	}
	// The membership is suspended, or the user already holds the role or a
	// higher one from a source the grant does not replace: nothing changed.
	kept, err := scanMembership(tx.QueryRow(ctx, `SELECT `+membershipColumns+`
		FROM tenant_memberships
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3`, projectID, tenantID, userID))
	if noRows(err) {
		return nil, false, fmt.Errorf("postgres: %s: membership vanished: %w", op, service.ErrUnavailable)
	}
	if err != nil {
		return nil, false, wrapPgErr(op+"(read)", err)
	}
	if kept.Status == service.MembershipStatusSuspended {
		return nil, false, service.ErrMemberSuspended
	}
	return kept, false, nil
}

// membershipLockKey names the advisory lock every write that records,
// clears or consults a (project, tenant, user) removal or suspension takes
// first. A statement that waits on a row re-checks only that row, with its
// old snapshot for everything else, so without it a join could wait on the
// membership a removal deletes and then insert it again, having read no
// removal record. Each of those transactions takes it before any row lock
// and takes no other advisory lock, so it adds no lock-order cycle.
func membershipLockKey(projectID, tenantID, userID string) string {
	return advisoryKey("tenant_membership", projectID, tenantID, userID)
}

// lockMembership takes membershipLockKey, held until tx ends.
func lockMembership(ctx context.Context, tx pgx.Tx, op, projectID, tenantID, userID string) error {
	return lockXact(ctx, tx, op, membershipLockKey(projectID, tenantID, userID))
}

// clearRemoval deletes the user's removal record from the tenant when a
// membership from source is a decision to let them back in: every source
// but the email's domain, whose membership the record exists to refuse.
func clearRemoval(ctx context.Context, tx pgx.Tx, op, projectID, tenantID, userID, source string) error {
	if source == service.MembershipSourceDomain {
		return nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tenant_member_removals
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3`, projectID, tenantID, userID); err != nil {
		return wrapPgErr(op+"(clear removal)", err)
	}
	return nil
}

// JoinByDomain makes userID an active member of the tenant through their
// email's domain, the verified domain domainID, as GrantMembership would
// with source MembershipSourceDomain and role member. It writes only while
// that domain is verified on the tenant and lets people join, the tenant is
// claimed, and the user has no removal record there. One transaction takes
// the membership's lock, then locks the domain and the tenant FOR SHARE and
// checks them, so a SetDomainAllowJoin, a change to the domain's status or
// the tenant's, or a removal either waits for the join or is seen by it.
//
// Returns (nil, false, nil) when the domain or the tenant no longer lets
// the user join, service.ErrRemovedFromTenant while a removal stands, the
// membership unchanged and false when the user already holds an active
// one, and the membership and true when this call wrote it.
func (s *MembershipStore) JoinByDomain(ctx context.Context, projectID, tenantID, userID, domainID string) (*service.TenantMembership, bool, error) {
	if projectID == "" || tenantID == "" || userID == "" || domainID == "" {
		return nil, false, fmt.Errorf("%w: project_id, tenant_id, user_id and domain_id are required", service.ErrInvalidArgument)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, wrapPgErr("JoinByDomain", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockMembership(ctx, tx, "JoinByDomain", projectID, tenantID, userID); err != nil {
		return nil, false, err
	}

	var open bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM domains d
		JOIN tenants t ON t.project_id = d.project_id AND t.id = d.tenant_id
		WHERE d.project_id = $1 AND d.id = $2 AND d.tenant_id = $3
		  AND d.status = 'verified' AND d.allow_join AND t.status = 'claimed'
		FOR SHARE OF d, t)`, projectID, domainID, tenantID).Scan(&open); err != nil {
		return nil, false, wrapPgErr("JoinByDomain(door)", err)
	}
	if !open {
		return nil, false, nil
	}
	removed, err := isRemoved(ctx, tx, projectID, tenantID, userID)
	if err != nil {
		return nil, false, wrapPgErr("JoinByDomain(removal)", err)
	}
	if removed {
		return nil, false, service.ErrRemovedFromTenant
	}
	joined, changed, err := grantIn(ctx, tx, "JoinByDomain", projectID, tenantID, userID, service.MembershipSourceDomain, service.RoleMember)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, wrapPgErr("JoinByDomain(commit)", err)
	}
	return joined, changed, nil
}

// IsRemoved reports whether userID has a removal record in the tenant: an
// owner or admin removed them, and no one has let them back in since.
func (s *MembershipStore) IsRemoved(ctx context.Context, projectID, tenantID, userID string) (bool, error) {
	if projectID == "" || tenantID == "" || userID == "" {
		return false, nil
	}
	removed, err := isRemoved(ctx, s.pool, projectID, tenantID, userID)
	if err != nil {
		return false, wrapPgErr("IsRemoved", err)
	}
	return removed, nil
}

func isRemoved(ctx context.Context, q querier, projectID, tenantID, userID string) (bool, error) {
	var removed bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_member_removals
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3)`, projectID, tenantID, userID).Scan(&removed)
	return removed, err
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

// activeUserTenantsQuery selects the tenants a user may act in: an active
// membership in a claimed tenant of the project, where one that came from the
// email's domain counts only when $3, the account's verified email domain,
// is a domain the tenant has verified. $3 is "" while the email is
// unverified, and no domain is empty. ListActiveTenantsForUser and
// GetActiveTenantForUser share it, so a tenant a refresh may select is
// exactly one the list shows. The schema does not tie a membership's
// project_id to its tenant's, so the join requires both to be the project.
//
// The service passes the domain rather than the query reading
// users.email_domain: users is under row-level security bound to the pool's
// project, which a governance read for another project cannot see.
var activeUserTenantsQuery = `
	SELECT t.id, t.name, m.role, m.source
	FROM tenant_memberships m
	JOIN tenants t ON t.project_id = m.project_id AND t.id = m.tenant_id
	WHERE m.project_id = $1 AND m.user_id = $2
	  AND m.status = 'active' AND t.status = 'claimed'
	  AND (m.source <> 'domain' OR ` + onVerifiedDomain("m", "$3") + `)`

// onVerifiedDomain is true when the email domain domainExpr is a domain
// that the tenant of membership alias m has verified: the rule a membership
// through the email's domain counts by. It is an index condition on 0045's
// (project_id, tenant_id, lower(domain)) unique index.
func onVerifiedDomain(m, domainExpr string) string {
	return `EXISTS (
	        SELECT 1 FROM domains d
	        WHERE d.project_id = ` + m + `.project_id AND d.tenant_id = ` + m + `.tenant_id
	          AND lower(d.domain) = ` + domainExpr + ` AND d.status = 'verified')`
}

// ListActiveTenantsForUser returns the tenants a user may act in within a
// project, ordered by name, then id.
func (s *MembershipStore) ListActiveTenantsForUser(ctx context.Context, projectID, userID, emailDomain string) ([]*service.UserTenant, error) {
	if projectID == "" || userID == "" {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, activeUserTenantsQuery+` ORDER BY t.name, t.id`, projectID, userID, emailDomain)
	if err != nil {
		return nil, wrapPgErr("ListActiveTenantsForUser", err)
	}
	defer rows.Close()
	var out []*service.UserTenant
	for rows.Next() {
		var ut service.UserTenant
		if err := rows.Scan(&ut.TenantID, &ut.Name, &ut.Role, &ut.Source); err != nil {
			return nil, wrapPgErr("ListActiveTenantsForUser scan", err)
		}
		out = append(out, &ut)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListActiveTenantsForUser rows", err)
	}
	return out, nil
}

// GetActiveTenantForUser returns the tenant when the user may act in it, or
// (nil, nil).
func (s *MembershipStore) GetActiveTenantForUser(ctx context.Context, projectID, tenantID, userID, emailDomain string) (*service.UserTenant, error) {
	if projectID == "" || tenantID == "" || userID == "" {
		return nil, nil
	}
	var ut service.UserTenant
	err := s.pool.QueryRow(ctx, activeUserTenantsQuery+` AND t.id = $4`, projectID, userID, emailDomain, tenantID).
		Scan(&ut.TenantID, &ut.Name, &ut.Role, &ut.Source)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetActiveTenantForUser", err)
	}
	return &ut, nil
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

// RemoveMembership deletes the membership for (project, tenant, user),
// unless it is the tenant's last active owner, which is service.ErrLastOwner,
// and records the removal in tenant_member_removals, which keeps the user
// from joining again through their email's domain (JoinByDomain) until a
// grant from another source lets them back in. It returns the membership as
// it stood when removed. Unknown rows are a no-op: (nil, nil), and nothing
// is recorded.
//
// The membership's lock (membershipLockKey) comes first, so a removal and a
// join or grant of the same membership queue behind one another.
// One transaction locks the tenant's owners and the membership
// (lockOwnersAnd), then counts the other active owners in a statement of its
// own, which sees whatever committed while it waited. So two removals of the
// last two owners, or a removal of the member a transfer is making the
// owner, cannot together leave the tenant without one: the second sees what
// the first did. Counting inside the DELETE would not do: a statement that
// waits on a lock re-checks only the row it waited for, with its old
// snapshot for everything else.
func (s *MembershipStore) RemoveMembership(ctx context.Context, projectID, tenantID, userID string) (*service.TenantMembership, error) {
	if projectID == "" || tenantID == "" || userID == "" {
		return nil, fmt.Errorf("%w: project_id, tenant_id and user_id are required", service.ErrInvalidArgument)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, wrapPgErr("RemoveMembership", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := lockMembership(ctx, tx, "RemoveMembership", projectID, tenantID, userID); err != nil {
		return nil, err
	}
	held, err := lockOwnersAnd(ctx, tx, projectID, tenantID, userID)
	if err != nil {
		return nil, wrapPgErr("RemoveMembership(lock)", err)
	}
	target := held[userID]
	if target == nil {
		return nil, nil
	}
	if err := keepAnOwner(ctx, tx, "RemoveMembership", target, "remove"); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tenant_memberships
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3`, projectID, tenantID, userID); err != nil {
		return nil, wrapPgErr("RemoveMembership", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO tenant_member_removals (
			project_id, tenant_id, user_id, removed_at_ms
		) VALUES ($1, $2, $3, $4)
		ON CONFLICT (project_id, tenant_id, user_id) DO UPDATE SET
			removed_at_ms = EXCLUDED.removed_at_ms`, projectID, tenantID, userID, nowMs()); err != nil {
		return nil, wrapPgErr("RemoveMembership(record)", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, wrapPgErr("RemoveMembership(commit)", err)
	}
	return target, nil
}

// keepAnOwner refuses, with service.ErrLastOwner, to take target out of
// the tenant's active owners when it is the last of them. verb names what
// the caller would do to it, in the error. It must run after lockOwnersAnd
// in the same transaction: the count is a statement of its own, so it sees
// whatever committed while the locks were awaited.
func keepAnOwner(ctx context.Context, tx pgx.Tx, op string, target *service.TenantMembership, verb string) error {
	if target.Role != service.RoleOwner || target.Status != service.MembershipStatusActive {
		return nil
	}
	var others int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant_memberships
		WHERE project_id = $1 AND tenant_id = $2 AND user_id <> $3
		  AND role = 'owner' AND status = 'active'`, target.ProjectID, target.TenantID, target.UserID).Scan(&others); err != nil {
		return wrapPgErr(op+"(count)", err)
	}
	if others == 0 {
		return fmt.Errorf("%w: cannot %s the last owner of a tenant", service.ErrLastOwner, verb)
	}
	return nil
}

// SuspendMembership sets the active membership for (project, tenant, user)
// to service.MembershipStatusSuspended, keeping its role and source, unless
// it is the tenant's last active owner (service.ErrLastOwner). It takes its
// locks as RemoveMembership does, the membership's lock and then
// lockOwnersAnd, so a suspension, a removal and a transfer that race cannot
// together leave the tenant without an owner. Returns the membership as it
// now stands, and whether this call suspended it: a suspended membership is
// returned unchanged. Any other status, or no membership, is
// service.ErrNotFound.
func (s *MembershipStore) SuspendMembership(ctx context.Context, projectID, tenantID, userID string) (*service.TenantMembership, bool, error) {
	if projectID == "" || tenantID == "" || userID == "" {
		return nil, false, fmt.Errorf("%w: project_id, tenant_id and user_id are required", service.ErrInvalidArgument)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, wrapPgErr("SuspendMembership", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := lockMembership(ctx, tx, "SuspendMembership", projectID, tenantID, userID); err != nil {
		return nil, false, err
	}
	held, err := lockOwnersAnd(ctx, tx, projectID, tenantID, userID)
	if err != nil {
		return nil, false, wrapPgErr("SuspendMembership(lock)", err)
	}
	target := held[userID]
	switch {
	case target == nil:
		return nil, false, fmt.Errorf("%w: the user is not a member of the tenant", service.ErrNotFound)
	case target.Status == service.MembershipStatusSuspended:
		return target, false, nil
	case target.Status != service.MembershipStatusActive:
		return nil, false, fmt.Errorf("%w: the user is not an active member of the tenant", service.ErrNotFound)
	}
	if err := keepAnOwner(ctx, tx, "SuspendMembership", target, "suspend"); err != nil {
		return nil, false, err
	}
	suspended, err := scanMembership(tx.QueryRow(ctx, `
		UPDATE tenant_memberships SET status = 'suspended', updated_at_ms = $4
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3
		RETURNING `+membershipColumns, projectID, tenantID, userID, nowMs()))
	if err != nil {
		return nil, false, wrapPgErr("SuspendMembership", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, wrapPgErr("SuspendMembership(commit)", err)
	}
	return suspended, true, nil
}

// RestoreMembership lifts the suspension of the membership for (project,
// tenant, user). It becomes active again, with the role and source it had,
// except one from the email's domain whose account's email is not, at that
// moment, on a domain the tenant has verified: that one becomes inactive.
// The rule is stricter than migration 0047's, which ends an active domain
// membership only when the email moves: a restore lets the membership count
// again, so it counts only on a domain the tenant verifies now. Returns the
// membership as it now stands, and whether this call lifted a suspension:
// an active membership is returned unchanged. Any other status, or no
// membership, is service.ErrNotFound.
//
// by is who restores it (service.Restorer). One transaction takes the
// membership's lock, then, for a suspended membership, the target's
// account row (lockedEmailDomain), then by's membership with the tenant's
// owners and the target's (lockOwnersAnd), and restores only while by's is
// an active owner or admin one, else service.ErrPermissionDenied; an
// operator is not checked. So a suspension or removal of by that commits
// first is seen: an admin cannot lift a suspension, their own included,
// through a call authorized before they were suspended.
//
// The account's email domain is read in that transaction and its row held,
// so an email change either commits first and is judged here, or waits for
// the restore and then meets an active membership, which 0047's trigger
// ends. The account row is taken before any membership row, the order in
// which deleting the account (its row, then by cascade its memberships)
// and 0047's trigger take them, so neither can deadlock with a restore.
// It is taken only when the membership is suspended: a restore naming
// anyone else writes nothing, and must not hold up writes to an account
// the caller merely named.
func (s *MembershipStore) RestoreMembership(ctx context.Context, projectID, tenantID, userID string, by service.Restorer) (*service.TenantMembership, bool, error) {
	if projectID == "" || tenantID == "" || userID == "" {
		return nil, false, fmt.Errorf("%w: project_id, tenant_id and user_id are required", service.ErrInvalidArgument)
	}
	if by.NamesNobody() {
		return nil, false, fmt.Errorf("%w: a restore must name who restores", service.ErrPermissionDenied)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, wrapPgErr("RestoreMembership", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := lockMembership(ctx, tx, "RestoreMembership", projectID, tenantID, userID); err != nil {
		return nil, false, err
	}
	// Every write that makes a membership suspended takes the lock just
	// taken, so one not suspended now is not suspended below, and its
	// restore writes nothing.
	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM tenant_memberships
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3`,
		projectID, tenantID, userID).Scan(&status)
	if err != nil && !noRows(err) {
		return nil, false, wrapPgErr("RestoreMembership(status)", err)
	}
	var emailDomain string
	if status == service.MembershipStatusSuspended {
		if emailDomain, err = lockedEmailDomain(ctx, tx, projectID, userID); err != nil {
			return nil, false, wrapPgErr("RestoreMembership(email domain)", err)
		}
	}
	held, err := lockOwnersAnd(ctx, tx, projectID, tenantID, userID, by.UserID())
	if err != nil {
		return nil, false, wrapPgErr("RestoreMembership(lock)", err)
	}
	if !by.IsOperator() {
		byMembership := held[by.UserID()]
		if byMembership == nil || byMembership.Status != service.MembershipStatusActive || (byMembership.Role != service.RoleOwner && byMembership.Role != service.RoleAdmin) {
			return nil, false, fmt.Errorf("%w: only an active owner or admin of the tenant may restore a member", service.ErrPermissionDenied)
		}
	}
	target := held[userID]
	switch {
	case target == nil:
		return nil, false, fmt.Errorf("%w: the user is not a member of the tenant", service.ErrNotFound)
	case target.Status == service.MembershipStatusActive:
		return target, false, nil
	case target.Status != service.MembershipStatusSuspended:
		return nil, false, fmt.Errorf("%w: the user is not a suspended member of the tenant", service.ErrNotFound)
	}
	restored, err := scanMembership(tx.QueryRow(ctx, `
		UPDATE tenant_memberships m SET
			status = CASE WHEN m.source = 'domain' AND NOT `+onVerifiedDomain("m", "$4")+`
			         THEN 'inactive' ELSE 'active' END,
			updated_at_ms = $5
		WHERE m.project_id = $1 AND m.tenant_id = $2 AND m.user_id = $3
		RETURNING `+membershipColumns, projectID, tenantID, userID, emailDomain, nowMs()))
	if err != nil {
		return nil, false, wrapPgErr("RestoreMembership", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, wrapPgErr("RestoreMembership(commit)", err)
	}
	return restored, true, nil
}

// lockedEmailDomain returns the domain of the email of userID's account in
// projectID, as users.email_domain holds it, or "" for no account, and
// holds the account's row (FOR SHARE) until tx ends, so the email cannot
// change before tx commits. users is under row-level security (migration
// 0016) and this store's pool is bound to the server's own project, so tx
// is first bound to projectID, as 0046's functions bind themselves; the
// binding ends with tx.
func lockedEmailDomain(ctx context.Context, tx pgx.Tx, projectID, userID string) (string, error) {
	if _, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, rlsGUC, projectID); err != nil {
		return "", err
	}
	var domain string
	err := tx.QueryRow(ctx, `SELECT COALESCE(email_domain, '') FROM users
		WHERE project_id = $1 AND id = $2
		FOR SHARE`, projectID, userID).Scan(&domain)
	if noRows(err) {
		return "", nil
	}
	return domain, err
}

// lockOwnersAnd locks the tenant's active owner memberships and those of
// userIDs, and returns the memberships of userIDs it found, by user id, as
// they stand once locked; an empty id is ignored. The writes that change an
// owner or check who may act take their membership locks this way, in one
// statement and in user_id order, so they queue behind one another and
// never deadlock: two transactions that each take all their locks in one
// ordered pass cannot each hold a row the other waits for. A write that
// also locks an account row takes it before this pass, as an account's
// deletion does. Two writes that change owners do not come
// through here and keep no owner: UpsertMembership, by which
// AdminAddTenantAdmin can lower an owner, and the cascade that drops an
// account's memberships when the account is deleted.
func lockOwnersAnd(ctx context.Context, tx pgx.Tx, projectID, tenantID string, userIDs ...string) (map[string]*service.TenantMembership, error) {
	rows, err := tx.Query(ctx, `SELECT `+membershipColumns+`
		FROM tenant_memberships
		WHERE project_id = $1 AND tenant_id = $2
		  AND ((role = 'owner' AND status = 'active') OR user_id = ANY($3))
		ORDER BY user_id
		FOR UPDATE`, projectID, tenantID, userIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	held := make(map[string]*service.TenantMembership, len(userIDs))
	for rows.Next() {
		m, err := scanMembership(rows)
		if err != nil {
			return nil, err
		}
		if slices.Contains(userIDs, m.UserID) {
			held[m.UserID] = m
		}
	}
	return held, rows.Err()
}

// TransferOwnership makes toUserID an owner of the tenant and fromUserID an
// admin. One transaction locks the tenant's owners and both memberships
// (lockOwnersAnd), as a removal does, then checks them, so a transfer that
// waited sees what the write before it did: an owner who has just handed
// the tenant on cannot hand it on again, and a member just removed cannot
// be made the owner. fromUserID must
// be an active owner (service.ErrPermissionDenied) and toUserID an active
// member (service.ErrNotFound). A domain-sourced membership of toUserID's
// becomes an added one, as GrantMembership would make it.
func (s *MembershipStore) TransferOwnership(ctx context.Context, projectID, tenantID, fromUserID, toUserID string) (*service.TenantMembership, *service.TenantMembership, error) {
	if projectID == "" || tenantID == "" || fromUserID == "" || toUserID == "" {
		return nil, nil, fmt.Errorf("%w: project_id, tenant_id and both user ids are required", service.ErrInvalidArgument)
	}
	if fromUserID == toUserID {
		return nil, nil, fmt.Errorf("%w: ownership cannot pass to the same user", service.ErrInvalidArgument)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, wrapPgErr("TransferOwnership", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	held, err := lockOwnersAnd(ctx, tx, projectID, tenantID, fromUserID, toUserID)
	if err != nil {
		return nil, nil, wrapPgErr("TransferOwnership(lock)", err)
	}
	if from := held[fromUserID]; from == nil || from.Role != service.RoleOwner || from.Status != service.MembershipStatusActive {
		return nil, nil, fmt.Errorf("%w: only an active owner may transfer ownership", service.ErrPermissionDenied)
	}
	if to := held[toUserID]; to == nil || to.Status != service.MembershipStatusActive {
		return nil, nil, fmt.Errorf("%w: the new owner is not an active member of the tenant", service.ErrNotFound)
	}

	now := nowMs()
	to, err := scanMembership(tx.QueryRow(ctx, `
		UPDATE tenant_memberships SET
			role          = 'owner',
			source        = CASE WHEN source = 'domain' THEN 'added' ELSE source END,
			updated_at_ms = $4
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3
		RETURNING `+membershipColumns, projectID, tenantID, toUserID, now))
	if err != nil {
		return nil, nil, wrapPgErr("TransferOwnership(owner)", err)
	}
	from, err := scanMembership(tx.QueryRow(ctx, `
		UPDATE tenant_memberships SET role = 'admin', updated_at_ms = $4
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3
		RETURNING `+membershipColumns, projectID, tenantID, fromUserID, now))
	if err != nil {
		return nil, nil, wrapPgErr("TransferOwnership(previous owner)", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, wrapPgErr("TransferOwnership(commit)", err)
	}
	return from, to, nil
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
// (project, tenant, email under service.FoldEmail) and inserts the new one.
// The service stores invitations in canonical form, and migration 0034
// canonicalized the pending ones stored before it did, so the fold key names
// the mailbox. Creates for one tenant are serialized by a transaction-scoped
// advisory lock, so concurrent ones each revoke the one before and exactly
// one stays pending; the fold-keyed partial unique index is the backstop. This is the
// authoritative enforcement (the partial unique index is defense-in-depth,
// and the memory driver — should they ever gain invitations — must
// match these revoke-then-insert semantics).
//
// Under the same lock, and the inviter's lock, it applies limits: an
// invitation to an address the tenant invited at or after
// limits.ResendCooldownStartMs is service.ErrInvitationResendTooSoon; one past
// limits.MaxPerTenant invitations the tenant created at or after
// limits.WindowStartMs is service.ErrInvitationLimited; one past
// limits.MaxPerInviter the inviter sent from any tenant in that window is
// service.ErrInviterLimited; and one past limits.MaxPerRecipient the tenant
// sent the address in that window is service.ErrInvitationRecipientLimited.
// Each counts every invitation, whatever its status, since each one sent an
// email. The recipient's count is the tenant's alone, so the tenant's lock
// covers it: one tenant reaching it never stops another inviting the address.
//
// The locks are always taken in that order — tenant, then inviter — so two
// creates never wait on each other's locks in opposite orders.
func (s *InvitationStore) CreateInvitation(ctx context.Context, inv *service.TenantInvitation, limits service.InvitationLimits) (string, error) {
	if inv == nil {
		return "", errors.New("postgres: CreateInvitation: nil invitation")
	}
	if limits.MaxPerTenant <= 0 {
		return "", fmt.Errorf("%w: max_per_tenant must be positive", service.ErrInvalidArgument)
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

	key := service.FoldEmail(inv.Email)
	locks := []string{advisoryKey("tenant_invitation", inv.ProjectID, inv.TenantID)}
	if inv.InvitedBy != "" {
		locks = append(locks, advisoryKey("tenant_invitation_inviter", inv.ProjectID, inv.InvitedBy))
	}
	for _, lock := range locks {
		if err := lockXact(ctx, tx, "CreateInvitation", lock); err != nil {
			return "", err
		}
	}

	if limits.ResendCooldownStartMs > 0 {
		var recent bool
		if err := tx.QueryRow(
			ctx, `
			SELECT EXISTS (
				SELECT 1 FROM tenant_invitations
				WHERE project_id = $1 AND tenant_id = $2
				  AND lower(email COLLATE "C") = $3 AND created_at_ms >= $4)`,
			inv.ProjectID, inv.TenantID, key, limits.ResendCooldownStartMs,
		).Scan(&recent); err != nil {
			return "", wrapPgErr("CreateInvitation(cooldown)", err)
		}
		if recent {
			return "", service.ErrInvitationResendTooSoon
		}
	}
	var sent int
	if err := tx.QueryRow(
		ctx, `
		SELECT count(*) FROM tenant_invitations
		WHERE project_id = $1 AND tenant_id = $2 AND created_at_ms >= $3`,
		inv.ProjectID, inv.TenantID, limits.WindowStartMs,
	).Scan(&sent); err != nil {
		return "", wrapPgErr("CreateInvitation(count)", err)
	}
	if sent >= limits.MaxPerTenant {
		return "", service.ErrInvitationLimited
	}
	if limits.MaxPerInviter > 0 && inv.InvitedBy != "" {
		var byInviter int
		if err := tx.QueryRow(
			ctx, `
			SELECT count(*) FROM tenant_invitations
			WHERE project_id = $1 AND invited_by = $2 AND created_at_ms >= $3`,
			inv.ProjectID, inv.InvitedBy, limits.WindowStartMs,
		).Scan(&byInviter); err != nil {
			return "", wrapPgErr("CreateInvitation(inviter)", err)
		}
		if byInviter >= limits.MaxPerInviter {
			return "", service.ErrInviterLimited
		}
	}
	if limits.MaxPerRecipient > 0 {
		var toRecipient int
		if err := tx.QueryRow(
			ctx, `
			SELECT count(*) FROM tenant_invitations
			WHERE project_id = $1 AND tenant_id = $2
			  AND lower(email COLLATE "C") = $3 AND created_at_ms >= $4`,
			inv.ProjectID, inv.TenantID, key, limits.WindowStartMs,
		).Scan(&toRecipient); err != nil {
			return "", wrapPgErr("CreateInvitation(recipient)", err)
		}
		if toRecipient >= limits.MaxPerRecipient {
			return "", service.ErrInvitationRecipientLimited
		}
	}

	// Revoke any open invite for the same recipient first, so the new one
	// is the only pending row — one open invite per (project, tenant, email).
	if _, err := tx.Exec(
		ctx, `
		UPDATE tenant_invitations SET status = 'revoked'
		WHERE project_id = $1 AND tenant_id = $2
		  AND lower(email COLLATE "C") = $3 AND status = 'pending'`,
		inv.ProjectID, inv.TenantID, key,
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
