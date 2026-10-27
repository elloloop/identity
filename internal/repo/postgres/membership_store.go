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
// reactivates the membership or changes nothing.
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
		WHERE NOT (` + grantHoldsRole + `
		       AND (tenant_memberships.source <> 'domain' OR EXCLUDED.source = 'domain'))
		RETURNING ` + membershipColumns

// GrantMembership makes m.UserID an active member of m.TenantID at m.Role,
// unless they already hold an active membership there at m.Role or a higher
// role, which is then kept. It never lowers a role, so a grant cannot demote
// an owner, the last one included. A membership that came only from the
// email's domain takes the grant's source; any other source is left
// unchanged, also when the grant raises the role or reactivates it. The
// decision is the statement's own, so it holds against a concurrent grant.
// Returns the surviving row, and whether the statement wrote it.
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
	now := nowMs()
	granted, err := scanMembership(s.pool.QueryRow(ctx, grantMembershipQuery, newID(), m.ProjectID, m.TenantID, m.UserID, source, role, now))
	if noRows(err) {
		// The user already holds the role or a higher one, from a source the
		// grant does not replace: nothing changed.
		kept, getErr := s.GetMembership(ctx, m.ProjectID, m.TenantID, m.UserID)
		if getErr != nil {
			return nil, false, getErr
		}
		if kept == nil {
			return nil, false, fmt.Errorf("postgres: GrantMembership: membership vanished: %w", service.ErrUnavailable)
		}
		return kept, false, nil
	}
	if err != nil {
		return nil, false, wrapPgErr("GrantMembership", err)
	}
	return granted, true, nil
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
// project, which a governance read for another project cannot see. The
// domain test is an index condition on 0045's (project_id, tenant_id,
// lower(domain)) unique index.
const activeUserTenantsQuery = `
	SELECT t.id, t.name, m.role, m.source
	FROM tenant_memberships m
	JOIN tenants t ON t.project_id = m.project_id AND t.id = m.tenant_id
	WHERE m.project_id = $1 AND m.user_id = $2
	  AND m.status = 'active' AND t.status = 'claimed'
	  AND (m.source <> 'domain' OR EXISTS (
	        SELECT 1 FROM domains d
	        WHERE d.project_id = m.project_id AND d.tenant_id = m.tenant_id
	          AND lower(d.domain) = $3 AND d.status = 'verified'))`

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
// unless it is the tenant's last active owner, which is service.ErrLastOwner.
// Unknown rows are a no-op.
//
// One transaction locks the tenant's owners and the membership
// (lockOwnersAnd), then counts the other active owners in a statement of its
// own, which sees whatever committed while it waited. So two removals of the
// last two owners, or a removal of the member a transfer is making the
// owner, cannot together leave the tenant without one: the second sees what
// the first did. Counting inside the DELETE would not do: a statement that
// waits on a lock re-checks only the row it waited for, with its old
// snapshot for everything else.
func (s *MembershipStore) RemoveMembership(ctx context.Context, projectID, tenantID, userID string) error {
	if projectID == "" || tenantID == "" || userID == "" {
		return fmt.Errorf("%w: project_id, tenant_id and user_id are required", service.ErrInvalidArgument)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return wrapPgErr("RemoveMembership", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	held, err := lockOwnersAnd(ctx, tx, projectID, tenantID, userID)
	if err != nil {
		return wrapPgErr("RemoveMembership(lock)", err)
	}
	target := held[userID]
	if target == nil {
		return nil
	}
	if target.Role == service.RoleOwner && target.Status == service.MembershipStatusActive {
		var others int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant_memberships
			WHERE project_id = $1 AND tenant_id = $2 AND user_id <> $3
			  AND role = 'owner' AND status = 'active'`, projectID, tenantID, userID).Scan(&others); err != nil {
			return wrapPgErr("RemoveMembership(count)", err)
		}
		if others == 0 {
			return fmt.Errorf("%w: cannot remove the last owner of a tenant", service.ErrLastOwner)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tenant_memberships
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3`, projectID, tenantID, userID); err != nil {
		return wrapPgErr("RemoveMembership", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return wrapPgErr("RemoveMembership(commit)", err)
	}
	return nil
}

// lockOwnersAnd locks the tenant's active owner memberships and those of
// userIDs, and returns the memberships of userIDs it found, by user id, as
// they stand once locked. Every write that can change who owns a tenant
// takes its locks this way, in one statement and in user_id order, so such
// writes queue behind one another and never deadlock: two transactions
// that each take all their locks in one ordered pass cannot each hold a row
// the other waits for.
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
