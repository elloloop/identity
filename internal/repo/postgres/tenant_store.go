package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

// Postgres-backed TenantStore + DomainStore over migration 0013's
// per-project governance tables (tenants, domains). Both are explicitly
// project-scoped — projectID leads every query — and share the owning
// *pgRepository's pool, like ProjectStore. Conventions mirror
// project_store.go: caller-supplied TEXT ids (newID when empty),
// *_at_ms epoch-millis timestamps via nowMs, and wrapPgErr for SQLSTATE →
// service sentinel translation.

var (
	_ service.TenantStore = (*TenantStore)(nil)
	_ service.DomainStore = (*DomainStore)(nil)
)

// ── tenants ─────────────────────────────────────────────────────────────

// TenantStore persists Tenants within a Project.
type TenantStore struct {
	pool *tracedPool
}

// NewTenantStore builds a tenant store sharing the repository's pool. Do
// not close it independently; closing the *pgRepository releases the pool.
func NewTenantStore(r *pgRepository) *TenantStore {
	return &TenantStore{pool: r.pool}
}

const tenantColumns = `
	id, project_id, name, primary_domain, status, created_by,
	created_at_ms, updated_at_ms`

func scanTenant(row pgx.Row) (*service.Tenant, error) {
	var t service.Tenant
	if err := row.Scan(
		&t.ID, &t.ProjectID, &t.Name, &t.PrimaryDomain, &t.Status, &t.CreatedBy,
		&t.CreatedAtMs, &t.UpdatedAtMs,
	); err != nil {
		return nil, err
	}
	return &t, nil
}

// CreateTenant inserts a tenant. ProjectID is required; a blank id is
// generated and written back to t.ID.
func (s *TenantStore) CreateTenant(ctx context.Context, t *service.Tenant) (string, error) {
	if t == nil {
		return "", errors.New("postgres: CreateTenant: nil tenant")
	}
	if t.ProjectID == "" {
		return "", fmt.Errorf("%w: missing project_id", service.ErrInvalidArgument)
	}
	now := nowMs()
	if t.CreatedAtMs == 0 {
		t.CreatedAtMs = now
	}
	if t.UpdatedAtMs == 0 {
		t.UpdatedAtMs = t.CreatedAtMs
	}
	id := t.ID
	if id == "" {
		id = newID()
	}
	status := t.Status
	if status == "" {
		status = service.TenantStatusLatent
	}
	const q = `
		INSERT INTO tenants (
			id, project_id, name, primary_domain, status, created_by,
			created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	if _, err := s.pool.Exec(
		ctx, q,
		id, t.ProjectID, t.Name, t.PrimaryDomain, status, t.CreatedBy,
		t.CreatedAtMs, t.UpdatedAtMs,
	); err != nil {
		return "", wrapPgErr("CreateTenant", err)
	}
	t.ID = id
	t.Status = status
	return id, nil
}

// GetTenant returns the tenant by id within a project, or (nil, nil).
func (s *TenantStore) GetTenant(ctx context.Context, projectID, tenantID string) (*service.Tenant, error) {
	if projectID == "" || tenantID == "" {
		return nil, nil
	}
	const q = `SELECT ` + tenantColumns + ` FROM tenants WHERE project_id = $1 AND id = $2`
	t, err := scanTenant(s.pool.QueryRow(ctx, q, projectID, tenantID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetTenant", err)
	}
	return t, nil
}

// GetTenantStatus returns the status of the tenant by id within a project,
// or "" when there is none. It selects the one column, since the access-token
// check calls it on every request a selected-tenant token makes.
func (s *TenantStore) GetTenantStatus(ctx context.Context, projectID, tenantID string) (string, error) {
	if projectID == "" || tenantID == "" {
		return "", nil
	}
	var status string
	err := s.pool.QueryRow(ctx, `SELECT status FROM tenants WHERE project_id = $1 AND id = $2`,
		projectID, tenantID).Scan(&status)
	if noRows(err) {
		return "", nil
	}
	if err != nil {
		return "", wrapPgErr("GetTenantStatus", err)
	}
	return status, nil
}

// GetTenantByPrimaryDomain returns the tenant whose primary_domain equals
// domain (case-insensitive) within a project, or (nil, nil). A blank
// domain never matches.
func (s *TenantStore) GetTenantByPrimaryDomain(ctx context.Context, projectID, domain string) (*service.Tenant, error) {
	if projectID == "" || domain == "" {
		return nil, nil
	}
	const q = `SELECT ` + tenantColumns + `
		FROM tenants
		WHERE project_id = $1 AND lower(primary_domain) = lower($2)`
	t, err := scanTenant(s.pool.QueryRow(ctx, q, projectID, domain))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetTenantByPrimaryDomain", err)
	}
	return t, nil
}

// ClaimLatentTenant moves a latent tenant to claimed. The status is
// compared and set in one statement, so a suspension that lands between a
// caller's read and this write is kept. Unknown ids, and a tenant in any
// other status, are a no-op.
func (s *TenantStore) ClaimLatentTenant(ctx context.Context, projectID, tenantID string) error {
	if projectID == "" || tenantID == "" {
		return fmt.Errorf("%w: project_id and tenant_id are required", service.ErrInvalidArgument)
	}
	const q = `
		UPDATE tenants SET status = 'claimed', updated_at_ms = $3
		WHERE project_id = $1 AND id = $2 AND status = 'latent'`
	if _, err := s.pool.Exec(ctx, q, projectID, tenantID, nowMs()); err != nil {
		return wrapPgErr("ClaimLatentTenant", err)
	}
	return nil
}

// ListTenants returns every tenant in a project, newest first.
func (s *TenantStore) ListTenants(ctx context.Context, projectID string) ([]*service.Tenant, error) {
	if projectID == "" {
		return nil, nil
	}
	const q = `SELECT ` + tenantColumns + `
		FROM tenants WHERE project_id = $1
		ORDER BY created_at_ms DESC, id DESC`
	rows, err := s.pool.Query(ctx, q, projectID)
	if err != nil {
		return nil, wrapPgErr("ListTenants", err)
	}
	defer rows.Close()
	var out []*service.Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, wrapPgErr("ListTenants scan", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListTenants rows", err)
	}
	return out, nil
}

// CreateOwnedTenant creates a claimed tenant and its creator's active owner
// membership in one transaction. The per-user limit is counted under a
// transaction-scoped advisory lock keyed on (project, owner), so two
// concurrent requests from one user are serialized and cannot both pass a
// limit only one of them fits under. The rows are stamped req.NowMs, the
// clock the window was measured on (now when 0).
func (s *TenantStore) CreateOwnedTenant(ctx context.Context, req service.OwnedTenantRequest) (*service.Tenant, *service.TenantMembership, error) {
	if req.ProjectID == "" || req.OwnerID == "" {
		return nil, nil, fmt.Errorf("%w: project_id and owner_id are required", service.ErrInvalidArgument)
	}
	if req.MaxPerWindow <= 0 {
		return nil, nil, fmt.Errorf("%w: max_per_window must be positive", service.ErrInvalidArgument)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, wrapPgErr("CreateOwnedTenant", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := lockXact(ctx, tx, "CreateOwnedTenant", advisoryKey("tenant_create", req.ProjectID, req.OwnerID)); err != nil {
		return nil, nil, err
	}

	var created int
	if err := tx.QueryRow(
		ctx, `
		SELECT count(*) FROM tenants
		WHERE project_id = $1 AND created_by = $2 AND created_by <> ''
		  AND created_at_ms >= $3`,
		req.ProjectID, req.OwnerID, req.WindowStartMs,
	).Scan(&created); err != nil {
		return nil, nil, wrapPgErr("CreateOwnedTenant(count)", err)
	}
	if created >= req.MaxPerWindow {
		return nil, nil, service.ErrTenantCreationLimited
	}

	now := req.NowMs
	if now == 0 {
		now = nowMs()
	}
	t := &service.Tenant{
		ID:          newID(),
		ProjectID:   req.ProjectID,
		Name:        req.Name,
		Status:      service.TenantStatusClaimed,
		CreatedBy:   req.OwnerID,
		CreatedAtMs: now,
		UpdatedAtMs: now,
	}
	if _, err := tx.Exec(
		ctx, `
		INSERT INTO tenants (
			id, project_id, name, primary_domain, status, created_by,
			created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, '', $4, $5, $6, $6)`,
		t.ID, t.ProjectID, t.Name, t.Status, t.CreatedBy, now,
	); err != nil {
		return nil, nil, wrapPgErr("CreateOwnedTenant(tenant)", err)
	}

	m := &service.TenantMembership{
		ID:          newID(),
		ProjectID:   req.ProjectID,
		TenantID:    t.ID,
		UserID:      req.OwnerID,
		Source:      service.MembershipSourceCreated,
		Role:        service.RoleOwner,
		Status:      service.MembershipStatusActive,
		CreatedAtMs: now,
		UpdatedAtMs: now,
	}
	if _, err := tx.Exec(
		ctx, `
		INSERT INTO tenant_memberships (
			id, project_id, tenant_id, user_id, source, role, status,
			created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)`,
		m.ID, m.ProjectID, m.TenantID, m.UserID, m.Source, m.Role, m.Status, now,
	); err != nil {
		return nil, nil, wrapPgErr("CreateOwnedTenant(membership)", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, wrapPgErr("CreateOwnedTenant(commit)", err)
	}
	return t, m, nil
}

// ── domains ─────────────────────────────────────────────────────────────

// DomainStore persists Domains within a Project.
type DomainStore struct {
	pool *tracedPool
}

// NewDomainStore builds a domain store sharing the repository's pool.
func NewDomainStore(r *pgRepository) *DomainStore {
	return &DomainStore{pool: r.pool}
}

const domainColumns = `
	id, project_id, tenant_id, domain, verification_method, status,
	verified_at_ms, created_at_ms, updated_at_ms, legacy_txt_challenge`

func scanDomain(row pgx.Row) (*service.Domain, error) {
	var d service.Domain
	if err := row.Scan(
		&d.ID, &d.ProjectID, &d.TenantID, &d.Domain, &d.VerificationMethod, &d.Status,
		&d.VerifiedAtMs, &d.CreatedAtMs, &d.UpdatedAtMs, &d.LegacyTXTChallenge,
	); err != nil {
		return nil, err
	}
	return &d, nil
}

// CreateDomain inserts a domain. ProjectID, TenantID and Domain are
// required; a blank id is generated and written back. Tenants may contest a
// domain, so the insert is refused with service.ErrAlreadyExists only when
// the tenant already holds the domain or another tenant has verified it. A
// new registration never takes the legacy challenge: migration 0045 sets
// that on the registrations that predate it. The insert runs under the
// domain's auto-formation lock, so it cannot interleave with the auto-former
// choosing a tenant for the domain or with a claim on it being verified.
func (s *DomainStore) CreateDomain(ctx context.Context, d *service.Domain) (string, error) {
	if d == nil {
		return "", errors.New("postgres: CreateDomain: nil domain")
	}
	if d.ProjectID == "" {
		return "", fmt.Errorf("%w: missing project_id", service.ErrInvalidArgument)
	}
	if d.TenantID == "" {
		return "", fmt.Errorf("%w: missing tenant_id", service.ErrInvalidArgument)
	}
	if d.Domain == "" {
		return "", fmt.Errorf("%w: missing domain", service.ErrInvalidArgument)
	}
	method := d.VerificationMethod
	if method == "" {
		method = service.DomainVerificationDNSTXT
	}
	status := d.Status
	if status == "" {
		status = service.DomainStatusPending
	}
	now := nowMs()
	if d.CreatedAtMs == 0 {
		d.CreatedAtMs = now
	}
	if d.UpdatedAtMs == 0 {
		d.UpdatedAtMs = d.CreatedAtMs
	}
	id := d.ID
	if id == "" {
		id = newID()
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", wrapPgErr("CreateDomain", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockXact(ctx, tx, "CreateDomain", autoformLockKey(d.ProjectID, d.Domain)); err != nil {
		return "", err
	}
	const q = `
		INSERT INTO domains (
			id, project_id, tenant_id, domain, verification_method, status,
			verified_at_ms, created_at_ms, updated_at_ms
		)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9
		WHERE NOT EXISTS (
			SELECT 1 FROM domains
			WHERE project_id = $2 AND lower(domain) = lower($4)
			  AND status = 'verified' AND tenant_id <> $3
		)`
	tag, err := tx.Exec(
		ctx, q,
		id, d.ProjectID, d.TenantID, d.Domain, method, status,
		d.VerifiedAtMs, d.CreatedAtMs, d.UpdatedAtMs,
	)
	if err != nil {
		return "", wrapPgErr("CreateDomain", err)
	}
	if tag.RowsAffected() == 0 {
		return "", fmt.Errorf("postgres: CreateDomain: verified by another tenant: %w", service.ErrAlreadyExists)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", wrapPgErr("CreateDomain(commit)", err)
	}
	d.ID = id
	d.LegacyTXTChallenge = false
	d.VerificationMethod = method
	d.Status = status
	return id, nil
}

// GetDomain returns the domain by id within a project, or (nil, nil).
func (s *DomainStore) GetDomain(ctx context.Context, projectID, domainID string) (*service.Domain, error) {
	if projectID == "" || domainID == "" {
		return nil, nil
	}
	const q = `SELECT ` + domainColumns + ` FROM domains WHERE project_id = $1 AND id = $2`
	d, err := scanDomain(s.pool.QueryRow(ctx, q, projectID, domainID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetDomain", err)
	}
	return d, nil
}

// GetVerifiedDomain returns the verified row for a domain name
// (case-insensitive) within a project, or (nil, nil) when no tenant has
// verified it. The verified-domain unique index (0045) makes it at most one
// row and serves the lookup, however many claims the name has.
func (s *DomainStore) GetVerifiedDomain(ctx context.Context, projectID, domain string) (*service.Domain, error) {
	if projectID == "" || domain == "" {
		return nil, nil
	}
	const q = `SELECT ` + domainColumns + `
		FROM domains
		WHERE project_id = $1 AND lower(domain) = lower($2) AND status = 'verified'`
	d, err := scanDomain(s.pool.QueryRow(ctx, q, projectID, domain))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetVerifiedDomain", err)
	}
	return d, nil
}

// SetDomainStatus transitions a domain's status and, when verifying,
// stamps verified_at_ms (0 defaults to now on a verify). Unknown ids, and a
// domain already in the status, are a no-op: a write on a verified domain
// fires the agent-governance trigger (0046), so one that changes nothing
// must not be made. Nor is a verified domain moved to any other status: a
// failed check racing a successful one must not un-verify it, and a domain
// stops being verified only by being removed. Verifying a domain another row
// of the project has verified breaks the verified-domain unique index, which
// surfaces service.ErrAlreadyExists; the verify runs under the domain's
// auto-formation lock, so it cannot interleave with the auto-former choosing
// a tenant for the domain.
func (s *DomainStore) SetDomainStatus(ctx context.Context, projectID, domainID, status string, verifiedAtMs int64) error {
	if projectID == "" || domainID == "" {
		return fmt.Errorf("%w: project_id and domain_id are required", service.ErrInvalidArgument)
	}
	now := nowMs()
	if status == service.DomainStatusVerified && verifiedAtMs == 0 {
		verifiedAtMs = now
	}
	const q = `
		UPDATE domains SET status = $3, verified_at_ms = $4, updated_at_ms = $5
		WHERE project_id = $1 AND id = $2 AND status IS DISTINCT FROM $3`
	if status != service.DomainStatusVerified {
		if _, err := s.pool.Exec(ctx, q+` AND status <> 'verified'`, projectID, domainID, status, verifiedAtMs, now); err != nil {
			return wrapPgErr("SetDomainStatus", err)
		}
		return nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return wrapPgErr("SetDomainStatus", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var name string
	err = tx.QueryRow(ctx, `SELECT domain FROM domains WHERE project_id = $1 AND id = $2`, projectID, domainID).Scan(&name)
	if noRows(err) {
		return nil
	}
	if err != nil {
		return wrapPgErr("SetDomainStatus(read)", err)
	}
	if err := lockXact(ctx, tx, "SetDomainStatus", autoformLockKey(projectID, name)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, q, projectID, domainID, status, verifiedAtMs, now); err != nil {
		return wrapPgErr("SetDomainStatus", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return wrapPgErr("SetDomainStatus(commit)", err)
	}
	return nil
}

// ListDomainsByTenant returns every domain bound to a tenant, newest first.
func (s *DomainStore) ListDomainsByTenant(ctx context.Context, projectID, tenantID string) ([]*service.Domain, error) {
	if projectID == "" || tenantID == "" {
		return nil, nil
	}
	const q = `SELECT ` + domainColumns + `
		FROM domains WHERE project_id = $1 AND tenant_id = $2
		ORDER BY created_at_ms DESC, id DESC`
	rows, err := s.pool.Query(ctx, q, projectID, tenantID)
	if err != nil {
		return nil, wrapPgErr("ListDomainsByTenant", err)
	}
	defer rows.Close()
	var out []*service.Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, wrapPgErr("ListDomainsByTenant scan", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListDomainsByTenant rows", err)
	}
	return out, nil
}

// RecordDomainAttempt counts one CreateDomain or VerifyDomain by a tenant
// against its cap: service.ErrDomainAttemptsLimited when the tenant already
// made a.MaxPerWindow attempts at or after a.WindowStartMs, else the attempt
// is recorded and the tenant's attempts older than the window are pruned, so
// the table holds at most the cap per tenant. Attempts by one tenant are
// serialised by an advisory lock, so concurrent ones cannot both pass a cap
// only one of them fits under.
func (s *DomainStore) RecordDomainAttempt(ctx context.Context, a service.DomainAttempt) error {
	if a.ProjectID == "" || a.TenantID == "" {
		return fmt.Errorf("%w: project_id and tenant_id are required", service.ErrInvalidArgument)
	}
	if a.MaxPerWindow <= 0 {
		return fmt.Errorf("%w: max_per_window must be positive", service.ErrInvalidArgument)
	}
	at := a.AtMs
	if at == 0 {
		at = nowMs()
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return wrapPgErr("RecordDomainAttempt", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockXact(ctx, tx, "RecordDomainAttempt", advisoryKey("domain_attempts", a.ProjectID, a.TenantID)); err != nil {
		return err
	}
	var made int
	if err := tx.QueryRow(
		ctx, `
		SELECT count(*) FROM domain_attempts
		WHERE project_id = $1 AND tenant_id = $2 AND attempted_at_ms >= $3`,
		a.ProjectID, a.TenantID, a.WindowStartMs,
	).Scan(&made); err != nil {
		return wrapPgErr("RecordDomainAttempt(count)", err)
	}
	if made >= a.MaxPerWindow {
		return service.ErrDomainAttemptsLimited
	}
	if _, err := tx.Exec(
		ctx, `
		INSERT INTO domain_attempts (id, project_id, tenant_id, attempted_at_ms)
		VALUES ($1, $2, $3, $4)`,
		newID(), a.ProjectID, a.TenantID, at,
	); err != nil {
		return wrapPgErr("RecordDomainAttempt(insert)", err)
	}
	if _, err := tx.Exec(
		ctx, `
		DELETE FROM domain_attempts
		WHERE project_id = $1 AND tenant_id = $2 AND attempted_at_ms < $3`,
		a.ProjectID, a.TenantID, a.WindowStartMs,
	); err != nil {
		return wrapPgErr("RecordDomainAttempt(prune)", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return wrapPgErr("RecordDomainAttempt(commit)", err)
	}
	return nil
}
