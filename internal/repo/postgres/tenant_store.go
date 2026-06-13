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
	id, project_id, name, primary_domain, status,
	created_at_ms, updated_at_ms`

func scanTenant(row pgx.Row) (*service.Tenant, error) {
	var t service.Tenant
	if err := row.Scan(
		&t.ID, &t.ProjectID, &t.Name, &t.PrimaryDomain, &t.Status,
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
			id, project_id, name, primary_domain, status,
			created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	if _, err := s.pool.Exec(
		ctx, q,
		id, t.ProjectID, t.Name, t.PrimaryDomain, status,
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

// SetTenantStatus transitions a tenant's status and stamps updated_at.
// Unknown ids are a no-op.
func (s *TenantStore) SetTenantStatus(ctx context.Context, projectID, tenantID, status string) error {
	if projectID == "" || tenantID == "" {
		return fmt.Errorf("%w: project_id and tenant_id are required", service.ErrInvalidArgument)
	}
	const q = `
		UPDATE tenants SET status = $3, updated_at_ms = $4
		WHERE project_id = $1 AND id = $2`
	if _, err := s.pool.Exec(ctx, q, projectID, tenantID, status, nowMs()); err != nil {
		return wrapPgErr("SetTenantStatus", err)
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
	verified_at_ms, created_at_ms, updated_at_ms`

func scanDomain(row pgx.Row) (*service.Domain, error) {
	var d service.Domain
	if err := row.Scan(
		&d.ID, &d.ProjectID, &d.TenantID, &d.Domain, &d.VerificationMethod, &d.Status,
		&d.VerifiedAtMs, &d.CreatedAtMs, &d.UpdatedAtMs,
	); err != nil {
		return nil, err
	}
	return &d, nil
}

// CreateDomain inserts a domain. ProjectID, TenantID and Domain are
// required; a blank id is generated and written back. A duplicate
// (project_id, lower(domain)) surfaces service.ErrAlreadyExists.
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
	const q = `
		INSERT INTO domains (
			id, project_id, tenant_id, domain, verification_method, status,
			verified_at_ms, created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	if _, err := s.pool.Exec(
		ctx, q,
		id, d.ProjectID, d.TenantID, d.Domain, method, status,
		d.VerifiedAtMs, d.CreatedAtMs, d.UpdatedAtMs,
	); err != nil {
		return "", wrapPgErr("CreateDomain", err)
	}
	d.ID = id
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

// GetDomainByName returns the domain row for a name (case-insensitive)
// within a project, or (nil, nil).
func (s *DomainStore) GetDomainByName(ctx context.Context, projectID, domain string) (*service.Domain, error) {
	if projectID == "" || domain == "" {
		return nil, nil
	}
	const q = `SELECT ` + domainColumns + `
		FROM domains WHERE project_id = $1 AND lower(domain) = lower($2)`
	d, err := scanDomain(s.pool.QueryRow(ctx, q, projectID, domain))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetDomainByName", err)
	}
	return d, nil
}

// SetDomainStatus transitions a domain's status and, when verifying,
// stamps verified_at_ms (0 defaults to now on a verify). Unknown ids are a
// no-op.
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
		WHERE project_id = $1 AND id = $2`
	if _, err := s.pool.Exec(ctx, q, projectID, domainID, status, verifiedAtMs, now); err != nil {
		return wrapPgErr("SetDomainStatus", err)
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
