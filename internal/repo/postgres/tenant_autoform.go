package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

// AutoFormStore is the postgres implementation of the tenant
// auto-formation primitive. It writes across the tenants, domains and
// tenant_memberships tables and is the one place that decides, under
// concurrency, which tenant an email domain's signups join.

var _ service.TenantAutoFormStore = (*AutoFormStore)(nil)

// AutoFormStore turns a verified company-email signup into governance rows.
type AutoFormStore struct {
	pool *tracedPool
}

// NewAutoFormStore builds an auto-formation store sharing the repository's
// pool.
func NewAutoFormStore(r *pgRepository) *AutoFormStore {
	return &AutoFormStore{pool: r.pool}
}

// EnsureTenantForDomain idempotently ensures a latent Tenant + its email
// Domain exist for (projectID, domain) and records a domain-derived
// membership for userID. See the interface doc for the concurrency
// contract: tenant+domain are created in one transaction so a lost race
// leaves no orphan tenant.
func (s *AutoFormStore) EnsureTenantForDomain(ctx context.Context, projectID, domain, userID string) (string, error) {
	if projectID == "" {
		return "", fmt.Errorf("%w: missing project_id", service.ErrInvalidArgument)
	}
	if domain == "" {
		return "", fmt.Errorf("%w: missing domain", service.ErrInvalidArgument)
	}
	if userID == "" {
		return "", fmt.Errorf("%w: missing user_id", service.ErrInvalidArgument)
	}

	tenantID, err := s.findOrCreateTenant(ctx, projectID, domain)
	if err != nil {
		return "", err
	}
	if err := s.upsertDerivedMembership(ctx, projectID, tenantID, userID); err != nil {
		return "", err
	}
	return tenantID, nil
}

// findOrCreateTenant returns the tenant an email domain's signups join
// within a project, creating a latent tenant + its domain in one
// transaction when there is none. Registering a domain does not make it a
// tenant's, so a claim another tenant has not proven is never joined: see
// tenantIDForDomain. The domain's auto-formation lock (autoformLockKey)
// serialises that choice, so concurrent signers converge on one tenant.
func (s *AutoFormStore) findOrCreateTenant(ctx context.Context, projectID, domain string) (string, error) {
	if id, err := s.tenantIDForDomain(ctx, s.pool, projectID, domain); err != nil || id != "" {
		return id, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", wrapPgErr("EnsureTenantForDomain", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := lockXact(ctx, tx, "EnsureTenantForDomain", autoformLockKey(projectID, domain)); err != nil {
		return "", err
	}
	// A signer that held the lock before us may have formed the tenant.
	if id, err := s.tenantIDForDomain(ctx, tx, projectID, domain); err != nil || id != "" {
		return id, err
	}

	now := nowMs()
	tenantID := newID()
	if _, err := tx.Exec(
		ctx, `
		INSERT INTO tenants (
			id, project_id, name, primary_domain, status,
			created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $3, 'latent', $4, $4)`,
		tenantID, projectID, domain, now,
	); err != nil {
		return "", wrapPgErr("EnsureTenantForDomain(tenant)", err)
	}
	if _, err := tx.Exec(
		ctx, `
		INSERT INTO domains (
			id, project_id, tenant_id, domain, verification_method, status,
			verified_at_ms, created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $4, 'email', 'pending', 0, $5, $5)`,
		newID(), projectID, tenantID, domain, now,
	); err != nil {
		return "", wrapPgErr("EnsureTenantForDomain(domain)", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", wrapPgErr("EnsureTenantForDomain(commit)", err)
	}
	return tenantID, nil
}

// querier is satisfied by both the pool and a transaction.
type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// tenantIDForDomain returns the tenant a domain's signups join within a
// project (case-insensitive), or "" when none: the tenant that verified the
// domain, else the latent tenant auto-formation made for it. A claim that is
// only registered — anyone's pending or failed dns_txt row, or an email row
// on a tenant that is not auto-formed — is ignored, so registering a domain
// one does not own captures none of its signups. Nor does a suspended
// auto-formed tenant: the domain's next signup forms a new latent tenant,
// which nobody can select until it is claimed by verifying the domain.
//
// The two reads are separate so each is one index probe: the verified row
// through the verified-domain unique index (0045), the oldest email row
// through the partial index 0046 adds. Neither scans the domain's claims.
func (s *AutoFormStore) tenantIDForDomain(ctx context.Context, q querier, projectID, domain string) (string, error) {
	var id string
	err := q.QueryRow(
		ctx, `
		SELECT tenant_id FROM domains
		WHERE project_id = $1 AND lower(domain) = lower($2) AND status = 'verified'`,
		projectID, domain,
	).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !noRows(err) {
		return "", wrapPgErr("tenantIDForDomain(verified)", err)
	}
	err = q.QueryRow(
		ctx, `
		SELECT d.tenant_id FROM domains d
		JOIN tenants t ON t.id = d.tenant_id AND t.project_id = d.project_id
		WHERE d.project_id = $1 AND lower(d.domain) = lower($2)
		  AND d.verification_method = 'email'
		  AND t.status = 'latent' AND t.created_by = ''
		ORDER BY d.created_at_ms, d.id
		LIMIT 1`,
		projectID, domain,
	).Scan(&id)
	if noRows(err) {
		return "", nil
	}
	if err != nil {
		return "", wrapPgErr("tenantIDForDomain(latent)", err)
	}
	return id, nil
}

// upsertDerivedMembership records a domain-derived, active membership for
// the user in the tenant, or refreshes the one they hold. Idempotent on
// (project, tenant, user). A held membership keeps its source: one the user
// created, was invited to or was added to carries more than their email's
// domain does, and relabelling it "domain" would hold it to the
// verified-email rule again.
func (s *AutoFormStore) upsertDerivedMembership(ctx context.Context, projectID, tenantID, userID string) error {
	now := nowMs()
	_, err := s.pool.Exec(
		ctx, `
		INSERT INTO tenant_memberships (
			id, project_id, tenant_id, user_id, source, role, status,
			created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $4, 'domain', 'member', 'active', $5, $5)
		ON CONFLICT (project_id, tenant_id, user_id) DO UPDATE SET
			updated_at_ms = EXCLUDED.updated_at_ms`,
		newID(), projectID, tenantID, userID, now,
	)
	if err != nil {
		return wrapPgErr("EnsureTenantForDomain(membership)", err)
	}
	return nil
}
