package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

// AutoFormStore is the postgres implementation of the tenant
// auto-formation primitive. It writes across the tenants, domains and
// tenant_memberships tables and is the one place that enforces
// "one tenant per email domain within a project" under concurrency.

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

// findOrCreateTenant returns the tenant id for an email domain within a
// project, creating a latent tenant + its domain in one transaction when
// none exists. On a lost race (the domain's unique index rejects the
// insert) the whole transaction rolls back — undoing the tenant insert too,
// so no orphan is left — and the winner's tenant is re-read.
func (s *AutoFormStore) findOrCreateTenant(ctx context.Context, projectID, domain string) (string, error) {
	if id, err := s.tenantIDForDomain(ctx, s.pool, projectID, domain); err != nil || id != "" {
		return id, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", wrapPgErr("EnsureTenantForDomain", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

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

	_, err = tx.Exec(
		ctx, `
		INSERT INTO domains (
			id, project_id, tenant_id, domain, verification_method, status,
			verified_at_ms, created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $4, 'email', 'pending', 0, $5, $5)`,
		newID(), projectID, tenantID, domain, now,
	)
	if err != nil {
		// A concurrent signer already created this domain (and its tenant).
		// Roll back — which also undoes our tenant insert, leaving no orphan
		// — and resolve the winner's tenant outside the aborted tx.
		if errors.Is(wrapPgErr("", err), service.ErrAlreadyExists) {
			_ = tx.Rollback(ctx)
			return s.tenantIDForDomain(ctx, s.pool, projectID, domain)
		}
		return "", wrapPgErr("EnsureTenantForDomain(domain)", err)
	}

	if err := tx.Commit(ctx); err != nil {
		// A commit-time unique violation is the same lost race.
		if errors.Is(wrapPgErr("", err), service.ErrAlreadyExists) {
			return s.tenantIDForDomain(ctx, s.pool, projectID, domain)
		}
		return "", wrapPgErr("EnsureTenantForDomain(commit)", err)
	}
	return tenantID, nil
}

// querier is satisfied by both the pool and a transaction.
type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// tenantIDForDomain returns the tenant id mapped to a domain within a
// project (case-insensitive), or "" when none.
func (s *AutoFormStore) tenantIDForDomain(ctx context.Context, q querier, projectID, domain string) (string, error) {
	var id string
	err := q.QueryRow(
		ctx, `
		SELECT tenant_id FROM domains
		WHERE project_id = $1 AND lower(domain) = lower($2)`,
		projectID, domain,
	).Scan(&id)
	if noRows(err) {
		return "", nil
	}
	if err != nil {
		return "", wrapPgErr("tenantIDForDomain", err)
	}
	return id, nil
}

// upsertDerivedMembership records (or refreshes) a domain-derived,
// active membership for the user in the tenant. Idempotent on
// (project, tenant, user).
func (s *AutoFormStore) upsertDerivedMembership(ctx context.Context, projectID, tenantID, userID string) error {
	now := nowMs()
	_, err := s.pool.Exec(
		ctx, `
		INSERT INTO tenant_memberships (
			id, project_id, tenant_id, user_id, source, role, status,
			created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $4, 'domain', 'member', 'active', $5, $5)
		ON CONFLICT (project_id, tenant_id, user_id) DO UPDATE SET
			source = 'domain', updated_at_ms = EXCLUDED.updated_at_ms`,
		newID(), projectID, tenantID, userID, now,
	)
	if err != nil {
		return wrapPgErr("EnsureTenantForDomain(membership)", err)
	}
	return nil
}
