package service

import "context"

// This file defines the redesign's per-project governance entities —
// Tenant and Domain — and the store interfaces over them. They are
// driver-agnostic value types so the service layer (tenant auto-formation,
// login policy, membership) and its tests depend on a contract, not a
// concrete store. The only production implementation is postgres
// (internal/repo/postgres); the in-memory driver has no
// control/governance plane.
//
// Every store method is explicitly project-scoped: projectID is the
// redesign's isolation boundary, so it is a required leading argument on
// every read and write rather than an ambient repository binding.

// Tenant status values.
const (
	// TenantStatusLatent is a tenant auto-formed from a user's email domain
	// that has not yet had that domain verified. It governs nothing until
	// claimed.
	TenantStatusLatent = "latent"
	// TenantStatusClaimed is a tenant whose domain has been verified; its
	// login policy and membership are now authoritative.
	TenantStatusClaimed = "claimed"
	// TenantStatusSuspended is an administratively disabled tenant.
	TenantStatusSuspended = "suspended"
)

// Domain status values.
const (
	DomainStatusPending  = "pending"
	DomainStatusVerified = "verified"
	DomainStatusFailed   = "failed"
)

// Domain verification methods.
const (
	DomainVerificationDNSTXT = "dns_txt"
	DomainVerificationEmail  = "email"
)

// Tenant is a company-governance entity within a Project, auto-formed per
// verified non-public email domain. It owns email Domains, a LoginPolicy,
// and tenant memberships. A Tenant is `latent` until one of its domains is
// verified, at which point it becomes `claimed` and authoritative.
type Tenant struct {
	ID            string
	ProjectID     string
	Name          string
	PrimaryDomain string
	Status        string
	CreatedAtMs   int64
	UpdatedAtMs   int64
}

// Domain is an email domain bound to a Tenant within a Project. Verifying
// it (DNS TXT or email) flips its status to `verified` and claims the
// owning tenant. (project_id, lower(domain)) is unique — one tenant per
// email domain within a project.
type Domain struct {
	ID                 string
	ProjectID          string
	TenantID           string
	Domain             string
	VerificationMethod string
	Status             string
	VerifiedAtMs       int64
	CreatedAtMs        int64
	UpdatedAtMs        int64
}

// TenantStore persists Tenants within a Project. Reads that miss return
// (nil, nil), never an error; only infrastructure failures error.
type TenantStore interface {
	// CreateTenant inserts a tenant. ProjectID is required; a blank id is
	// generated and written back. The assigned id is returned.
	CreateTenant(ctx context.Context, t *Tenant) (string, error)
	// GetTenant returns the tenant by id within a project, or (nil, nil).
	GetTenant(ctx context.Context, projectID, tenantID string) (*Tenant, error)
	// GetTenantByPrimaryDomain returns the tenant whose primary_domain
	// equals domain (case-insensitive) within a project, or (nil, nil).
	GetTenantByPrimaryDomain(ctx context.Context, projectID, domain string) (*Tenant, error)
	// SetTenantStatus transitions a tenant's status (e.g. latent→claimed)
	// and stamps updated_at. Unknown ids are a no-op.
	SetTenantStatus(ctx context.Context, projectID, tenantID, status string) error
	// ListTenants returns every tenant in a project, newest first.
	ListTenants(ctx context.Context, projectID string) ([]*Tenant, error)
}

// DomainStore persists Domains within a Project. Reads that miss return
// (nil, nil), never an error.
type DomainStore interface {
	// CreateDomain inserts a domain. ProjectID, TenantID and Domain are
	// required; a blank id is generated and written back. A duplicate
	// (project_id, lower(domain)) surfaces ErrAlreadyExists.
	CreateDomain(ctx context.Context, d *Domain) (string, error)
	// GetDomain returns the domain by id within a project, or (nil, nil).
	GetDomain(ctx context.Context, projectID, domainID string) (*Domain, error)
	// GetDomainByName returns the domain row for a name (case-insensitive)
	// within a project, or (nil, nil).
	GetDomainByName(ctx context.Context, projectID, domain string) (*Domain, error)
	// SetDomainStatus transitions a domain's status and, when verifying,
	// stamps verified_at_ms (pass 0 to default to now on a verify). Unknown
	// ids are a no-op.
	SetDomainStatus(ctx context.Context, projectID, domainID, status string, verifiedAtMs int64) error
	// ListDomainsByTenant returns every domain bound to a tenant, newest
	// first.
	ListDomainsByTenant(ctx context.Context, projectID, tenantID string) ([]*Domain, error)
}
