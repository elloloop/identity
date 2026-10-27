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
	// TenantStatusClaimed is a tenant that governs: one whose domain has
	// been verified, one an operator created, or one a signed-in user
	// created through CreateTenant (ADR-0018). Its membership is
	// authoritative, and its login policy applies to sign-ins through a
	// domain it has verified.
	TenantStatusClaimed = "claimed"
	// TenantStatusSuspended is an administratively disabled tenant: it
	// cannot be selected for a token or administered by its members, and
	// its login policy still applies to sign-ins through its verified
	// domains.
	TenantStatusSuspended = "suspended"
)

// governsSignIn reports whether a tenant in status holds the sign-ins
// through its verified domains to its login policy. A claimed tenant does,
// and a suspended one still does: a suspension stops selection and
// administration and never loosens sign-in controls. A latent tenant
// governs nothing.
func governsSignIn(status string) bool {
	return status == TenantStatusClaimed || status == TenantStatusSuspended
}

// IsTenantStatus reports whether status is one a tenant may hold.
func IsTenantStatus(status string) bool {
	switch status {
	case TenantStatusLatent, TenantStatusClaimed, TenantStatusSuspended:
		return true
	default:
		return false
	}
}

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

// Tenant is a governance entity within a Project: a company or a team. It
// forms in one of three ways: auto-formed from a user's non-public email
// domain, `latent` until one of its domains is verified and then `claimed`;
// created `claimed` by an operator; or created `claimed`, with no domain, by
// a signed-in user through CreateTenant where the project allows it
// (ADR-0018). It owns email Domains, a LoginPolicy and tenant memberships.
// It is never a workspace: identity models nothing below a tenant.
type Tenant struct {
	ID            string
	ProjectID     string
	Name          string
	PrimaryDomain string
	Status        string
	// CreatedBy is the user who created the tenant through CreateTenant, and
	// empty on a tenant made any other way. Provenance only, never a foreign
	// key: deleting that user leaves it in place.
	CreatedBy   string
	CreatedAtMs int64
	UpdatedAtMs int64
}

// OwnedTenantRequest asks TenantStore.CreateOwnedTenant for a tenant owned
// by the user who creates it.
type OwnedTenantRequest struct {
	ProjectID string
	Name      string
	OwnerID   string
	// MaxPerWindow and WindowStartMs bound how many tenants OwnerID may
	// create: the request is refused with ErrTenantCreationLimited when
	// OwnerID has already created MaxPerWindow tenants at or after
	// WindowStartMs.
	MaxPerWindow  int
	WindowStartMs int64
	// NowMs stamps the new rows: the clock WindowStartMs was measured on, so
	// a creation and the window it counts against agree. 0 means now.
	NowMs int64
}

// TenantPosition is a tenant's place in the newest-first order
// TenantStore.ListTenants pages through: by creation time, then by id.
type TenantPosition struct {
	CreatedAtMs int64
	ID          string
}

// TenantListQuery asks TenantStore.ListTenants for one page of a project's
// tenants.
type TenantListQuery struct {
	ProjectID string
	// After starts the page just after that position; nil starts at the
	// newest tenant.
	After *TenantPosition
	// Limit caps the page and must be positive.
	Limit int
}

// DomainAttempt asks DomainStore.RecordDomainAttempt to count one
// CreateDomain or VerifyDomain by a tenant. Each verify makes the server look
// up a DNS name the tenant chose, so a tenant admin is held to a cap.
type DomainAttempt struct {
	ProjectID string
	TenantID  string
	// AtMs stamps the attempt; 0 means now.
	AtMs int64
	// MaxPerWindow and WindowStartMs cap the tenant's attempts: the attempt
	// is refused with ErrDomainAttemptsLimited when the tenant already made
	// MaxPerWindow attempts at or after WindowStartMs. MaxPerWindow must be
	// positive.
	MaxPerWindow  int
	WindowStartMs int64
}

// Domain is an email domain bound to a Tenant within a Project. Verifying
// it (DNS TXT or email) flips its status to `verified` and claims the
// owning tenant. A registration is only a claim: several tenants may hold
// pending rows for one domain, and the one that proves control first
// verifies it. Once verified it is the domain's only verified row in the
// project — one tenant per verified email domain — and no other tenant may
// register it.
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
	// LegacyTXTChallenge marks a DNS TXT registration made before the
	// challenge named the tenant: it still verifies with the value it was
	// given then (see dnsTXTChallenge). Registrations made since never do.
	LegacyTXTChallenge bool
	// AllowJoin lets a person whose verified email is on the domain join the
	// tenant themselves (JoinTenantByDomain) while the domain is verified.
	// Off on a new domain; a tenant admin sets it with SetDomainJoin.
	AllowJoin bool
}

// TenantStore persists Tenants within a Project. Reads that miss return
// (nil, nil), never an error; only infrastructure failures error.
type TenantStore interface {
	// CreateTenant inserts a tenant. ProjectID is required; a blank id is
	// generated and written back. The assigned id is returned.
	CreateTenant(ctx context.Context, t *Tenant) (string, error)
	// GetTenant returns the tenant by id within a project, or (nil, nil).
	GetTenant(ctx context.Context, projectID, tenantID string) (*Tenant, error)
	// GetTenantStatus returns the status of the tenant by id within a
	// project, or "" when the project has no such tenant. It reads nothing
	// else, for the check every request with a selected-tenant token makes.
	GetTenantStatus(ctx context.Context, projectID, tenantID string) (string, error)
	// GetTenantByPrimaryDomain returns the tenant whose primary_domain
	// equals domain (case-insensitive) within a project, or (nil, nil).
	GetTenantByPrimaryDomain(ctx context.Context, projectID, domain string) (*Tenant, error)
	// SetTenantStatus moves a tenant from status from to status to,
	// comparing and setting in one step so that a change made meanwhile is
	// kept, and reports whether it moved: false for an unknown id or a
	// tenant no longer in from. from and to must be two different tenant
	// statuses (IsTenantStatus); anything else is ErrInvalidArgument.
	SetTenantStatus(ctx context.Context, projectID, tenantID, from, to string) (bool, error)
	// ListTenants returns up to q.Limit tenants of q.ProjectID, whatever
	// their status, newest first (by creation time, then by id descending),
	// starting after q.After.
	ListTenants(ctx context.Context, q TenantListQuery) ([]*Tenant, error)
	// CreateOwnedTenant creates a claimed tenant and its creator's active
	// owner membership (source "created") in one transaction, and returns
	// both. The per-user limit in req is checked inside that transaction,
	// serialized per (project, owner), so concurrent requests cannot pass it
	// together.
	CreateOwnedTenant(ctx context.Context, req OwnedTenantRequest) (*Tenant, *TenantMembership, error)
}

// DomainStore persists Domains within a Project. Reads that miss return
// (nil, nil), never an error.
type DomainStore interface {
	// CreateDomain inserts a domain. ProjectID, TenantID and Domain are
	// required; a blank id is generated and written back. ErrAlreadyExists
	// when the tenant already holds the domain, or another tenant of the
	// project has verified it.
	CreateDomain(ctx context.Context, d *Domain) (string, error)
	// GetDomain returns the domain by id within a project, or (nil, nil).
	GetDomain(ctx context.Context, projectID, domainID string) (*Domain, error)
	// GetVerifiedDomain returns the verified row for a domain name
	// (case-insensitive) within a project, or (nil, nil) when no tenant has
	// verified it. A claim nobody has verified governs nothing, so it is
	// never returned.
	GetVerifiedDomain(ctx context.Context, projectID, domain string) (*Domain, error)
	// SetDomainStatus transitions a domain's status and, when verifying,
	// stamps verified_at_ms (pass 0 to default to now on a verify). Unknown
	// ids, a domain already in the status, and a verified domain asked for
	// any other status, are a no-op: a domain stops being verified only by
	// being removed. Verifying a domain another row of the project has
	// already verified is ErrAlreadyExists.
	SetDomainStatus(ctx context.Context, projectID, domainID, status string, verifiedAtMs int64) error
	// ListDomainsByTenant returns every domain bound to a tenant, newest
	// first.
	ListDomainsByTenant(ctx context.Context, projectID, tenantID string) ([]*Domain, error)
	// SetDomainAllowJoin sets a domain's AllowJoin and returns the domain as
	// it then stands, with whether the call changed it: (nil, false, nil)
	// for an unknown id, and the domain with false when it already has the
	// value. The write must not count as a change of the domain's status,
	// tenant or name, which withdraws agent authority (migration 0046).
	SetDomainAllowJoin(ctx context.Context, projectID, domainID string, allowJoin bool) (*Domain, bool, error)
	// RecordDomainAttempt counts one domain registration or verification by
	// a tenant: ErrDomainAttemptsLimited past the cap in a, else the attempt
	// is recorded. Attempts by one tenant are serialised, so concurrent ones
	// cannot both pass a cap only one of them fits under.
	RecordDomainAttempt(ctx context.Context, a DomainAttempt) error
}
