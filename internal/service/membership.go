package service

import "context"

// This file defines the redesign's tenant-membership and tenant-invitation
// entities and their store interfaces. Membership is the materialized
// record of a user's relationship to a Tenant (a domain-derived,
// invitation-accepted, or admin-added row); invitations are the pending
// offers that, once accepted, become memberships. Both are per-project,
// postgres-backed, and project-scoped like the other governance stores.

// Membership source — how the row came to exist.
const (
	MembershipSourceDomain  = "domain"  // derived from a verified email domain
	MembershipSourceInvited = "invited" // accepted an invitation
	MembershipSourceAdded   = "added"   // added by a tenant admin
	MembershipSourceCreated = "created" // the user created the tenant (CreateTenant)
)

// Membership / invitation role.
const (
	RoleMember = "member"
	RoleAdmin  = "admin"
	RoleOwner  = "owner"
)

// Membership status.
const (
	MembershipStatusActive   = "active"
	MembershipStatusPending  = "pending"
	MembershipStatusInactive = "inactive"
)

// Invitation status.
const (
	InvitationStatusPending  = "pending"
	InvitationStatusAccepted = "accepted"
	InvitationStatusRevoked  = "revoked"
	InvitationStatusExpired  = "expired"
)

// TenantMembership is a user's materialized relationship to a Tenant within
// a Project. At most one row per (project, tenant, user).
type TenantMembership struct {
	ID          string
	ProjectID   string
	TenantID    string
	UserID      string
	Source      string
	Role        string
	Status      string
	CreatedAtMs int64
	UpdatedAtMs int64
}

// TenantInvitation is a pending offer to join a Tenant, addressed to an
// email and redeemed by a hashed token. At most one open (pending)
// invitation per (project, tenant, email).
type TenantInvitation struct {
	ID        string
	ProjectID string
	TenantID  string
	TokenHash string
	Email     string
	// InvitedBy is provenance only — intentionally not an FK, so deleting
	// the inviter neither blocks the delete nor rewrites the audit trail.
	InvitedBy    string
	Role         string
	Status       string
	ExpiresAtMs  int64
	AcceptedAtMs int64
	CreatedAtMs  int64
}

// UserTenant is a tenant a user may act in: an active membership in a
// claimed tenant, with the role the user holds there and how the membership
// began. A domain-derived one (MembershipSourceDomain) counts only while the
// account's email is verified and on a domain the tenant has verified: see
// UserTenantReader.
type UserTenant struct {
	TenantID string
	Name     string
	Role     string
	Source   string
}

// UserTenantReader reads the tenants a user may act in. Both methods apply
// the same rule, so the tenant a refresh may select is exactly one
// ListMyTenants shows: an active membership in a claimed tenant of the
// project, where one that came from the email's domain
// (MembershipSourceDomain) counts only when emailDomain is a domain the
// tenant has verified. emailDomain is the domain of the account's email
// under FoldEmail, as users.email_domain holds it, once that email is
// verified, and "" while it is not, which no domain matches.
type UserTenantReader interface {
	// ListActiveTenantsForUser returns the user's tenants in a project,
	// ordered by name, then id.
	ListActiveTenantsForUser(ctx context.Context, projectID, userID, emailDomain string) ([]*UserTenant, error)
	// GetActiveTenantForUser returns one of them, or (nil, nil) when the
	// tenant is not one the user may act in.
	GetActiveTenantForUser(ctx context.Context, projectID, tenantID, userID, emailDomain string) (*UserTenant, error)
}

// MembershipStore persists TenantMemberships within a Project. Reads that
// miss return (nil, nil).
type MembershipStore interface {
	UserTenantReader

	// UpsertMembership inserts or, on a (project, tenant, user) conflict,
	// updates source/role/status in place (keeping id + created_at_ms).
	// Returns the surviving row id.
	UpsertMembership(ctx context.Context, m *TenantMembership) (string, error)
	// GrantMembership makes m.UserID an active member of m.TenantID at
	// m.Role, unless they already hold an active membership there at m.Role
	// or a higher one (owner, then admin, then member), whose role is then
	// kept. It never lowers a role, so it cannot demote an owner. A kept
	// membership whose source is MembershipSourceDomain takes m.Source, so a
	// grant, an accepted invitation say, lifts the verified-email rule that
	// source carries; any other source is left unchanged. Returns the
	// surviving membership.
	GrantMembership(ctx context.Context, m *TenantMembership) (*TenantMembership, error)
	// GetMembership returns the membership for (project, tenant, user), or
	// (nil, nil).
	GetMembership(ctx context.Context, projectID, tenantID, userID string) (*TenantMembership, error)
	// ListMembershipsForUser returns every membership a user holds across
	// the tenants of a project — the set the auth middleware checks.
	ListMembershipsForUser(ctx context.Context, projectID, userID string) ([]*TenantMembership, error)
	// ListMembershipsForTenant returns every membership in a tenant.
	ListMembershipsForTenant(ctx context.Context, projectID, tenantID string) ([]*TenantMembership, error)
	// RemoveMembership deletes the membership for (project, tenant, user).
	// Unknown rows are a no-op.
	RemoveMembership(ctx context.Context, projectID, tenantID, userID string) error
}

// InvitationStore persists TenantInvitations within a Project. Reads that
// miss return (nil, nil).
type InvitationStore interface {
	// CreateInvitation atomically enforces one-open-invite: in a single
	// transaction it revokes any existing pending invitation for the same
	// (project, tenant, lower(email)) and inserts the new one. A blank id
	// is generated and written back. Returns the new invitation id.
	//
	// limits bounds how many invitations the tenant, the inviter and the
	// recipient account for; the checks and the insert run serialised per
	// tenant, inviter and recipient, so concurrent creates cannot both pass
	// a limit only one of them fits under.
	CreateInvitation(ctx context.Context, inv *TenantInvitation, limits InvitationLimits) (string, error)
	// GetInvitationByTokenHash resolves an invitation by its hashed token
	// within a project, or (nil, nil).
	GetInvitationByTokenHash(ctx context.Context, projectID, tokenHash string) (*TenantInvitation, error)
	// SetInvitationStatus transitions an invitation's status and, when
	// accepting, stamps accepted_at_ms (0 defaults to now on accept).
	// Unknown ids are a no-op.
	SetInvitationStatus(ctx context.Context, projectID, invitationID, status string, acceptedAtMs int64) error
	// ListInvitationsForTenant returns every invitation in a tenant,
	// newest first.
	ListInvitationsForTenant(ctx context.Context, projectID, tenantID string) ([]*TenantInvitation, error)
}

// InvitationLimits bounds how many invitations InvitationStore.CreateInvitation
// lets one tenant, one inviter and one recipient account for. Each invitation
// is an email from the deployment's sender, so the limits keep a tenant admin
// from using it to mail arbitrary addresses without end — however many
// tenants they create to spread the sending over.
type InvitationLimits struct {
	// MaxPerTenant and WindowStartMs cap the tenant's invitations: the create
	// is refused with ErrInvitationLimited when the tenant already has
	// MaxPerTenant invitations, whatever their status, created at or after
	// WindowStartMs. MaxPerTenant must be positive.
	MaxPerTenant  int
	WindowStartMs int64
	// ResendCooldownStartMs is the per-recipient cooldown: the create is
	// refused with ErrInvitationResendTooSoon when the tenant already
	// invited the same address at or after it.
	ResendCooldownStartMs int64
	// MaxPerInviter caps the invitations the inviter (InvitedBy) sent from
	// every tenant of the project at or after WindowStartMs: past it the
	// create is refused with ErrInviterLimited.
	MaxPerInviter int
	// MaxPerRecipient caps the invitations the address was sent from every
	// tenant of the project at or after WindowStartMs: past it the create is
	// refused with ErrInvitationRecipientLimited.
	MaxPerRecipient int
	// A store applies none of the three limits above that is zero. The
	// MembershipService never passes zero: a deployment cannot switch these
	// limits off, as 0 in their GATEWAY_* settings selects the default.
}

// TenantAutoFormStore is the transactional auto-formation primitive: it
// turns "a user signed up with a company email domain" into the governance
// rows that represent it, atomically and idempotently.
type TenantAutoFormStore interface {
	// EnsureTenantForDomain records a domain-derived membership for userID
	// in the tenant that verified the domain or, when none has, in the
	// latent tenant auto-formation made for it, creating that tenant and its
	// email Domain on the domain's first signup. A registration nobody has
	// verified is never joined, so registering a domain captures none of
	// its signups. Concurrent signers on one domain converge on one tenant:
	// the choice and the creation run serialised in one transaction, so no
	// orphan tenant is left. Returns the resolved tenant id.
	//
	// The caller must only invoke this for a non-public domain (see
	// config.IsPublicEmailDomain); the store does not re-check.
	EnsureTenantForDomain(ctx context.Context, projectID, domain, userID string) (string, error)
}
