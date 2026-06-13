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

// MembershipStore persists TenantMemberships within a Project. Reads that
// miss return (nil, nil).
type MembershipStore interface {
	// UpsertMembership inserts or, on a (project, tenant, user) conflict,
	// updates source/role/status in place (keeping id + created_at_ms).
	// Returns the surviving row id.
	UpsertMembership(ctx context.Context, m *TenantMembership) (string, error)
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
	CreateInvitation(ctx context.Context, inv *TenantInvitation) (string, error)
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
