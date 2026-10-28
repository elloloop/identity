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
	// MembershipStatusSuspended is a membership a tenant owner or admin
	// suspended (SuspendTenantMember): it keeps its role and source, and lets
	// its holder do nothing in the tenant until RestoreTenantMember, or an
	// operator's grant, lifts it.
	MembershipStatusSuspended = "suspended"
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

// RestoredByOperator is the restoredBy of an operator's
// MembershipStore.RestoreMembership: no owner or admin, so nobody's
// membership is checked.
const RestoredByOperator = ""

// MembershipStore persists TenantMemberships within a Project. Reads that
// miss return (nil, nil).
type MembershipStore interface {
	UserTenantReader

	// UpsertMembership inserts or, on a (project, tenant, user) conflict,
	// updates source/role/status in place (keeping id + created_at_ms). A
	// source other than MembershipSourceDomain also deletes the user's
	// removal record (see RemoveMembership). It writes m.Status whatever the
	// row held, so it lifts a suspension. Returns the surviving row id.
	UpsertMembership(ctx context.Context, m *TenantMembership) (string, error)
	// GrantMembership makes m.UserID an active member of m.TenantID at
	// m.Role, unless they already hold an active membership there at m.Role
	// or a higher one (owner, then admin, then member), whose role is then
	// kept. It never lowers a role, so it cannot demote an owner. A kept
	// membership whose source is MembershipSourceDomain takes m.Source, so a
	// grant, an accepted invitation say, lifts the verified-email rule that
	// source carries; any other source is left unchanged. Returns the
	// surviving membership, and whether this call changed it: false when the
	// membership already held the role, or a higher one, from a source the
	// grant keeps. The decision is made where the write is, so of two
	// concurrent grants of the same membership one at most reports a change.
	// A source other than MembershipSourceDomain also deletes the user's
	// removal record (see RemoveMembership), ordered against a removal. A
	// suspended membership is ErrMemberSuspended and is left as it is: only
	// RestoreMembership, or an operator's UpsertMembership, lifts a
	// suspension.
	GrantMembership(ctx context.Context, m *TenantMembership) (granted *TenantMembership, changed bool, err error)
	// GetMembership returns the membership for (project, tenant, user), or
	// (nil, nil).
	GetMembership(ctx context.Context, projectID, tenantID, userID string) (*TenantMembership, error)
	// ListMembershipsForUser returns every membership a user holds across
	// the tenants of a project — the set the auth middleware checks.
	ListMembershipsForUser(ctx context.Context, projectID, userID string) ([]*TenantMembership, error)
	// ListMembershipsForTenant returns every membership in a tenant.
	ListMembershipsForTenant(ctx context.Context, projectID, tenantID string) ([]*TenantMembership, error)
	// RemoveMembership deletes the membership for (project, tenant, user),
	// unless it is the tenant's last active owner (ErrLastOwner): the check
	// and the delete are one step, so no concurrent removal or transfer
	// leaves the tenant without an owner. In the same step it records the
	// removal, which keeps the user from joining the tenant through their
	// email's domain (JoinByDomain) until a membership from another source
	// lets them back in. Returns the membership as it stood when removed;
	// an unknown row is a no-op that returns (nil, nil) and records nothing.
	RemoveMembership(ctx context.Context, projectID, tenantID, userID string) (*TenantMembership, error)
	// JoinByDomain makes userID an active member of the tenant through
	// their email's domain, the verified domain domainID: role member,
	// source MembershipSourceDomain, never lowering a role held. It writes
	// only while that domain is verified on the tenant and allows joining,
	// the tenant is claimed, and the user has no removal record there, all
	// decided where the write is, so a concurrent SetDomainAllowJoin, status
	// change or removal is ordered against it. Returns (nil, false, nil)
	// when the domain or the tenant does not let the user join,
	// ErrRemovedFromTenant while a removal stands, the membership and
	// false when the user already holds an active one, and the membership
	// and true when this call wrote it. A suspended membership is
	// ErrMemberSuspended.
	JoinByDomain(ctx context.Context, projectID, tenantID, userID, domainID string) (joined *TenantMembership, changed bool, err error)
	// IsRemoved reports whether userID has a removal record in the tenant:
	// an owner or admin removed them, and no membership from another source
	// has let them back in since.
	IsRemoved(ctx context.Context, projectID, tenantID, userID string) (bool, error)
	// TransferOwnership makes toUserID an owner of the tenant and fromUserID,
	// an owner, an admin, in one transaction holding both memberships, so a
	// concurrent change to either is seen before anything is written. It
	// refuses with ErrPermissionDenied when fromUserID is not an active owner
	// and with ErrNotFound when toUserID is not an active member. A
	// membership toUserID holds through the email's domain takes source
	// MembershipSourceAdded, as GrantMembership gives it, so the ownership
	// does not end when the email leaves the domain. Returns both memberships
	// as they now stand.
	TransferOwnership(ctx context.Context, projectID, tenantID, fromUserID, toUserID string) (from, to *TenantMembership, err error)
	// SuspendMembership sets the active membership for (project, tenant,
	// user) to MembershipStatusSuspended, keeping its role and source, unless
	// it is the tenant's last active owner (ErrLastOwner): the check and the
	// write are one step, ordered against a removal, a transfer or another
	// suspension. Returns the membership as it now stands, and whether this
	// call suspended it; a suspended membership is returned unchanged. Any
	// other status, or no membership, is ErrNotFound.
	SuspendMembership(ctx context.Context, projectID, tenantID, userID string) (m *TenantMembership, changed bool, err error)
	// RestoreMembership lifts the suspension of the membership for (project,
	// tenant, user), keeping its role and source. It becomes active, except
	// one with source MembershipSourceDomain whose holder's email is not, at
	// that moment, on a domain the tenant has verified: that one becomes
	// inactive. The email is read where the write is, so a change of email
	// cannot slip between them. restoredBy is the owner or admin restoring
	// it, or RestoredByOperator, whom nothing checks: an owner's or admin's
	// membership is checked where the write is, so unless it is an active
	// owner or admin one when the restore lands, it is ErrPermissionDenied
	// and nothing changes. Returns the
	// membership as it now stands, and whether this call lifted a
	// suspension; an active membership is returned unchanged. Any other
	// status, or no membership, is ErrNotFound.
	RestoreMembership(ctx context.Context, projectID, tenantID, userID, restoredBy string) (m *TenantMembership, changed bool, err error)
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
	// MaxPerRecipient caps the invitations the tenant sent the address at or
	// after WindowStartMs: past it the create is refused with
	// ErrInvitationRecipientLimited. Each tenant has its own count, so one
	// tenant reaching it never stops another inviting the address.
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
