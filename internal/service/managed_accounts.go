package service

import (
	"context"
	"errors"
)

// A managed account is an account a tenant owns: an owner or admin creates it
// on a domain verified for the tenant, before its first sign-in, and it
// belongs to that tenant only (User.ManagedByTenantID). Every write to one
// runs in a single store transaction that takes its locks in one global
// order: the membership's advisory lock (membershipLockKey) where the write
// touches a membership, then the account's users row FOR UPDATE, then the
// tenant's memberships in one ordered pass (lockOwnersAnd / lockGovernorsAnd),
// then the tenant_invitations rows. ManagedSetupStore and ManagedMemberStore
// are those writes; only the postgres control-plane driver has them.

var (
	// ErrManagedByThisTenant refuses an address that is already one of the
	// tenant's managed accounts and cannot take the write asked for.
	ErrManagedByThisTenant = errors.New("the address is already an account this tenant manages")
	// ErrManagedAddressUnavailable refuses an address something outside the
	// tenant holds: a person's account, a recovery email or another tenant's
	// managed account. It never says which.
	ErrManagedAddressUnavailable = errors.New("the address is not available")
	// ErrManagedDomainUnverified refuses an address on a domain the tenant
	// has not verified.
	ErrManagedDomainUnverified = errors.New("the domain is not verified for this tenant")
	// ErrManagedSetupStale refuses a set-up link that is no longer the
	// account's current one: it was revoked or replaced, or the account is no
	// longer waiting to be set up.
	ErrManagedSetupStale = errors.New("this set-up link is no longer valid")
	// ErrManagedResetLimited refuses a reset past the per-delivery-address
	// cap.
	ErrManagedResetLimited = errors.New("too many set-up links sent to this address recently; try again later")
)

// Managed address holders, as ManagedSetupStore.ManagedAddressHolders reports
// them.
const (
	ManagedAddressFree                 = ""
	ManagedAddressManagedByThis        = "managed_by_this_tenant"
	ManagedAddressHeldOutsideTheTenant = "unavailable"
	// ManagedAddressDomainUnverified is an address on a domain the tenant has
	// not verified, which is not looked up at all.
	ManagedAddressDomainUnverified = "domain_unverified"
)

// ManagedSetup asks ManagedSetupStore.CreateManagedSetup for a managed
// account's set-up link: a new account at Address, or a new link for one of
// the tenant's managed accounts that has not been set up yet.
type ManagedSetup struct {
	ProjectID string
	TenantID  string
	// Address is the account's address, <username>@<Domain>, in canonical
	// form. It becomes users.email.
	Address string
	// Domain is Address's domain. It must be verified for TenantID when the
	// link is written.
	Domain string
	// DisplayName is the new account's name; a resend leaves the name as it
	// is.
	DisplayName string
	// DeliveryEmail is where the set-up link is sent.
	DeliveryEmail string
	// Role is the role the account takes in TenantID at set-up.
	Role string
	// InvitedBy must hold an active owner or admin membership of TenantID
	// when the link is written, and an owner one when Role is RoleOwner or
	// the link replaces an owner-role link.
	InvitedBy   string
	TokenHash   string
	ExpiresAtMs int64
	// Limits apply as InvitationStore.CreateInvitation applies them, with
	// Address as the recipient.
	Limits InvitationLimits
}

// ManagedSetupIssued is what CreateManagedSetup wrote.
type ManagedSetupIssued struct {
	// User is the managed account as it now stands.
	User *User
	// Invitation is the new set-up link.
	Invitation *TenantInvitation
	// Created reports whether the account was created by this call; false
	// for a resend.
	Created bool
	// PreviousDeliveryEmail is where the pending link this one replaced was
	// sent, "" when none was pending.
	PreviousDeliveryEmail string
}

// ManagedSetupCompletion is a set-up from a managed account's link
// (ManagedSetupStore.CompleteManagedSetup).
type ManagedSetupCompletion struct {
	ProjectID    string
	InvitationID string
	// TokenHash is the hash of the token the person presented; it must be
	// the link's.
	TokenHash string
	// PasswordHash is the password the person chose, already hashed.
	PasswordHash string
	NowMs        int64
}

// ManagedSetupCompleted is what CompleteManagedSetup wrote.
type ManagedSetupCompleted struct {
	// User is the account as it now stands: active, its email verified.
	User *User
	// Membership is the account's membership of the managing tenant: active
	// with the link's role, or still suspended when it was suspended.
	Membership *TenantMembership
	// Invitation is the link, now accepted.
	Invitation *TenantInvitation
	// FirstSetUp reports whether this was the account's first set-up (it had
	// never been set up before; a set-up after a reset is not).
	FirstSetUp bool
}

// ManagedSetupRevoked is what RevokeManagedSetup did.
type ManagedSetupRevoked struct {
	// Invitation is the link as it now stands.
	Invitation *TenantInvitation
	// Changed reports whether this call revoked a pending link.
	Changed bool
	// DeletedUser is the account this call deleted, nil when it kept it
	// (it had been set up, or was already gone).
	DeletedUser *User
}

// ManagedMemberChange is what SuspendManaged or RemoveManaged did.
type ManagedMemberChange struct {
	// Membership is the membership after a suspension, or as it stood when
	// it was removed.
	Membership *TenantMembership
	// Changed reports whether this call changed anything; a suspension of a
	// suspended membership changes nothing.
	Changed bool
	// RevokedSessionIDs are the sessions this call revoked, the account's
	// and its agents', so the caller can drop them from any session cache
	// after the commit.
	RevokedSessionIDs []string
	// DeactivatedAgentIDs are the account's agents this call deactivated.
	DeactivatedAgentIDs []string
}

// ManagedReset asks ManagedMemberStore.ResetManaged to take a managed account
// back and issue it a new set-up link.
type ManagedReset struct {
	ProjectID string
	TenantID  string
	UserID    string
	// By is the owner or admin resetting: an active owner or admin of
	// TenantID when the reset is written, an owner to reset an owner, and
	// never UserID.
	By            string
	DeliveryEmail string
	TokenHash     string
	ExpiresAtMs   int64
	NowMs         int64
	// Limits: MaxPerTenant and MaxPerInviter (for By) apply with
	// WindowStartMs; the resend cooldown and the per-recipient cap do not.
	Limits InvitationLimits
	// MaxPerDeliveryEmail caps the set-up links sent to DeliveryEmail, under
	// FoldEmail, across the project at or after Limits.WindowStartMs: past it
	// the reset is ErrManagedResetLimited. Zero applies no cap.
	MaxPerDeliveryEmail int
}

// ManagedResetDone is what ResetManaged wrote.
type ManagedResetDone struct {
	// User is the account as it now stands: invited, with no credentials.
	User *User
	// Invitation is the new set-up link.
	Invitation *TenantInvitation
	// NoticeEmails are every address the account had before the reset, its
	// email and its recovery emails, for the notice of the reset.
	NoticeEmails        []string
	RevokedSessionIDs   []string
	DeactivatedAgentIDs []string
}

// ManagedSetupStore writes managed accounts' set-up links.
type ManagedSetupStore interface {
	// CreateManagedSetup creates the managed account at setup.Address with
	// status StatusInvited, set_up_at_ms 0 and setup_epoch 1, or, for one of
	// setup.TenantID's managed accounts still waiting to be set up, bumps its
	// setup_epoch; then revokes every pending link of the account and
	// inserts the new one. The address's holder is decided under the
	// address's lock: one of the tenant's managed accounts that cannot be
	// resent is ErrManagedByThisTenant, and any other holder, an account or a
	// recovery email, ErrManagedAddressUnavailable; both are said only after
	// the domain and the inviter have passed, so they reveal nothing to a
	// caller who could not use the address. A domain not verified for the
	// tenant is ErrManagedDomainUnverified; an inviter who is not an active
	// owner or admin (or owner, where needed) is ErrPermissionDenied;
	// a role other than member, admin or owner is ErrInvalidArgument; limits
	// refuse as CreateInvitation's do.
	CreateManagedSetup(ctx context.Context, setup ManagedSetup) (*ManagedSetupIssued, error)
	// CompleteManagedSetup sets the account's password from its pending,
	// unexpired, current link: the account becomes active with its email
	// verified, set_up_at_ms is stamped if it was 0, and the link is accepted.
	// A membership the account already holds keeps its role and an active or
	// suspended status, so a reset's link never undoes a role change made
	// after the reset; one that has ended is made active again with its role,
	// and an account with none is granted the link's role. An unknown link is
	// ErrNotFound, an accepted one ErrInvitationUsed, an expired one
	// ErrInvitationExpired, one revoked or replaced, or whose account is not
	// waiting to be set up, ErrManagedSetupStale, a domain the tenant no
	// longer verifies ErrManagedDomainUnverified, and a tenant that is not
	// claimed or has no other active owner or admin ErrPermissionDenied. The
	// link's issuer must still be an active owner or admin of the tenant, and
	// an owner where the link grants the owner role (ErrPermissionDenied), as
	// an ordinary invitation's must. An account removed from the tenant is
	// ErrRemovedFromTenant: an old link never brings it back. A TokenHash
	// that is not the link's is ErrNotFound.
	CompleteManagedSetup(ctx context.Context, c ManagedSetupCompletion) (*ManagedSetupCompleted, error)
	// RevokeManagedSetup revokes tenantID's managed set-up link
	// invitationID, if pending, and, at any status of the link, deletes its
	// account while that account is still invited and has never been set up,
	// revoking its other pending links. by must be an active owner or admin of
	// tenantID where the revoke is written (ErrPermissionDenied). An accepted
	// link is ErrInvitationUsed; an id that is not one of the tenant's managed
	// set-up links is ErrNotFound.
	RevokeManagedSetup(ctx context.Context, projectID, tenantID, invitationID, by string) (*ManagedSetupRevoked, error)
	// ManagedAddressHolders reports, for each canonical address, who holds
	// it as tenantID sees it: ManagedAddressFree,
	// ManagedAddressManagedByThis, or ManagedAddressHeldOutsideTheTenant. An
	// address on a domain tenantID has not verified is
	// ManagedAddressDomainUnverified and is not looked up, so no tenant learns
	// who holds addresses on another's domain. It locks nothing; the answer
	// may be stale by the time it is read.
	ManagedAddressHolders(ctx context.Context, projectID, tenantID string, addresses []string) (map[string]string, error)
}

// ManagedMemberStore changes the membership and the account of a managed
// account together.
type ManagedMemberStore interface {
	// SuspendManaged suspends userID's active membership of tenantID, the
	// tenant that manages the account, as SuspendMembership does
	// (ErrLastOwner for the last active owner), and in the same transaction
	// revokes the account's sessions and refresh tokens and deactivates its
	// agents. by must be an active owner or admin of tenantID
	// (ErrPermissionDenied). An account tenantID does not manage, or one with
	// no active or suspended membership, is ErrNotFound. A suspended
	// membership is returned unchanged, with nothing revoked.
	SuspendManaged(ctx context.Context, projectID, tenantID, userID, by string) (*ManagedMemberChange, error)
	// RemoveManaged removes userID's membership of tenantID, the tenant that
	// manages the account, and records the removal, as RemoveMembership does
	// (ErrLastOwner for the last active owner); in the same transaction it
	// deactivates the account, keeping its id and address, revokes its
	// sessions, refresh tokens and pending set-up links, and deactivates its
	// agents. by must be an active owner or admin of tenantID
	// (ErrPermissionDenied). An account tenantID does not manage, or one with
	// no membership there, is ErrNotFound.
	RemoveManaged(ctx context.Context, projectID, tenantID, userID, by string) (*ManagedMemberChange, error)
	// ResetManaged takes a managed account back in one transaction: it
	// collects every address the account has, revokes its sessions and
	// refresh tokens, consumes its outstanding password-reset, magic-link,
	// email-code, email-verification, email-change and recovery-email codes,
	// clears its password, passkeys, provider links, recovery emails, TOTP,
	// backup codes and phone, resets its lockout, deactivates its agents,
	// makes it StatusInvited with its membership unchanged, bumps its
	// setup_epoch, revokes its pending links and inserts a new one with the
	// membership's current role. The account must be one tenantID manages
	// with an active or suspended membership there (ErrNotFound); reset.By
	// must be an active owner or admin of tenantID, an owner to reset an
	// owner, and not the account (ErrPermissionDenied, ErrInvalidArgument).
	ResetManaged(ctx context.Context, reset ManagedReset) (*ManagedResetDone, error)
}
