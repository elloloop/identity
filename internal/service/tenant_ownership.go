package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/elloloop/identity/pkg/audit"
)

var (
	// ErrIneligibleTenantOwner is returned when the account a tenant's
	// ownership would go to may not own a tenant: it is not an active,
	// signed-up person, or its email is unverified. Mapped to
	// CodeFailedPrecondition.
	ErrIneligibleTenantOwner = errors.New("this account cannot own a tenant")
	// ErrTenantStillGoverned is returned by AdminRecoverTenantOwnership
	// while the tenant still has an owner or admin who is a person and can
	// sign in: an owner transfers the ownership, and an admin invites a new
	// owner, instead. A suspended tenant refuses both, so the operator
	// restores it first. Mapped to CodeFailedPrecondition.
	ErrTenantStillGoverned = errors.New("the tenant still has an owner or admin who can sign in")
)

// OwnershipTransfer is the result of TransferTenantOwnership: the new
// owner's membership and the previous owner's, now an admin.
type OwnershipTransfer struct {
	Owner         *TenantMembership
	PreviousOwner *TenantMembership
}

// TransferTenantOwnership hands callerID's ownership of tenantID to
// newOwnerID, another active member: newOwnerID becomes an owner and callerID
// an admin, in one step, so the tenant is never left without an owner.
// Naming a co-owner leaves them an owner and callerID an admin, so an owner
// can step down. Only an owner may transfer, and only while the tenant may be
// governed (not suspended); the tenant's status is read before the transfer's
// own transaction, so a suspension that lands in between does not stop it.
// The new owner must be an active, signed-up person with a verified email,
// as a tenant's creator must be, since an owner sends the tenant's
// invitations; otherwise the transfer is ErrIneligibleTenantOwner. A member
// only through their email's domain must still be one: a domain the tenant
// no longer verifies makes them no member (ErrNotFound). The transfer is
// audited with callerID as actor and newOwnerID as target.
func (s *MembershipService) TransferTenantOwnership(ctx context.Context, callerID, tenantID, newOwnerID, ip, userAgent string) (*OwnershipTransfer, error) {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return nil, err
	}
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	tenantID = strings.TrimSpace(tenantID)
	newOwnerID = strings.TrimSpace(newOwnerID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	if newOwnerID == "" {
		return nil, fmt.Errorf("%w: missing user_id", ErrInvalidArgument)
	}
	if newOwnerID == callerID {
		return nil, fmt.Errorf("%w: user_id is the caller", ErrInvalidArgument)
	}
	caller, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID)
	if err != nil {
		return nil, err
	}
	if caller.Role != RoleOwner {
		return nil, fmt.Errorf("%w: only an owner may transfer ownership", ErrPermissionDenied)
	}
	target, err := s.memberships.GetMembership(ctx, projectID, tenantID, newOwnerID)
	if err != nil {
		return nil, err
	}
	if target == nil || target.Status != MembershipStatusActive {
		return nil, fmt.Errorf("%w: user_id is not an active member of the tenant", ErrNotFound)
	}
	user, err := s.users.GetUserInProject(ctx, projectID, newOwnerID)
	if err != nil {
		return nil, err
	}
	if err := requireEligibleTenantOwner(user); err != nil {
		return nil, err
	}
	if target.Source == MembershipSourceDomain {
		held, err := s.memberships.GetActiveTenantForUser(ctx, projectID, tenantID, newOwnerID, verifiedEmailDomain(user))
		if err != nil {
			return nil, err
		}
		if held == nil {
			return nil, fmt.Errorf("%w: user_id is not an active member of the tenant", ErrNotFound)
		}
	}

	from, to, err := s.memberships.TransferOwnership(ctx, projectID, tenantID, callerID, newOwnerID)
	if err != nil {
		return nil, err
	}
	if s.audit != nil {
		s.audit.Log(ctx, audit.EventTenantOwnershipTransferred,
			audit.WithActor(callerID), audit.WithTarget(newOwnerID),
			audit.WithIP(ip), audit.WithUserAgent(userAgent),
			audit.WithSuccess(true), audit.WithDetails(map[string]any{
				"project_id": projectID,
				"tenant_id":  tenantID,
			}),
		)
	}
	return &OwnershipTransfer{Owner: to, PreviousOwner: from}, nil
}

// tenantOwnerFitness is whether an account may own a tenant and, when it may
// not, which part of the rule it fails, so each caller maps that to its own
// refusal.
type tenantOwnerFitness int

const (
	// fitToOwnTenant is an active person with a verified email.
	fitToOwnTenant tenantOwnerFitness = iota
	// notAnActivePerson is a missing account, or one that is not an active,
	// permanent person (isActivePerson).
	notAnActivePerson
	// ownerEmailUnverified is an active person whose email nobody has proven.
	ownerEmailUnverified
)

// judgeTenantOwner applies the one rule for who may own a tenant: an
// active, permanent person (an anonymous account is swept by retention, an
// agent cannot hold what it would own, a merged account is gone) whose email
// is verified, since an owner sends the tenant's invitations. CreateTenant
// holds its caller to it, and a transfer or a recovery the new owner.
func judgeTenantOwner(u *User) tenantOwnerFitness {
	switch {
	case !isActivePerson(u):
		return notAnActivePerson
	case !u.EmailVerified:
		return ownerEmailUnverified
	default:
		return fitToOwnTenant
	}
}

// requireEligibleTenantOwner refuses, with ErrIneligibleTenantOwner, an
// account judgeTenantOwner does not find fit to own a tenant.
func requireEligibleTenantOwner(u *User) error {
	switch judgeTenantOwner(u) {
	case notAnActivePerson:
		return fmt.Errorf("%w: the account is not an active person's", ErrIneligibleTenantOwner)
	case ownerEmailUnverified:
		return fmt.Errorf("%w: the account's email is unverified", ErrIneligibleTenantOwner)
	default:
		return nil
	}
}

// AdminRecoverTenantOwnership appoints userID an owner of a tenant that
// nobody can govern any more: no owner or admin of it can sign in, because
// each was deleted, deactivated or merged away. reason, with the operator's
// ip and ua, is kept in the audit trail.
//
// While any owner or admin can still sign in, recovery is
// ErrTenantStillGoverned: an owner hands the tenant on with
// TransferTenantOwnership, and an admin invites a new owner with
// CreateTenantInvitation, so an operator never appoints an outside account
// above people who can act. An account pending deletion can still sign in
// (its sign-in cancels the deletion), so it counts as one who can act. The
// exception is when userID is already an owner who can sign in: recovery
// then returns that membership unchanged and records nothing, before judging
// the account again, so an operator who retries after a lost response gets
// the same answer.
//
// userID may be any account of the project an owner may be (see
// judgeTenantOwner), a member of the tenant or not; a membership it already
// holds becomes an active owner one and keeps its source. A suspended one is
// restored first (MembershipStore.RestoreMembership), so the appointment
// lifts the suspension. The tenant must be
// claimed or suspended: a latent tenant has never had an owner
// (ErrTenantStatusConflict). Only a grant that changed something is audited.
// A refused recovery is not. Recovery reads the governors, then grants, so
// two operators recovering one tenant at once with different accounts may
// each appoint an owner; both are audited.
func (s *ControlPlaneAdminService) AdminRecoverTenantOwnership(ctx context.Context, secret, projectID, tenantID, userID, reason, ip, ua string) (*TenantMembership, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID, tenantID, err := requireTenantRef(projectID, tenantID)
	if err != nil {
		return nil, err
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("%w: missing user_id", ErrInvalidArgument)
	}
	reason, err = normalizeText("reason", reason, operatorReasonMaxRunes)
	if err != nil {
		return nil, err
	}
	t, err := s.getTenant(ctx, projectID, tenantID)
	if err != nil {
		return nil, err
	}
	if t.Status != TenantStatusClaimed && t.Status != TenantStatusSuspended {
		return nil, fmt.Errorf("%w: the tenant is %s", ErrTenantStatusConflict, t.Status)
	}
	governors, err := s.governorsWhoCanSignIn(ctx, projectID, tenantID)
	if err != nil {
		return nil, err
	}
	for _, m := range governors {
		if m.UserID == userID && m.Role == RoleOwner {
			return m, nil
		}
	}
	user, err := s.users.GetUserInProject(ctx, projectID, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user", ErrNotFound)
	}
	if err := requireEligibleTenantOwner(user); err != nil {
		return nil, err
	}
	if len(governors) > 0 {
		return nil, ErrTenantStillGoverned
	}

	restored, err := s.liftSuspension(ctx, projectID, tenantID, user)
	if err != nil {
		return nil, err
	}
	m, changed, err := s.memberships.GrantMembership(ctx, &TenantMembership{
		ProjectID: projectID,
		TenantID:  tenantID,
		UserID:    userID,
		Source:    MembershipSourceAdded,
		Role:      RoleOwner,
	})
	if err != nil {
		return nil, err
	}
	if changed || restored {
		s.audit.Log(WithProjectScope(ctx, &ProjectScope{ProjectID: projectID}), audit.EventTenantOwnershipRecovered,
			audit.WithTarget(userID), audit.WithIP(ip), audit.WithUserAgent(ua),
			audit.WithSuccess(true), audit.WithDetails(map[string]any{
				"project_id": projectID,
				"tenant_id":  tenantID,
				"reason":     reason,
			}))
	}
	return m, nil
}

// liftSuspension restores user's membership of the tenant when it is
// suspended, so a grant can make it an owner one, and reports whether it
// lifted one. Any other membership, or none, is left to the grant.
func (s *ControlPlaneAdminService) liftSuspension(ctx context.Context, projectID, tenantID string, user *User) (bool, error) {
	held, err := s.memberships.GetMembership(ctx, projectID, tenantID, user.ID)
	if err != nil || held == nil || held.Status != MembershipStatusSuspended {
		return false, err
	}
	_, restored, err := s.memberships.RestoreMembership(ctx, projectID, tenantID, user.ID, accountEmailDomain(user))
	if errors.Is(err, ErrNotFound) {
		// Removed or restored since the read: the grant decides.
		return false, nil
	}
	return restored, err
}

// governorsWhoCanSignIn returns the tenant's active owner and admin
// memberships whose account can still sign in (statusCanSignIn, the rule
// sign-in itself applies) and is a permanent person's. An owner or admin
// whose account was deleted has no membership left; one deactivated or
// merged away keeps a membership nobody can use.
func (s *ControlPlaneAdminService) governorsWhoCanSignIn(ctx context.Context, projectID, tenantID string) ([]*TenantMembership, error) {
	members, err := s.memberships.ListMembershipsForTenant(ctx, projectID, tenantID)
	if err != nil {
		return nil, err
	}
	var governors []*TenantMembership
	for _, m := range members {
		if (m.Role != RoleOwner && m.Role != RoleAdmin) || m.Status != MembershipStatusActive {
			continue
		}
		u, err := s.users.GetUserInProject(ctx, projectID, m.UserID)
		if err != nil {
			return nil, err
		}
		if isPermanentPerson(u) && statusCanSignIn(u.Status) {
			governors = append(governors, m)
		}
	}
	return governors, nil
}
