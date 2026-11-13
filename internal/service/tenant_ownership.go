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
	// ErrTenantStillGoverned is returned by AdminRecoverTenantOwnership,
	// and by a tenant_operator credential's AdminAddTenantAdmin, while the
	// tenant still has an owner or admin who is a person, can sign in and
	// holds an active membership: an owner transfers the ownership,
	// and an admin invites a new owner, instead. A suspended tenant refuses
	// both, so the operator restores it first. Mapped to
	// CodeFailedPrecondition.
	ErrTenantStillGoverned = errors.New("the tenant still has an owner or admin who can sign in")
	// ErrIneligibleTenantMember is returned by AdminAddTenantMember for an
	// account that may not be added to a tenant: it is not an active,
	// signed-up person, or its email is unverified
	// (requireEligibleTenantMember). Mapped to CodeFailedPrecondition.
	ErrIneligibleTenantMember = errors.New("this account cannot be added to a tenant")
	// ErrMemberRefusedByTenant is returned by AdminAddTenantMember for a
	// person whose membership the tenant suspended, or whom its owners or
	// admins removed: an operator's addition does not override them, and an
	// owner or admin restores or invites the person instead. Mapped to
	// CodeFailedPrecondition.
	ErrMemberRefusedByTenant = errors.New("the tenant suspended or removed this person; an owner or admin must restore or invite them")
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
func (s *MembershipService) TransferTenantOwnership(ctx context.Context, callerID string, signIn SessionSignIn, tenantID, newOwnerID, ip, userAgent string) (*OwnershipTransfer, error) {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return nil, err
	}
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	if err := s.refuseHeldSession(ctx, projectID, callerID, signIn); err != nil {
		return nil, err
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
// is verified, since an owner sends the tenant's invitations.
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

// requireEligibleTenantMember refuses, with ErrIneligibleTenantMember, an
// account an operator may not add to a tenant: one that is not an active,
// permanent person (isActivePerson), since an anonymous account is swept by
// retention and an agent acts through its owner, or one whose email is
// unverified, since an operator finds the person by their address and an
// address nobody has proven could put a stranger in the tenant.
func requireEligibleTenantMember(u *User) error {
	switch {
	case !isActivePerson(u):
		return fmt.Errorf("%w: the account is not an active person's", ErrIneligibleTenantMember)
	case !u.EmailVerified:
		return fmt.Errorf("%w: the account's email is unverified", ErrIneligibleTenantMember)
	default:
		return nil
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
// nobody can govern any more: no owner or admin of it who is a person both
// can sign in and holds an active membership. reason, with the operator's
// ip and ua, is kept in the audit trail.
//
// While any owner or admin both can still sign in and holds an active
// membership, recovery is ErrTenantStillGoverned: an owner hands the tenant
// on with TransferTenantOwnership, and an admin invites a new owner with
// CreateTenantInvitation, so an operator never appoints an outside account
// above people who can act. An account pending deletion can still sign in
// (its sign-in cancels the deletion), so it counts as one who can act. The
// exception is when userID is already such an owner: recovery then returns
// that membership unchanged and records nothing, before judging the account
// again, so an operator who retries after a lost response gets the same
// answer.
//
// userID may be any account of the project an owner may be (see
// judgeTenantOwner), a member of the tenant or not; a membership it already
// holds becomes an active owner one and keeps its source. A suspended one is
// restored first (liftSuspension), so the appointment lifts the suspension,
// and the lift is audited when it lands. An owner or admin whose membership
// is suspended does not govern, and does not stop a recovery. The tenant
// must be claimed or suspended: a latent tenant has never had an owner
// (ErrTenantStatusConflict). Only a grant that changed something is audited.
// A refused recovery is not. Recovery reads the governors, then grants, so
// two operators recovering one tenant at once with different accounts may
// each appoint an owner; both are audited. caller presents the admin secret
// or a tenant_operator credential of the project, which the audit records
// then name as their actor.
func (s *ControlPlaneAdminService) AdminRecoverTenantOwnership(ctx context.Context, caller OperatorCredentials, projectID, tenantID, userID, reason, ip, ua string) (*TenantMembership, error) {
	op, err := s.authorizeTenantOperator(ctx, caller, projectID)
	if err != nil {
		return nil, err
	}
	projectID, tenantID, err = requireTenantRef(projectID, tenantID)
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
	governors, err := s.appointableGovernors(ctx, projectID, t)
	if err != nil {
		return nil, err
	}
	if held := governingAs(governors, userID, RoleOwner); held != nil {
		return held, nil
	}
	if err := s.admitAppointment(ctx, projectID, governors, userID); err != nil {
		return nil, err
	}

	restored, err := s.liftSuspension(ctx, op, projectID, tenantID, userID, reason, ip, ua)
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
			audit.WithActor(op.actor), audit.WithTarget(userID), audit.WithIP(ip), audit.WithUserAgent(ua),
			audit.WithSuccess(true), audit.WithDetails(map[string]any{
				"project_id": projectID,
				"tenant_id":  tenantID,
				"reason":     reason,
			}))
	}
	return m, nil
}

// appointableGovernors starts an operator's appointment of a governor of t, a
// tenant of projectID, under recovery's rules: t must be governable
// (requireGovernable), and it returns who can govern t now
// (governorsWhoCanSignIn), the set governingAs and admitAppointment judge the
// appointment against.
func (s *ControlPlaneAdminService) appointableGovernors(ctx context.Context, projectID string, t *Tenant) ([]*TenantMembership, error) {
	if err := requireGovernable(t); err != nil {
		return nil, err
	}
	return s.governorsWhoCanSignIn(ctx, projectID, t.ID)
}

// requireGovernable refuses, with ErrTenantStatusConflict, a latent tenant,
// which has never been governed and which no operator therefore staffs. A
// claimed or suspended tenant is governable.
func requireGovernable(t *Tenant) error {
	if t.Status != TenantStatusClaimed && t.Status != TenantStatusSuspended {
		return fmt.Errorf("%w: the tenant is %s", ErrTenantStatusConflict, t.Status)
	}
	return nil
}

// governingAs returns the membership with which userID is one of governors at
// role, or nil.
func governingAs(governors []*TenantMembership, userID, role string) *TenantMembership {
	for _, m := range governors {
		if m.UserID == userID && m.Role == role {
			return m
		}
	}
	return nil
}

// admitAppointment applies the rest of recovery's rules: userID must be an
// account of projectID that may own a tenant (requireEligibleTenantOwner),
// and none of governors may remain (ErrTenantStillGoverned), so an
// appointment never overrides or lowers people who can act.
func (s *ControlPlaneAdminService) admitAppointment(ctx context.Context, projectID string, governors []*TenantMembership, userID string) error {
	user, err := s.projectAccount(ctx, projectID, userID)
	if err != nil {
		return err
	}
	if err := requireEligibleTenantOwner(user); err != nil {
		return err
	}
	if len(governors) > 0 {
		return ErrTenantStillGoverned
	}
	return nil
}

// projectAccount reads userID in projectID; an account the project does not
// hold is ErrNotFound.
func (s *ControlPlaneAdminService) projectAccount(ctx context.Context, projectID, userID string) (*User, error) {
	user, err := s.users.GetUserInProject(ctx, projectID, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user", ErrNotFound)
	}
	return user, nil
}

// liftSuspension is an operator's restore of userID's membership of the
// tenant, made so that a grant can then write it: the grant refuses a
// suspended one. It reports whether it lifted a suspension, and audits the
// lift at once as EventTenantMemberRestored, with the operator's actor (none
// for the admin secret) and reason, if any, so a grant that then fails
// cannot leave it unrecorded. Any other membership, or none, is left to the
// grant.
func (s *ControlPlaneAdminService) liftSuspension(ctx context.Context, op tenantOperator, projectID, tenantID, userID, reason, ip, ua string) (bool, error) {
	m, restored, err := s.memberships.RestoreMembership(ctx, projectID, tenantID, userID, RestoredByOperator())
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil || !restored {
		return false, err
	}
	details := memberChangeDetails(m)
	if reason != "" {
		details["reason"] = reason
	}
	s.audit.Log(WithProjectScope(ctx, &ProjectScope{ProjectID: projectID}), audit.EventTenantMemberRestored,
		audit.WithActor(op.actor), audit.WithTarget(userID), audit.WithIP(ip), audit.WithUserAgent(ua),
		audit.WithSuccess(true), audit.WithDetails(details))
	return true, nil
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
