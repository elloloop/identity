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
	// ErrTenantHasOwner is returned by AdminRecoverTenantOwnership while the
	// tenant still has an owner who can sign in: that owner transfers the
	// ownership instead. Mapped to CodeFailedPrecondition.
	ErrTenantHasOwner = errors.New("the tenant still has an owner")
)

// OwnershipTransfer is the result of TransferTenantOwnership: the new
// owner's membership and the previous owner's, now an admin.
type OwnershipTransfer struct {
	Owner         *TenantMembership
	PreviousOwner *TenantMembership
}

// TransferTenantOwnership hands callerID's ownership of tenantID to
// newOwnerID, another active member: newOwnerID becomes an owner and callerID
// an admin, in one step, so the tenant never has fewer owners than it had.
// Only an owner may transfer, and only while the tenant may be governed (not
// suspended). The new owner must be an active, signed-up person with a
// verified email, as a tenant's creator must be, since an owner sends the
// tenant's invitations; otherwise the transfer is ErrIneligibleTenantOwner.
// The transfer is audited with callerID as actor and newOwnerID as target.
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

// requireEligibleTenantOwner refuses, with ErrIneligibleTenantOwner, an
// account that may not own a tenant: a missing one; one that is not an
// active, signed-up person (an anonymous account is swept by retention, an
// agent cannot hold what it would own, a merged account is gone); or one
// whose email is unverified, since an owner sends the tenant's invitations.
// CreateTenant holds its caller to the same rule.
func requireEligibleTenantOwner(u *User) error {
	if u == nil {
		return fmt.Errorf("%w: no such account", ErrIneligibleTenantOwner)
	}
	if !isPermanentPerson(u) || !isActiveStatus(u.Status) {
		return fmt.Errorf("%w: the account is not an active person's", ErrIneligibleTenantOwner)
	}
	if !u.EmailVerified {
		return fmt.Errorf("%w: the account's email is unverified", ErrIneligibleTenantOwner)
	}
	return nil
}

// AdminRecoverTenantOwnership appoints userID an owner of a tenant left with
// no owner who can sign in — each was deleted, deactivated or merged away —
// so the tenant can be governed again. reason is kept in the audit trail.
// While any owner can still sign in, that owner hands the tenant on with
// TransferTenantOwnership and recovery is ErrTenantHasOwner; the exception is
// when userID is that owner, which returns their membership unchanged and
// records nothing, so an operator who retries after a lost response gets the
// same answer.
//
// userID may be any account of the project an owner may be (see
// requireEligibleTenantOwner), a member of the tenant or not; a membership it
// already holds becomes an active owner one. The tenant must be claimed or
// suspended: a latent tenant has never had an owner (ErrTenantStatusConflict).
// Recovery reads the owners, then grants, so two operators recovering one
// tenant at once may each appoint an owner; both are audited.
func (s *ControlPlaneAdminService) AdminRecoverTenantOwnership(ctx context.Context, secret, projectID, tenantID, userID, reason string) (*TenantMembership, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	if s.users == nil {
		return nil, ErrUnimplemented
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
	owners, err := s.ownersWhoCanSignIn(ctx, projectID, tenantID)
	if err != nil {
		return nil, err
	}
	for _, m := range owners {
		if m.UserID == userID {
			return m, nil
		}
	}
	if len(owners) > 0 {
		return nil, ErrTenantHasOwner
	}

	m, err := s.memberships.GrantMembership(ctx, &TenantMembership{
		ProjectID: projectID,
		TenantID:  tenantID,
		UserID:    userID,
		Source:    MembershipSourceAdded,
		Role:      RoleOwner,
	})
	if err != nil {
		return nil, err
	}
	s.audit.Log(WithProjectScope(ctx, &ProjectScope{ProjectID: projectID}), audit.EventTenantOwnershipRecovered,
		audit.WithTarget(userID), audit.WithSuccess(true), audit.WithDetails(map[string]any{
			"project_id": projectID,
			"tenant_id":  tenantID,
			"reason":     reason,
		}))
	return m, nil
}

// ownersWhoCanSignIn returns the tenant's active owner memberships whose
// account is still an active person's. An owner whose account was deleted
// has no membership left; one deactivated or merged away keeps a membership
// nobody can use.
func (s *ControlPlaneAdminService) ownersWhoCanSignIn(ctx context.Context, projectID, tenantID string) ([]*TenantMembership, error) {
	members, err := s.memberships.ListMembershipsForTenant(ctx, projectID, tenantID)
	if err != nil {
		return nil, err
	}
	var owners []*TenantMembership
	for _, m := range members {
		if m.Role != RoleOwner || m.Status != MembershipStatusActive {
			continue
		}
		u, err := s.users.GetUserInProject(ctx, projectID, m.UserID)
		if err != nil {
			return nil, err
		}
		if u != nil && isPermanentPerson(u) && isActiveStatus(u.Status) {
			owners = append(owners, m)
		}
	}
	return owners, nil
}
