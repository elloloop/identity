package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/elloloop/identity/pkg/audit"
)

// AdminAddTenantMember makes userID an active member of a tenant of the
// project (role member, source added), as an operator adds a person without
// an invitation. The tenant must be claimed or suspended (requireGovernable)
// and userID an account of the project. A person who already holds an
// active membership, of any role and source, keeps it: it is returned
// unchanged and nothing is recorded, before the account is judged, so the
// call never lowers a role and a retry gets the first answer. A membership
// through the email's domain therefore stays bound to that domain. Anyone
// else must be an active, signed-up person with a verified email
// (requireEligibleTenantMember). A person the tenant suspended or removed is
// ErrMemberRefusedByTenant, decided where the membership is written
// (MembershipStore.AddMember): an operator does not override the tenant's
// owners and admins. caller presents the admin secret or a tenant_operator
// credential of the project; both are held to these rules. A membership
// written is audited as EventTenantMemberAdded with the operator's actor,
// ip and ua, and the role and status of the ended membership it renews, if
// any.
func (s *ControlPlaneAdminService) AdminAddTenantMember(ctx context.Context, caller OperatorCredentials, projectID, tenantID, userID, ip, ua string) (*TenantMembership, error) {
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
	t, err := s.getTenant(ctx, projectID, tenantID)
	if err != nil {
		return nil, err
	}
	if err := requireGovernable(t); err != nil {
		return nil, err
	}
	user, err := s.projectAccount(ctx, projectID, userID)
	if err != nil {
		return nil, err
	}
	previous, err := s.memberships.GetMembership(ctx, projectID, tenantID, userID)
	if err != nil {
		return nil, err
	}
	if previous != nil && previous.Status == MembershipStatusActive {
		return previous, nil
	}
	if err := requireEligibleTenantMember(user); err != nil {
		return nil, err
	}
	m, added, err := s.memberships.AddMember(ctx, projectID, tenantID, userID)
	switch {
	case errors.Is(err, ErrMemberSuspended), errors.Is(err, ErrRemovedFromTenant):
		return nil, ErrMemberRefusedByTenant
	case err != nil:
		return nil, err
	}
	if added {
		details := map[string]any{
			"project_id": projectID,
			"tenant_id":  tenantID,
			"role":       m.Role,
		}
		if previous != nil {
			details["previous_role"] = previous.Role
			details["previous_status"] = previous.Status
		}
		s.audit.Log(WithProjectScope(ctx, &ProjectScope{ProjectID: projectID}), audit.EventTenantMemberAdded,
			audit.WithActor(op.actor), audit.WithTarget(userID), audit.WithIP(ip), audit.WithUserAgent(ua),
			audit.WithSuccess(true), audit.WithDetails(details))
	}
	return m, nil
}
