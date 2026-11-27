package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

var (
	// ErrMemberIsOwner is returned by SetTenantMemberRole for an owner's
	// membership: an owner's role changes only by TransferTenantOwnership.
	// Mapped to CodeFailedPrecondition.
	ErrMemberIsOwner = errors.New("the member is an owner; an owner's role changes only by transferring the tenant's ownership")
	// ErrIneligibleTenantAdmin is returned by SetTenantMemberRole for a
	// promotion to admin of an account that may not be one: it is not an
	// active, signed-up person, or its email is unverified
	// (requireEligibleTenantAdmin). Mapped to CodeFailedPrecondition.
	ErrIneligibleTenantAdmin = errors.New("this account cannot be a tenant admin")
	// ErrLastTenantGovernor is returned by SetTenantMemberRole for a change
	// that would leave the tenant with no active owner or admin. Mapped to
	// CodeFailedPrecondition.
	ErrLastTenantGovernor = errors.New("the tenant would be left with no active owner or admin")
)

// SetTenantMemberRole sets targetUserID's role in tenantID to role, RoleAdmin
// or RoleMember: an owner or admin promotes a member to admin, or makes an
// admin a member, themselves included, so an admin can step down. callerID
// must be an active owner or admin of a tenant that may be governed, asking
// from a session no recovery hold binds, and still be one where the change is
// written (MembershipStore.SetMemberRole), so one suspended or demoted while
// the call is in flight is ErrPermissionDenied and changes nothing. The
// tenant's status is read before that write, as for a transfer.
//
// RoleOwner is ErrInvalidArgument: ownership moves only by
// TransferTenantOwnership, and an owner's own role is ErrMemberIsOwner. A
// target that is not an active or suspended member is ErrNotFound, as is one
// only through their email's domain once the tenant no longer verifies it. A
// promotion to admin needs an account that may own a tenant
// (requireEligibleTenantAdmin), since an admin sends the tenant's invitations
// too, and no change may leave the tenant without an active owner or admin
// (ErrLastTenantGovernor). A suspended member keeps the suspension. Setting
// the role the member has returns the membership unchanged and records
// nothing; a change is audited as EventTenantMemberRoleChanged with the role
// it replaced. Each call logs one line: tenant_member_role_changed,
// tenant_member_role_unchanged, or tenant_member_role_change_refused with the
// reason.
func (s *MembershipService) SetTenantMemberRole(ctx context.Context, callerID string, signIn SessionSignIn, tenantID, targetUserID, role, ip, userAgent string) (*TenantMembership, error) {
	tenantID, targetUserID = strings.TrimSpace(tenantID), strings.TrimSpace(targetUserID)
	projectID, err := s.requireProject(ctx)
	fields := []zap.Field{
		zap.String("project_id", projectID), zap.String("tenant_id", tenantID),
		zap.String("user_id", targetUserID), zap.String("caller_id", callerID),
	}
	refuse := func(reason string, err error) (*TenantMembership, error) {
		s.logger.Info("tenant_member_role_change_refused", append(fields, zap.String("reason", reason), zap.Error(err))...)
		return nil, err
	}
	if err != nil {
		return refuse("no_project", err)
	}
	if callerID == "" {
		return refuse("unauthenticated", ErrUnauthenticated)
	}
	if err := s.refuseHeldSession(ctx, projectID, callerID, signIn); err != nil {
		return refuse("held_session", err)
	}
	if tenantID == "" {
		return refuse("invalid_argument", fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument))
	}
	if targetUserID == "" {
		return refuse("invalid_argument", fmt.Errorf("%w: missing user_id", ErrInvalidArgument))
	}
	role = strings.ToLower(strings.TrimSpace(role))
	if role != RoleAdmin && role != RoleMember {
		return refuse("invalid_argument", fmt.Errorf("%w: role must be %q or %q; ownership moves only by TransferTenantOwnership",
			ErrInvalidArgument, RoleAdmin, RoleMember))
	}
	fields = append(fields, zap.String("to_role", role))
	if _, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID, signIn); err != nil {
		if !errors.Is(err, ErrPermissionDenied) {
			return refuse("store_error", err)
		}
		return refuse("not_permitted", err)
	}
	user, err := s.users.GetUserInProject(ctx, projectID, targetUserID)
	if err != nil {
		return refuse("store_error", err)
	}
	if user == nil {
		return refuse("not_found", fmt.Errorf("%w: the user is not a member of the tenant", ErrNotFound))
	}
	adminRefusal := requireEligibleTenantAdmin(user)
	m, from, err := s.memberships.SetMemberRole(ctx, MemberRoleChange{
		ProjectID:   projectID,
		TenantID:    tenantID,
		UserID:      targetUserID,
		Role:        role,
		By:          callerID,
		EmailDomain: verifiedEmailDomain(user),
		MayBeAdmin:  adminRefusal == nil,
	})
	if errors.Is(err, ErrIneligibleTenantAdmin) && adminRefusal != nil {
		err = adminRefusal
	}
	switch {
	case errors.Is(err, ErrPermissionDenied):
		return refuse("not_permitted", err)
	case errors.Is(err, ErrNotFound):
		return refuse("not_found", err)
	case errors.Is(err, ErrMemberIsOwner):
		return refuse("member_is_owner", err)
	case errors.Is(err, ErrIneligibleTenantAdmin):
		return refuse("ineligible_admin", err)
	case errors.Is(err, ErrLastTenantGovernor):
		return refuse("last_governor", err)
	case err != nil:
		return refuse("store_error", err)
	case from == m.Role:
		s.logger.Info("tenant_member_role_unchanged", append(fields, zap.String("status", m.Status))...)
		return m, nil
	}
	s.logger.Info("tenant_member_role_changed", append(fields, zap.String("from_role", from), zap.String("status", m.Status))...)
	if s.audit != nil {
		details := memberChangeDetails(m)
		details["previous_role"] = from
		s.audit.Log(ctx, audit.EventTenantMemberRoleChanged,
			audit.WithActor(callerID), audit.WithTarget(m.UserID),
			audit.WithIP(ip), audit.WithUserAgent(userAgent),
			audit.WithSuccess(true), audit.WithDetails(details),
		)
	}
	return m, nil
}

// requireEligibleTenantAdmin refuses, with ErrIneligibleTenantAdmin, an
// account judgeTenantOwner does not find fit to own a tenant: an admin sends
// the tenant's invitations, as an owner does.
func requireEligibleTenantAdmin(u *User) error {
	switch judgeTenantOwner(u) {
	case notAnActivePerson:
		return fmt.Errorf("%w: the account is not an active person's", ErrIneligibleTenantAdmin)
	case ownerEmailUnverified:
		return fmt.Errorf("%w: the account's email is unverified", ErrIneligibleTenantAdmin)
	default:
		return nil
	}
}
