package service

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"
)

// ManagedMembershipReader reads a managed account's membership of the
// tenant that manages it, which decides whether the account may hold a
// session.
type ManagedMembershipReader interface {
	GetMembership(ctx context.Context, projectID, tenantID, userID string) (*TenantMembership, error)
}

// ManagedTenantStatusReader reads the status of the tenant that manages an
// account: a suspended tenant's accounts hold no session.
type ManagedTenantStatusReader interface {
	GetTenantStatus(ctx context.Context, projectID, tenantID string) (string, error)
}

// errManagedStandingUnread is a managed account refused because its
// standing in its tenant could not be read: fail closed, but over no fault
// of the account's, so it is ErrUnavailable (retryable) as well as
// ErrAccountNotActive, a refresh keeps its token and an agent's grant stays
// for a retry.
var errManagedStandingUnread = fmt.Errorf("%w: %w: the account's standing in its tenant could not be read", ErrUnavailable, ErrAccountNotActive)

// managedStanding judges whether a managed account may hold a session or
// stand behind an agent: the one rule every service that mints a token for
// a person or an agent asks. Its zero value reads nothing and refuses every
// managed account (errManagedStandingUnread); personal accounts always pass.
type managedStanding struct {
	memberships ManagedMembershipReader
	tenants     ManagedTenantStatusReader
	logger      *zap.Logger
}

// refuse refuses user, with ErrAccountNotActive, when a tenant manages it
// and it is not active, has never been set up, its membership of the
// managing tenant is not active, or that tenant is neither claimed nor
// latent. A personal account is never read for. Missing readers or a failed
// read refuse too (errManagedStandingUnread). Each refusal is logged once,
// as managed_account_refused with the calling surface.
func (j managedStanding) refuse(ctx context.Context, projectID string, user *User, surface string) error {
	if user.ManagedByTenantID == "" {
		return nil
	}
	logger := j.logger
	if logger == nil {
		logger = zap.NewNop()
	}
	refuse := func(reason string, err error) error {
		logger.Info("managed_account_refused",
			zap.String("project_id", projectID), zap.String("tenant_id", user.ManagedByTenantID),
			zap.String("user_id", user.ID), zap.String("surface", surface), zap.String("reason", reason))
		return err
	}
	switch {
	case user.Status != StatusActive:
		return refuse("account_not_active", fmt.Errorf("%w: account is %s", ErrAccountNotActive, user.Status))
	case user.SetUpAtMs <= 0:
		return refuse("not_set_up", fmt.Errorf("%w: the account has not been set up", ErrAccountNotActive))
	case j.memberships == nil || j.tenants == nil:
		return refuse("no_reader", errManagedStandingUnread)
	}
	m, err := j.memberships.GetMembership(ctx, projectID, user.ManagedByTenantID, user.ID)
	if err != nil {
		logger.Warn("managed_account_membership_read_failed", zap.String("user_id", user.ID), zap.Error(err))
		return refuse("read_failed", errManagedStandingUnread)
	}
	if m == nil || m.Status != MembershipStatusActive {
		return refuse("membership_not_active", fmt.Errorf("%w: your access to this account's organization is not active", ErrAccountNotActive))
	}
	status, err := j.tenants.GetTenantStatus(ctx, projectID, user.ManagedByTenantID)
	if err != nil {
		logger.Warn("managed_account_tenant_read_failed", zap.String("user_id", user.ID), zap.Error(err))
		return refuse("read_failed", errManagedStandingUnread)
	}
	if status != TenantStatusClaimed && status != TenantStatusLatent {
		return refuse("tenant_not_active", fmt.Errorf("%w: this account's organization is not active", ErrAccountNotActive))
	}
	return nil
}

// ownerStands is the one rule for whether owner may stand behind an agent
// now: an active permanent person (else errAgentOwnerNotActive) who, when a
// tenant manages the account, is in standing in it (managedStanding).
func (j managedStanding) ownerStands(ctx context.Context, projectID string, owner *User, surface string) error {
	if !isEligibleAgentOwner(owner) {
		return errAgentOwnerNotActive
	}
	return j.refuse(ctx, projectID, owner, surface)
}

// WithManagedMemberships wires the readers that decide whether a managed
// account may hold a session, and returns the service for chaining. Without
// both, every managed account is refused a session.
func (s *AuthService) WithManagedMemberships(memberships ManagedMembershipReader, tenants ManagedTenantStatusReader) *AuthService {
	s.managedStanding = managedStanding{memberships: memberships, tenants: tenants, logger: s.logger}
	return s
}

// managedStandingKey marks, on a request's context, the account whose
// standing the request has already judged and admitted.
type managedStandingKey struct{}

// withManagedStanding records that the request admitted userID's standing,
// so the token issue that follows does not read it again: a refresh judges
// the standing, the account's or an agent's owner's, before it consumes the
// token, and a second read failing after the consume would spend the token
// for nothing.
func withManagedStanding(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, managedStandingKey{}, userID)
}

// admittedEarlier reports whether the request already admitted user's
// standing (withManagedStanding).
func admittedEarlier(ctx context.Context, user *User) bool {
	admitted, _ := ctx.Value(managedStandingKey{}).(string)
	return admitted != "" && admitted == user.ID
}

// refuseManagedAccount is managedStanding's refusal in the request's
// project from surface, skipping an account this request already admitted.
func (s *AuthService) refuseManagedAccount(ctx context.Context, user *User, surface string) error {
	if admittedEarlier(ctx, user) {
		return nil
	}
	return s.managedStanding.refuse(ctx, s.projectID(ctx), user, surface)
}

// isManagedStandingUnread reports whether err is a managed account refused
// only because its standing could not be read.
func isManagedStandingUnread(err error) bool { return errors.Is(err, errManagedStandingUnread) }

// agentOwnerStanding is managedStanding.ownerStands in the request's
// project, used at creation, transfer, every agent session and every agent
// OAuth or machine exchange; an owner this request already admitted is not
// read again. So suspending or removing a managed member stops their agents
// at the next refresh or exchange, and restoring them lets the agents back.
func (s *AuthService) agentOwnerStanding(ctx context.Context, owner *User) error {
	if !isEligibleAgentOwner(owner) {
		return errAgentOwnerNotActive
	}
	return s.refuseManagedAccount(ctx, owner, "agent_owner")
}
