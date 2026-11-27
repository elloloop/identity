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
// of the account's, so a refresh keeps its token and an agent's grant stays
// for a retry.
var errManagedStandingUnread = fmt.Errorf("%w: the account's standing in its tenant could not be read", ErrAccountNotActive)

// WithManagedMemberships wires the readers that decide whether a managed
// account may hold a session, and returns the service for chaining. Without
// both, every managed account is refused a session.
func (s *AuthService) WithManagedMemberships(memberships ManagedMembershipReader, tenants ManagedTenantStatusReader) *AuthService {
	s.managedMemberships, s.managedTenantStatus = memberships, tenants
	return s
}

// managedStandingKey marks, on a request's context, the managed account
// whose standing the request has already judged and admitted.
type managedStandingKey struct{}

// withManagedStanding records that the request admitted userID's standing,
// so the token issue that follows does not read it again: a refresh judges
// the standing before it consumes the token, and a second read failing
// after the consume would spend the token for nothing.
func withManagedStanding(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, managedStandingKey{}, userID)
}

// refuseManagedAccount refuses a session, with ErrAccountNotActive, to a
// managed account that is not active, has never been set up, whose
// membership of its managing tenant is not active, or whose managing tenant
// is neither claimed nor latent. A personal account is never read for, nor
// an account this request already admitted (withManagedStanding). Missing
// readers or a failed read refuse too (errManagedStandingUnread). Each
// refusal is logged.
func (s *AuthService) refuseManagedAccount(ctx context.Context, user *User) error {
	if user.ManagedByTenantID == "" {
		return nil
	}
	if admitted, _ := ctx.Value(managedStandingKey{}).(string); admitted != "" && admitted == user.ID {
		return nil
	}
	refuse := func(reason string, err error) error {
		s.logger.Info("managed_account_refused",
			zap.String("project_id", s.projectID(ctx)), zap.String("tenant_id", user.ManagedByTenantID),
			zap.String("user_id", user.ID), zap.String("path", "session"), zap.String("reason", reason), zap.Error(err))
		return err
	}
	switch {
	case user.Status != StatusActive:
		return refuse("account_not_active", fmt.Errorf("%w: account is %s", ErrAccountNotActive, user.Status))
	case user.SetUpAtMs <= 0:
		return refuse("not_set_up", fmt.Errorf("%w: the account has not been set up", ErrAccountNotActive))
	case s.managedMemberships == nil || s.managedTenantStatus == nil:
		return refuse("no_reader", errManagedStandingUnread)
	}
	projectID := s.projectID(ctx)
	m, err := s.managedMemberships.GetMembership(ctx, projectID, user.ManagedByTenantID, user.ID)
	if err != nil {
		s.logger.Warn("managed_account_membership_read_failed", zap.String("user_id", user.ID), zap.Error(err))
		return refuse("read_failed", errManagedStandingUnread)
	}
	if m == nil || m.Status != MembershipStatusActive {
		return refuse("membership_not_active", fmt.Errorf("%w: your access to this account's organization is not active", ErrAccountNotActive))
	}
	status, err := s.managedTenantStatus.GetTenantStatus(ctx, projectID, user.ManagedByTenantID)
	if err != nil {
		s.logger.Warn("managed_account_tenant_read_failed", zap.String("user_id", user.ID), zap.Error(err))
		return refuse("read_failed", errManagedStandingUnread)
	}
	if status != TenantStatusClaimed && status != TenantStatusLatent {
		return refuse("tenant_not_active", fmt.Errorf("%w: this account's organization is not active", ErrAccountNotActive))
	}
	return nil
}

// isManagedStandingUnread reports whether err is a managed account refused
// only because its standing could not be read.
func isManagedStandingUnread(err error) bool { return errors.Is(err, errManagedStandingUnread) }

// agentOwnerStanding is the one rule for whether owner may stand behind an
// agent now, at creation, transfer, every agent session and every agent
// OAuth or machine exchange: an active permanent person (else
// errAgentOwnerNotActive) who, when a tenant manages the account, holds a
// session in its own right (refuseManagedAccount). So suspending or
// removing a managed member stops their agents at the next refresh or
// exchange, and restoring them lets the agents back.
func (s *AuthService) agentOwnerStanding(ctx context.Context, owner *User) error {
	if !isEligibleAgentOwner(owner) {
		return errAgentOwnerNotActive
	}
	return s.refuseManagedAccount(ctx, owner)
}
