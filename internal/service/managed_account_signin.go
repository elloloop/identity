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

// errManagedStandingUnread is a managed account refused because its
// membership could not be read: fail closed, but over no fault of the
// account's, so a refresh keeps its token for a retry.
var errManagedStandingUnread = fmt.Errorf("%w: the account's standing in its tenant could not be read", ErrAccountNotActive)

// WithManagedMemberships wires the reader that decides whether a managed
// account may hold a session, and returns the service for chaining. Without
// one every managed account is refused a session.
func (s *AuthService) WithManagedMemberships(r ManagedMembershipReader) *AuthService {
	s.managedMemberships = r
	return s
}

// refuseManagedAccount refuses a session, with ErrAccountNotActive, to a
// managed account that is not active, has never been set up, or whose
// membership of its managing tenant is not active. A personal account is
// never read for. A missing reader or a failed read refuses too
// (errManagedStandingUnread). Each refusal is logged.
func (s *AuthService) refuseManagedAccount(ctx context.Context, user *User) error {
	if user.ManagedByTenantID == "" {
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
	case user.SetUpAtMs == 0:
		return refuse("not_set_up", fmt.Errorf("%w: the account has not been set up", ErrAccountNotActive))
	case s.managedMemberships == nil:
		return refuse("no_reader", errManagedStandingUnread)
	}
	m, err := s.managedMemberships.GetMembership(ctx, s.projectID(ctx), user.ManagedByTenantID, user.ID)
	if err != nil {
		s.logger.Warn("managed_account_membership_read_failed", zap.String("user_id", user.ID), zap.Error(err))
		return refuse("read_failed", errManagedStandingUnread)
	}
	if m == nil || m.Status != MembershipStatusActive {
		return refuse("membership_not_active", fmt.Errorf("%w: your access to this account's organization is not active", ErrAccountNotActive))
	}
	return nil
}

// isManagedStandingUnread reports whether err is a managed account refused
// only because its membership could not be read.
func isManagedStandingUnread(err error) bool { return errors.Is(err, errManagedStandingUnread) }
