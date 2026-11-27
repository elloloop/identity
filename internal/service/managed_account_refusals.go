package service

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"
)

// ErrManagedAccount refuses, to an account a tenant manages, an operation
// only a person's own account may take: the tenant that manages it decides
// what it holds, where it belongs and when it ends. Mapped to
// CodePermissionDenied.
var ErrManagedAccount = errors.New("managed_account: this account is managed by its organization; ask one of its owners or admins")

// refuseManagedAccountPath refuses user, with ErrManagedAccount, when a
// tenant manages it, logging the refusal as managed_account_refused with
// path; nil for a personal account.
func refuseManagedAccountPath(ctx context.Context, logger *zap.Logger, projectID string, user *User, path string) error {
	if user == nil || user.ManagedByTenantID == "" {
		return nil
	}
	logger.Info("managed_account_refused",
		zap.String("project_id", projectID), zap.String("tenant_id", user.ManagedByTenantID),
		zap.String("user_id", user.ID), zap.String("path", path))
	return ErrManagedAccount
}

// managedAccountsMayMerge is the rule that keeps a managed account out of
// every merge, on either side: a merge would move a tenant's account, or
// its credentials, into or out of the tenant's hands. A later operation that
// adopts a personal account into a tenant is the one way past it.
func managedAccountsMayMerge(survivor, other *User) bool {
	return survivor.ManagedByTenantID == "" && other.ManagedByTenantID == ""
}

// tenantOwnsProvider reports whether a tenant owns the OAuth provider, so
// that its managed accounts may sign in, or be linked, through it. No tenant
// owns a provider yet, so every provider is refused to a managed account:
// otherwise whoever holds a provider account at the same address would
// control the tenant's account.
func tenantOwnsProvider(_, _ string) bool { return false }

// refuseManagedProvider refuses user, with ErrManagedAccount, signing in or
// being linked through provider unless the tenant that manages it owns the
// provider; nil for a personal account.
func refuseManagedProvider(ctx context.Context, logger *zap.Logger, projectID string, user *User, provider string) error {
	if user == nil || user.ManagedByTenantID == "" || tenantOwnsProvider(user.ManagedByTenantID, provider) {
		return nil
	}
	return refuseManagedAccountPath(ctx, logger, projectID, user, "oauth:"+provider)
}

// managedAccountWaiting reports whether address is a managed account still
// waiting to be set up, to which no sign-in code or link is sent: only its
// set-up link sets it up. It runs inside the dispatched send, after the
// constant-work reply. A failed lookup sends as before: redeeming the code
// or link refuses such an account anyway.
func (s *AuthService) managedAccountWaiting(ctx context.Context, address string) bool {
	u, err := s.repo(ctx).FindUserByEmail(ctx, address)
	if err != nil {
		s.logger.Warn("managed_account_lookup_failed", zap.Error(err))
		return false
	}
	if u == nil || u.ManagedByTenantID == "" || u.Status != StatusInvited {
		return false
	}
	_ = refuseManagedAccountPath(ctx, s.logger, s.projectID(ctx), u, "passwordless_send:invited")
	return true
}

// refuseManagedLeave refuses callerID, with ErrManagedAccount, removing
// themselves from a tenant when a tenant manages their account.
func (s *MembershipService) refuseManagedLeave(ctx context.Context, projectID, callerID string) error {
	caller, err := s.users.GetUserInProject(ctx, projectID, callerID)
	if err != nil {
		return err
	}
	return refuseManagedAccountPath(ctx, s.logger, projectID, caller, "leave_tenant")
}

// endManagedSetupLinks revokes every pending set-up link of u when a tenant
// manages it, as RevokeManagedSetup does when it deletes an account, before
// u is purged. A managed account is not purged without the managed store
// (ErrUnavailable).
func (s *AdminService) endManagedSetupLinks(ctx context.Context, u *User) error {
	if u.ManagedByTenantID == "" {
		return nil
	}
	if s.managedSetups == nil {
		return fmt.Errorf("%w: a managed account's set-up links cannot be ended here", ErrUnavailable)
	}
	if err := s.managedSetups.RevokeSetupLinksOf(ctx, s.projectID(ctx), u.ID); err != nil {
		return fmt.Errorf("end set-up links: %w", err)
	}
	return nil
}
