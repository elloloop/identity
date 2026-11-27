package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/elloloop/identity/internal/config"
)

// ErrManagedAccountsNotAdmitted refuses a managed-account write the server or
// the project does not admit for the tenant: GATEWAY_MANAGED_ACCOUNTS_ENABLED
// is off, the project has not set access.admit_managed_accounts (and
// access.admit_managed_accounts_self_service for a tenant made through
// self-service CreateTenant), or the project refuses the address.
var ErrManagedAccountsNotAdmitted = errors.New("managed accounts are not admitted for this tenant")

// Account kinds ListTenantMembers reports for a member.
const (
	AccountKindPersonal = "personal"
	AccountKindManaged  = "managed"
)

// managedAccountsAdmitted reports whether new managed-account writes are
// admitted for tenant t under the server's cfg and the project's access
// policy.
func managedAccountsAdmitted(cfg *config.Config, access ProjectAccessConfig, t *Tenant) bool {
	if cfg == nil || !cfg.ManagedAccountsEnabled || !access.AdmitManagedAccounts || t == nil {
		return false
	}
	return t.CreatedBy == "" || access.AdmitManagedAccountsSelfService
}

// requireManagedAccountsAdmitted refuses with ErrManagedAccountsNotAdmitted a
// managed-account write the server, the project or its tenant does not
// admit. It reads the tenant from tenants.
func requireManagedAccountsAdmitted(ctx context.Context, cfg *config.Config, tenants TenantStore, scope *ProjectScope, tenantID string) error {
	if cfg == nil || !cfg.ManagedAccountsEnabled || scope == nil || !scope.Access.AdmitManagedAccounts {
		return ErrManagedAccountsNotAdmitted
	}
	t, err := tenants.GetTenant(ctx, scope.ProjectID, tenantID)
	if err != nil {
		return err
	}
	if !managedAccountsAdmitted(cfg, scope.Access, t) {
		return ErrManagedAccountsNotAdmitted
	}
	return nil
}

// managedAccountAddress builds a managed account's canonical address from
// username and domain: the username must pass validateUsernameFormat, the
// domain normalizeDomain, and the address must be a usable mailbox. It
// returns the address and the canonical domain.
func managedAccountAddress(username, domain string) (address, canonicalDomain string, err error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return "", "", fmt.Errorf("%w: missing account_username", ErrInvalidArgument)
	}
	if err := validateUsernameFormat(username); err != nil {
		return "", "", err
	}
	if strings.TrimSpace(domain) == "" {
		return "", "", fmt.Errorf("%w: missing account_domain", ErrInvalidArgument)
	}
	canonicalDomain, err = normalizeDomain(domain)
	if err != nil {
		return "", "", err
	}
	addr, usable := canonicalMailbox(username + "@" + canonicalDomain)
	if !usable || emailDomain(string(addr)) != canonicalDomain {
		return "", "", fmt.Errorf("%w: %s@%s is not a valid address", ErrInvalidArgument, username, canonicalDomain)
	}
	return string(addr), canonicalDomain, nil
}

// refuseProjectAddress refuses, with ErrManagedAccountsNotAdmitted, a managed
// account address the project cannot hold: one on the project's own account
// domain (accounts.domain), whose addresses the project issues itself, or one
// its deny layer refuses.
func refuseProjectAddress(cfg *config.Config, scope *ProjectScope, address, domain string) error {
	if scope.Accounts.Domain != "" && strings.EqualFold(scope.Accounts.Domain, domain) {
		return fmt.Errorf("%w: the project issues its own addresses on this domain", ErrManagedAccountsNotAdmitted)
	}
	if scope.Access.denies(cfg, canonicalEmail(address)) {
		return fmt.Errorf("%w: the project does not admit this address", ErrManagedAccountsNotAdmitted)
	}
	return nil
}
