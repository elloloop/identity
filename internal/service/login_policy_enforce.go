package service

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// LoginGovernance is the read-side bundle the login path consults to enforce
// a claimed tenant's LoginPolicy. It is postgres-only governance state, set
// once via AuthService.WithLoginGovernance; drivers without a governance
// plane (entdb/memory) leave it nil and impose no restriction.
//
// It is deliberately read-only — enforcement never mutates governance state —
// and groups the three stores the lookup walks (domain → tenant → policy) so
// the dependency stays a single optional field on the already-wide service.
type LoginGovernance struct {
	Domains  DomainStore
	Tenants  TenantStore
	Policies LoginPolicyStore
}

// enforceLoginPolicy decides whether the chosen authentication method is
// permitted for the caller's organization, BEFORE any token is issued.
//
// Policy governs HOW a user authenticates, never WHETHER their account
// exists — so this is consulted only after credentials have been verified and
// it returns at most ErrPermissionDenied; it never reveals account existence.
//
// It fails SAFE at every step: no governance bundle, no resolved project, an
// unverified or unknown domain, an unclaimed tenant, an absent policy, or any
// lookup error all impose NO restriction, so a misconfiguration or an
// infrastructure blip can never lock a tenant out of its own login. Only an
// explicit, non-empty AllowedMethods list that omits `method` denies.
//
// method is one of the LoginMethod* tokens (e.g. LoginMethodPassword,
// LoginMethodEmailOTP).
func (s *AuthService) enforceLoginPolicy(ctx context.Context, email, method string) error {
	if s.governance == nil {
		return nil
	}
	projectID := s.projectID(ctx)
	if projectID == "" {
		return nil
	}
	_, domainName, ok := strings.Cut(email, "@")
	if !ok || domainName == "" {
		return nil
	}

	domain, err := s.governance.Domains.GetDomainByName(ctx, projectID, domainName)
	if err != nil {
		s.logger.Warn("login_policy_domain_lookup_failed",
			zap.String("project_id", projectID), zap.Error(err))
		return nil
	}
	if domain == nil || domain.Status != DomainStatusVerified {
		return nil
	}

	tenant, err := s.governance.Tenants.GetTenant(ctx, projectID, domain.TenantID)
	if err != nil {
		s.logger.Warn("login_policy_tenant_lookup_failed",
			zap.String("project_id", projectID), zap.String("tenant_id", domain.TenantID), zap.Error(err))
		return nil
	}
	if tenant == nil || tenant.Status != TenantStatusClaimed {
		return nil
	}

	policy, err := s.governance.Policies.GetLoginPolicy(ctx, projectID, tenant.ID)
	if err != nil {
		s.logger.Warn("login_policy_lookup_failed",
			zap.String("project_id", projectID), zap.String("tenant_id", tenant.ID), zap.Error(err))
		return nil
	}
	if policy == nil || strings.TrimSpace(policy.AllowedMethods) == "" {
		return nil
	}

	// TODO(redesign slice 7c): honor policy.SSORequired (force SSO) and
	// policy.Require2FA (force a second factor after the primary method).
	// Only the AllowedMethods allow-list is enforced here.
	if !allowedMethodsContains(policy.AllowedMethods, method) {
		s.logger.Info("login_method_denied_by_policy",
			zap.String("project_id", projectID),
			zap.String("tenant_id", tenant.ID),
			zap.String("method", method))
		return fmt.Errorf("%w: login method not allowed for your organization", ErrPermissionDenied)
	}
	return nil
}

// allowedMethodsContains reports whether the comma-separated allow-list names
// method. Tokens are trimmed and matched case-insensitively so a policy
// written as "Password, Email_OTP" still matches the LoginMethod* constants.
func allowedMethodsContains(allowedMethods, method string) bool {
	method = strings.ToLower(strings.TrimSpace(method))
	for _, tok := range strings.Split(allowedMethods, ",") {
		if strings.ToLower(strings.TrimSpace(tok)) == method {
			return true
		}
	}
	return false
}
