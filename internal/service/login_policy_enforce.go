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
// plane (memory) leave it nil and impose no restriction.
//
// It is deliberately read-only — enforcement never mutates governance state —
// and groups the three stores the lookup walks (domain → tenant → policy) so
// the dependency stays a single optional field on the already-wide service.
type LoginGovernance struct {
	Domains  DomainStore
	Tenants  TenantStore
	Policies LoginPolicyStore
}

// loginPolicyDecision is the outcome of consulting a claimed tenant's
// LoginPolicy after a primary method has been verified. The zero value is
// "no governed restriction" — every fail-safe exit returns it — so a caller
// can always act on the decision without a nil check.
type loginPolicyDecision struct {
	// RequireSecondFactor is set when the tenant's policy mandates 2FA and
	// the verified method is a single-factor primary (password, email_otp,
	// oauth). The caller must complete a second-factor step before minting
	// full tokens rather than issuing them directly. Methods that are
	// already strong (passkey, sso) never set this — they satisfy 2FA on
	// their own.
	RequireSecondFactor bool
}

// isSecondFactorSatisfyingMethod reports whether a login method already
// constitutes strong (multi-factor) authentication and therefore satisfies a
// Require2FA policy on its own. A passkey assertion proves device possession
// plus user verification; SSO delegates the factor count to the IdP. The
// single-factor primaries (password, email_otp, oauth) do not qualify and
// must be followed by a second-factor step when 2FA is required.
func isSecondFactorSatisfyingMethod(method string) bool {
	switch method {
	case LoginMethodPasskey, LoginMethodSSO:
		return true
	default:
		return false
	}
}

// enforceLoginPolicy decides whether and how the chosen authentication method
// may complete for the caller's organization, BEFORE any token is issued.
//
// Policy governs HOW a user authenticates, never WHETHER their account
// exists — so this is consulted only after credentials have been verified and
// it returns at most ErrPermissionDenied / ErrSSORequired; it never reveals
// account existence.
//
// It fails SAFE at every step: no governance bundle, no resolved project, an
// unverified or unknown domain, an unclaimed tenant, an absent policy, or any
// lookup error all impose NO restriction (returning the zero decision), so a
// misconfiguration or an infrastructure blip can never lock a tenant out of
// its own login.
//
// Three orthogonal controls are enforced, in order of severity:
//
//  1. SSORequired — the tenant has delegated authentication to an IdP, so
//     every non-SSO method is blocked with ErrSSORequired, steering the user
//     to the SSO connection.
//  2. AllowedMethods — a non-empty allow-list that omits `method` denies it
//     with ErrPermissionDenied.
//  3. Require2FA — a permitted single-factor primary still needs a second
//     factor, signalled via the returned decision (not an error).
//
// method is one of the LoginMethod* tokens (e.g. LoginMethodPassword,
// LoginMethodEmailOTP).
func (s *AuthService) enforceLoginPolicy(ctx context.Context, email, method string) (loginPolicyDecision, error) {
	var noop loginPolicyDecision
	if s.governance == nil {
		return noop, nil
	}
	projectID := s.projectID(ctx)
	if projectID == "" {
		return noop, nil
	}

	// The tenant LoginPolicy, when one applies, fully governs and overrides
	// the project-wide default; otherwise the project default (which may be
	// empty = no restriction) applies. This layering — tenant overrides
	// project overrides global — is what lets a tenant-less user (the common
	// case for a consumer pool) still be constrained project-wide.
	eff, tenantID := s.effectiveLoginPolicy(ctx, projectID, email)

	// 1. SSO required: authentication is exclusively through the IdP. Every
	// non-SSO method is blocked and the caller is steered to the SSO
	// connection. This outranks the allow-list — an SSO-required org has no
	// business letting any local method through, even one the allow-list
	// happens to name.
	if eff.SSORequired && method != LoginMethodSSO {
		s.logger.Info("login_method_blocked_sso_required",
			zap.String("project_id", projectID),
			zap.String("tenant_id", tenantID),
			zap.String("method", method))
		return noop, fmt.Errorf("%w: this organization requires single sign-on", ErrSSORequired)
	}

	// 2. AllowedMethods allow-list. Empty means "no restriction" — an empty
	// allow-list must never lock a user out of their own login.
	if strings.TrimSpace(eff.AllowedMethods) != "" &&
		!allowedMethodsContains(eff.AllowedMethods, method) {
		s.logger.Info("login_method_denied_by_policy",
			zap.String("project_id", projectID),
			zap.String("tenant_id", tenantID),
			zap.String("method", method))
		return noop, fmt.Errorf("%w: login method not allowed for your organization", ErrPermissionDenied)
	}

	// 3. Require 2FA. A permitted single-factor primary (password/email_otp/
	// oauth) must be followed by a second factor; a method that is already
	// strong (passkey/sso) satisfies the requirement on its own.
	if eff.Require2FA && !isSecondFactorSatisfyingMethod(method) {
		s.logger.Info("login_requires_second_factor_by_policy",
			zap.String("project_id", projectID),
			zap.String("tenant_id", tenantID),
			zap.String("method", method))
		return loginPolicyDecision{RequireSecondFactor: true}, nil
	}

	return noop, nil
}

// effectiveLoginPolicy resolves the policy that governs email's login in
// project projectID, layering the tenant LoginPolicy OVER the project-wide
// default. It returns the effective controls and the governing tenant id (""
// when only the project default applies).
//
// It fails SAFE at every step: an unverified or unknown domain, an unclaimed
// tenant, an absent tenant policy, or any lookup error all fall back to the
// project default rather than locking a user out — so a misconfiguration or
// an infrastructure blip can never become a login lockout. A tenant policy,
// once found, fully replaces the project default (it does not merge field by
// field): a tenant that deliberately runs an open login must not inherit a
// project-wide restriction.
func (s *AuthService) effectiveLoginPolicy(ctx context.Context, projectID, email string) (loginControls, string) {
	project := projectLoginControls(ctx)

	_, domainName, ok := strings.Cut(email, "@")
	if !ok || domainName == "" {
		return project, ""
	}

	domain, err := s.governance.Domains.GetDomainByName(ctx, projectID, domainName)
	if err != nil {
		s.logger.Warn("login_policy_domain_lookup_failed",
			zap.String("project_id", projectID), zap.Error(err))
		return project, ""
	}
	if domain == nil || domain.Status != DomainStatusVerified {
		return project, ""
	}

	tenant, err := s.governance.Tenants.GetTenant(ctx, projectID, domain.TenantID)
	if err != nil {
		s.logger.Warn("login_policy_tenant_lookup_failed",
			zap.String("project_id", projectID), zap.String("tenant_id", domain.TenantID), zap.Error(err))
		return project, ""
	}
	if tenant == nil || tenant.Status != TenantStatusClaimed {
		return project, ""
	}

	policy, err := s.governance.Policies.GetLoginPolicy(ctx, projectID, tenant.ID)
	if err != nil {
		s.logger.Warn("login_policy_lookup_failed",
			zap.String("project_id", projectID), zap.String("tenant_id", tenant.ID), zap.Error(err))
		return project, ""
	}
	if policy == nil {
		return project, ""
	}
	return loginControls{
		AllowedMethods: policy.AllowedMethods,
		SSORequired:    policy.SSORequired,
		Require2FA:     policy.Require2FA,
	}, tenant.ID
}

// loginControls is the resolved, source-agnostic set of login restrictions the
// enforcement applies. It is the common shape both a tenant LoginPolicy and a
// project-wide default reduce to, so the three checks run once over either.
type loginControls struct {
	AllowedMethods string
	SSORequired    bool
	Require2FA     bool
}

// projectLoginControls reads the project-wide login default off the request's
// resolved project scope. The zero value (no scope, or a project that
// configures none) imposes no restriction, so a deployment without a control
// plane or a project with empty config_json behaves exactly as before.
//
// A project-wide default has no SSO connection of its own, so it never sets
// SSORequired — forcing SSO without an IdP would lock the whole project out.
func projectLoginControls(ctx context.Context) loginControls {
	scope := ProjectScopeFromContext(ctx)
	if scope == nil {
		return loginControls{}
	}
	return loginControls{
		AllowedMethods: scope.LoginDefaults.AllowedMethods,
		Require2FA:     scope.LoginDefaults.Require2FA,
	}
}

// requireSecondFactor is the shared tail every single-factor primary login
// takes once its credential is proven but a second factor is still owed —
// either because the user enrolled TOTP (user.TotpRequired) or because the
// tenant's LoginPolicy mandates 2FA (policyForced).
//
// It issues a single-use login challenge so the caller returns
// TotpRequired=true with no tokens; the client then completes the login via
// VerifyTotp. When 2FA is forced by policy but the user has not yet enrolled
// a verified TOTP credential, there is no second factor to verify — minting
// tokens anyway would defeat the policy, so it returns ErrTotpRequired to
// steer the user into enrollment rather than handing them a challenge they
// cannot answer.
func (s *AuthService) requireSecondFactor(ctx context.Context, user *User, policyForced bool) (*LoginResult, error) {
	if policyForced && !user.TotpRequired {
		cred, err := s.repo(ctx).GetTotpCredential(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		if cred == nil || !cred.Verified {
			s.logger.Info("login_policy_2fa_required_no_factor_enrolled",
				zap.String("user_id", user.ID))
			return nil, fmt.Errorf("%w: your organization requires two-factor authentication; enroll a second factor", ErrTotpRequired)
		}
	}

	challengeID, err := s.issueLoginChallenge(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		User:             user,
		TotpRequired:     true,
		LoginChallengeID: challengeID,
	}, nil
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
