package service

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/passwords"
)

// passwordStrengthPolicyFor returns the per-tenant password StrengthPolicy
// for the org that owns email's domain. When no governed policy applies it
// returns the zero StrengthPolicy, which is the global default — so callers
// can always validate without a nil check and a tenant only ever tightens
// the global baseline.
func (s *AuthService) passwordStrengthPolicyFor(ctx context.Context, email string) passwords.StrengthPolicy {
	_, policy := s.resolveLoginPolicy(ctx, email)
	if policy == nil {
		return passwords.StrengthPolicy{}
	}
	return passwords.StrengthPolicy{
		MinLength:      policy.PasswordMinLength,
		RequireClasses: policy.PasswordRequireClasses,
	}
}

// enforceSessionTimeout invalidates a session whose refresh token has gone
// idle or exceeded its absolute lifetime under the owning tenant's
// LoginPolicy. nowMs is the current epoch ms; createdAtMs/lastUsedAtMs come
// from the refresh-token row. It returns ErrSessionExpired when a configured
// timeout is breached and nil otherwise (including when no policy or no
// timeout is set — fail-safe to the global behavior).
func (s *AuthService) enforceSessionTimeout(ctx context.Context, email string, nowMs, createdAtMs, lastUsedAtMs int64) error {
	_, policy := s.resolveLoginPolicy(ctx, email)
	if policy == nil {
		return nil
	}
	if policy.SessionAbsoluteTimeoutSeconds > 0 && createdAtMs > 0 {
		if nowMs-createdAtMs > policy.SessionAbsoluteTimeoutSeconds*msPerSecond {
			s.logger.Info("session_absolute_timeout_exceeded",
				zap.String("email_domain", emailDomain(email)))
			return fmt.Errorf("%w: session exceeded its maximum lifetime", ErrSessionExpired)
		}
	}
	if policy.SessionIdleTimeoutSeconds > 0 && lastUsedAtMs > 0 {
		if nowMs-lastUsedAtMs > policy.SessionIdleTimeoutSeconds*msPerSecond {
			s.logger.Info("session_idle_timeout_exceeded",
				zap.String("email_domain", emailDomain(email)))
			return fmt.Errorf("%w: session timed out due to inactivity", ErrSessionExpired)
		}
	}
	return nil
}

// emailDomain returns the domain part of an email for low-cardinality
// logging, or "" when the address has no domain.
func emailDomain(email string) string {
	_, domain, _ := strings.Cut(email, "@")
	return domain
}

// msPerSecond converts the policy's second-granularity timeouts to the
// epoch-ms granularity the refresh-token timestamps use.
const msPerSecond = 1000

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
	tenant, policy := s.resolveLoginPolicy(ctx, email)
	if policy == nil {
		return noop, nil
	}
	projectID := s.projectID(ctx)
	return s.applyLoginPolicy(tenant, policy, projectID, method)
}

// resolveLoginPolicy walks the governance plane (domain → tenant → policy)
// for the claimed tenant that owns email's domain and returns its
// LoginPolicy, or (nil, nil) when there is no governed policy to apply.
//
// It fails SAFE at every step — no governance bundle, no resolved project,
// an unverified or unknown domain, an unclaimed tenant, an absent policy, or
// any lookup error all return (nil, nil) so a caller imposes NO restriction.
// The tenant is returned alongside the policy so callers that audit or log
// can name the org without a second lookup.
func (s *AuthService) resolveLoginPolicy(ctx context.Context, email string) (*Tenant, *LoginPolicy) {
	if s.governance == nil {
		return nil, nil
	}
	projectID := s.projectID(ctx)
	if projectID == "" {
		return nil, nil
	}
	_, domainName, ok := strings.Cut(email, "@")
	if !ok || domainName == "" {
		return nil, nil
	}

	domain, err := s.governance.Domains.GetDomainByName(ctx, projectID, domainName)
	if err != nil {
		s.logger.Warn("login_policy_domain_lookup_failed",
			zap.String("project_id", projectID), zap.Error(err))
		return nil, nil
	}
	if domain == nil || domain.Status != DomainStatusVerified {
		return nil, nil
	}

	tenant, err := s.governance.Tenants.GetTenant(ctx, projectID, domain.TenantID)
	if err != nil {
		s.logger.Warn("login_policy_tenant_lookup_failed",
			zap.String("project_id", projectID), zap.String("tenant_id", domain.TenantID), zap.Error(err))
		return nil, nil
	}
	if tenant == nil || tenant.Status != TenantStatusClaimed {
		return nil, nil
	}

	policy, err := s.governance.Policies.GetLoginPolicy(ctx, projectID, tenant.ID)
	if err != nil {
		s.logger.Warn("login_policy_lookup_failed",
			zap.String("project_id", projectID), zap.String("tenant_id", tenant.ID), zap.Error(err))
		return nil, nil
	}
	if policy == nil {
		return nil, nil
	}
	return tenant, policy
}

// applyLoginPolicy enforces the three orthogonal controls of an already
// resolved LoginPolicy (SSO-required → allow-list → 2FA) for a verified
// method, returning at most ErrSSORequired / ErrPermissionDenied or a
// RequireSecondFactor decision. projectID/tenant are passed in for logging.
func (s *AuthService) applyLoginPolicy(tenant *Tenant, policy *LoginPolicy, projectID, method string) (loginPolicyDecision, error) {
	var noop loginPolicyDecision

	// 1. SSO required: the tenant authenticates exclusively through its IdP.
	// Every non-SSO method is blocked and the caller is steered to the SSO
	// connection. This outranks the allow-list — an SSO-required tenant has
	// no business letting any local method through, even one the allow-list
	// happens to name.
	if policy.SSORequired && method != LoginMethodSSO {
		s.logger.Info("login_method_blocked_sso_required",
			zap.String("project_id", projectID),
			zap.String("tenant_id", tenant.ID),
			zap.String("method", method))
		return noop, fmt.Errorf("%w: this organization requires single sign-on", ErrSSORequired)
	}

	// 2. AllowedMethods allow-list. Empty means "no restriction" — an empty
	// allow-list must never lock a tenant out of its own login.
	if strings.TrimSpace(policy.AllowedMethods) != "" &&
		!allowedMethodsContains(policy.AllowedMethods, method) {
		s.logger.Info("login_method_denied_by_policy",
			zap.String("project_id", projectID),
			zap.String("tenant_id", tenant.ID),
			zap.String("method", method))
		return noop, fmt.Errorf("%w: login method not allowed for your organization", ErrPermissionDenied)
	}

	// 3. Require 2FA. A permitted single-factor primary (password/email_otp/
	// oauth) must be followed by a second factor; a method that is already
	// strong (passkey/sso) satisfies the requirement on its own.
	if policy.Require2FA && !isSecondFactorSatisfyingMethod(method) {
		s.logger.Info("login_requires_second_factor_by_policy",
			zap.String("project_id", projectID),
			zap.String("tenant_id", tenant.ID),
			zap.String("method", method))
		return loginPolicyDecision{RequireSecondFactor: true}, nil
	}

	return noop, nil
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
