package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/passwords"
	"github.com/elloloop/identity/pkg/totp"
)

// ── Fake governance stores ─────────────────────────────────────────────
//
// The login-policy lookup walks domain → tenant → policy, all read-only, so
// the fakes serve fixtures from maps keyed exactly as the real stores are
// addressed: (projectID, lowercased-name) for domains and (projectID, id)
// for tenants/policies. Each store can also be forced to error so the
// fail-safe paths are exercised.

type lpDomainStore struct {
	byName map[string]*Domain // key: projectID + "|" + domainName
	err    error
}

func (f *lpDomainStore) GetDomainByName(_ context.Context, projectID, domain string) (*Domain, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byName[projectID+"|"+domain], nil
}

// The remaining DomainStore methods are unused by enforcement; they satisfy
// the interface so the fake is assignable to LoginGovernance.Domains.
func (f *lpDomainStore) CreateDomain(context.Context, *Domain) (string, error) { return "", nil }

func (f *lpDomainStore) GetDomain(context.Context, string, string) (*Domain, error) {
	return nil, nil
}

func (f *lpDomainStore) SetDomainStatus(context.Context, string, string, string, int64) error {
	return nil
}

func (f *lpDomainStore) ListDomainsByTenant(context.Context, string, string) ([]*Domain, error) {
	return nil, nil
}

type lpTenantStore struct {
	byID map[string]*Tenant // key: projectID + "|" + tenantID
	err  error
}

func (f *lpTenantStore) GetTenant(_ context.Context, projectID, tenantID string) (*Tenant, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byID[projectID+"|"+tenantID], nil
}

func (f *lpTenantStore) CreateTenant(context.Context, *Tenant) (string, error) { return "", nil }
func (f *lpTenantStore) GetTenantByPrimaryDomain(context.Context, string, string) (*Tenant, error) {
	return nil, nil
}
func (f *lpTenantStore) SetTenantStatus(context.Context, string, string, string) error { return nil }
func (f *lpTenantStore) ListTenants(context.Context, string) ([]*Tenant, error)        { return nil, nil }

type fakePolicyStore struct {
	byTenant map[string]*LoginPolicy // key: projectID + "|" + tenantID
	err      error
}

func (f *fakePolicyStore) GetLoginPolicy(_ context.Context, projectID, tenantID string) (*LoginPolicy, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byTenant[projectID+"|"+tenantID], nil
}

func (f *fakePolicyStore) UpsertLoginPolicy(context.Context, *LoginPolicy) (string, error) {
	return "", nil
}

var (
	_ DomainStore      = (*lpDomainStore)(nil)
	_ TenantStore      = (*lpTenantStore)(nil)
	_ LoginPolicyStore = (*fakePolicyStore)(nil)
)

// claimedPasswordOnlyGovernance wires a claimed tenant `acme.com` whose
// verified domain points at it and whose policy permits password only.
func claimedPasswordOnlyGovernance() *LoginGovernance {
	const project, tenant, domain = "proj-1", "tenant-acme", "acme.com"
	return &LoginGovernance{
		Domains: &lpDomainStore{byName: map[string]*Domain{
			project + "|" + domain: {ProjectID: project, TenantID: tenant, Domain: domain, Status: DomainStatusVerified},
		}},
		Tenants: &lpTenantStore{byID: map[string]*Tenant{
			project + "|" + tenant: {ID: tenant, ProjectID: project, Status: TenantStatusClaimed},
		}},
		Policies: &fakePolicyStore{byTenant: map[string]*LoginPolicy{
			project + "|" + tenant: {ProjectID: project, TenantID: tenant, AllowedMethods: LoginMethodPassword},
		}},
	}
}

// withAllowedMethods returns a claimed-tenant governance bundle for
// acme.com whose policy permits exactly the given methods — a convenience
// over claimedPasswordOnlyGovernance for tests that need a different
// allow-list (e.g. one that permits oauth but not password).
func withAllowedMethods(methods string) *LoginGovernance {
	g := claimedPasswordOnlyGovernance()
	g.Policies.(*fakePolicyStore).byTenant["proj-1|tenant-acme"].AllowedMethods = methods
	return g
}

// enforceErr drops the policy decision and returns only the error, so the
// many fail-safe assertions that care only about allow/deny stay terse. Tests
// that inspect the second-factor decision call enforceLoginPolicy directly.
func enforceErr(ctx context.Context, t *testing.T, svc *AuthService, email, method string) error {
	t.Helper()
	_, err := svc.enforceLoginPolicy(ctx, email, method)
	return err
}

// withSSORequired returns a claimed-tenant governance bundle for acme.com
// whose policy mandates SSO. AllowedMethods is left empty so the test proves
// SSO-required blocks on its own, independent of any allow-list.
func withSSORequired() *LoginGovernance {
	g := claimedPasswordOnlyGovernance()
	p := g.Policies.(*fakePolicyStore).byTenant["proj-1|tenant-acme"]
	p.AllowedMethods = ""
	p.SSORequired = true
	p.SSOConnectionJSON = `{"type":"saml","idp":"https://idp.acme.com"}`
	return g
}

// withRequire2FA returns a claimed-tenant governance bundle for acme.com
// whose policy mandates a second factor. AllowedMethods is left empty so the
// requirement is proven on its own.
func withRequire2FA() *LoginGovernance {
	g := claimedPasswordOnlyGovernance()
	p := g.Policies.(*fakePolicyStore).byTenant["proj-1|tenant-acme"]
	p.AllowedMethods = ""
	p.Require2FA = true
	return g
}

// seedVerifiedTotp enrolls a verified TOTP credential for the user so a
// Require2FA login can complete its second-factor step.
func seedVerifiedTotp(t *testing.T, repo *fakeRepo, userID string) {
	t.Helper()
	encrypted, err := totp.EncryptSecret("JBSWY3DPEHPK3PXP", testTotpKey())
	require.NoError(t, err)
	repo.mu.Lock()
	id := nextNodeID()
	repo.totpCreds[id] = &TotpCredRecord{
		NodeID:          id,
		UserID:          userID,
		SecretEncrypted: encrypted,
		Verified:        true,
	}
	repo.mu.Unlock()
}

// ── enforceLoginPolicy ──────────────────────────────────────────────────

// A claimed tenant with a password-only policy rejects an email_otp login but
// permits a password login. Policy governs HOW, not WHETHER.
func TestEnforceLoginPolicy_PasswordOnlyTenant(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())
	ctx := withProject("proj-1")

	require.NoError(t, enforceErr(ctx, t, svc, "alice@acme.com", LoginMethodPassword),
		"password is on the allow-list and must pass")

	err := enforceErr(ctx, t, svc, "alice@acme.com", LoginMethodEmailOTP)
	require.ErrorIs(t, err, ErrPermissionDenied,
		"email_otp is not on the allow-list and must be denied")
}

// An allow-list written with whitespace and mixed case still matches the
// LoginMethod* constants — a policy is human-editable governance data.
func TestEnforceLoginPolicy_AllowedMethodsTokenNormalization(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	g := claimedPasswordOnlyGovernance()
	g.Policies.(*fakePolicyStore).byTenant["proj-1|tenant-acme"].AllowedMethods = " Password , Email_OTP "
	svc.WithLoginGovernance(g)
	ctx := withProject("proj-1")

	require.NoError(t, enforceErr(ctx, t, svc, "alice@acme.com", LoginMethodPassword))
	require.NoError(t, enforceErr(ctx, t, svc, "alice@acme.com", LoginMethodEmailOTP))
	require.ErrorIs(t, enforceErr(ctx, t, svc, "alice@acme.com", LoginMethodOAuth), ErrPermissionDenied)
}

// A password-only policy denies every other distinct authentication method
// — oauth and passkey included — so the allow-list cannot be sidestepped by
// switching method. (The end-to-end passkey path requires a real WebAuthn
// assertion and is not unit-testable; the enforcement decision is.)
func TestEnforceLoginPolicy_PasswordOnlyDeniesOtherMethods(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())
	ctx := withProject("proj-1")

	for _, method := range []string{LoginMethodOAuth, LoginMethodPasskey, LoginMethodSSO} {
		require.ErrorIs(t, enforceErr(ctx, t, svc, "alice@acme.com", method), ErrPermissionDenied,
			"%s must be denied for a password-only tenant", method)
	}
}

// A nil governance bundle (entdb/memory) imposes no restriction.
func TestEnforceLoginPolicy_NilBundle_NoOp(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	// governance left nil.
	require.NoError(t, enforceErr(withProject("proj-1"), t, svc, "alice@acme.com", LoginMethodEmailOTP))
}

// With no resolved project there is nothing to scope the lookup to.
func TestEnforceLoginPolicy_NoProject_NoOp(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())
	// cfg.DefaultProjectID is empty and no scope is set.
	require.NoError(t, enforceErr(context.Background(), t, svc, "alice@acme.com", LoginMethodEmailOTP))
}

// A domain unknown to the project (e.g. a public/consumer domain) is not
// governed, so any method is allowed.
func TestEnforceLoginPolicy_UnknownDomain_NoRestriction(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())
	ctx := withProject("proj-1")
	require.NoError(t, enforceErr(ctx, t, svc, "bob@gmail.com", LoginMethodEmailOTP))
}

// A pending (unverified) domain governs nothing — its tenant has not been
// claimed by proving control of the domain.
func TestEnforceLoginPolicy_UnverifiedDomain_NoRestriction(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	g := claimedPasswordOnlyGovernance()
	g.Domains.(*lpDomainStore).byName["proj-1|acme.com"].Status = DomainStatusPending
	svc.WithLoginGovernance(g)
	require.NoError(t, enforceErr(withProject("proj-1"), t, svc, "alice@acme.com", LoginMethodEmailOTP))
}

// A latent (unclaimed) tenant governs nothing even when its domain row exists
// and is marked verified — status drives authority, not the row's presence.
func TestEnforceLoginPolicy_LatentTenant_NoRestriction(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	g := claimedPasswordOnlyGovernance()
	g.Tenants.(*lpTenantStore).byID["proj-1|tenant-acme"].Status = TenantStatusLatent
	svc.WithLoginGovernance(g)
	require.NoError(t, enforceErr(withProject("proj-1"), t, svc, "alice@acme.com", LoginMethodEmailOTP))
}

// A claimed tenant with no policy row imposes no restriction (fail safe).
func TestEnforceLoginPolicy_NoPolicy_NoRestriction(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	g := claimedPasswordOnlyGovernance()
	delete(g.Policies.(*fakePolicyStore).byTenant, "proj-1|tenant-acme")
	svc.WithLoginGovernance(g)
	require.NoError(t, enforceErr(withProject("proj-1"), t, svc, "alice@acme.com", LoginMethodEmailOTP))
}

// A policy with an empty AllowedMethods list imposes no restriction — an
// empty allow-list must never lock a tenant out of its own login.
func TestEnforceLoginPolicy_EmptyAllowedMethods_NoRestriction(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	g := claimedPasswordOnlyGovernance()
	g.Policies.(*fakePolicyStore).byTenant["proj-1|tenant-acme"].AllowedMethods = "   "
	svc.WithLoginGovernance(g)
	require.NoError(t, enforceErr(withProject("proj-1"), t, svc, "alice@acme.com", LoginMethodEmailOTP))
}

// A malformed email with no domain part is not governed.
func TestEnforceLoginPolicy_NoDomainPart_NoRestriction(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())
	require.NoError(t, enforceErr(withProject("proj-1"), t, svc, "alice", LoginMethodEmailOTP))
}

// Every lookup error fails safe: a domain/tenant/policy store outage must
// never become a login lockout.
func TestEnforceLoginPolicy_LookupErrors_FailSafe(t *testing.T) {
	boom := errors.New("boom")

	t.Run("domain lookup error", func(t *testing.T) {
		svc, _, _ := newAuthSvcWithMailer(t)
		g := claimedPasswordOnlyGovernance()
		g.Domains.(*lpDomainStore).err = boom
		svc.WithLoginGovernance(g)
		require.NoError(t, enforceErr(withProject("proj-1"), t, svc, "alice@acme.com", LoginMethodEmailOTP))
	})

	t.Run("tenant lookup error", func(t *testing.T) {
		svc, _, _ := newAuthSvcWithMailer(t)
		g := claimedPasswordOnlyGovernance()
		g.Tenants.(*lpTenantStore).err = boom
		svc.WithLoginGovernance(g)
		require.NoError(t, enforceErr(withProject("proj-1"), t, svc, "alice@acme.com", LoginMethodEmailOTP))
	})

	t.Run("policy lookup error", func(t *testing.T) {
		svc, _, _ := newAuthSvcWithMailer(t)
		g := claimedPasswordOnlyGovernance()
		g.Policies.(*fakePolicyStore).err = boom
		svc.WithLoginGovernance(g)
		require.NoError(t, enforceErr(withProject("proj-1"), t, svc, "alice@acme.com", LoginMethodEmailOTP))
	})
}

// ── End-to-end enforcement on the login paths ───────────────────────────

// PasswordLogin honours a password-only policy: the password login of a
// governed user succeeds.
func TestPasswordLogin_AllowedByPolicy(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())
	pwHash, _ := passwords.Hash("Str0ng!Passw0rd")
	seedUser(repo, "alice@acme.com", pwHash, "active")

	res, err := svc.PasswordLogin(withProject("proj-1"), "alice@acme.com", "Str0ng!Passw0rd", "", "")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
}

// VerifyEmailLoginCode is denied when the tenant's policy permits password
// only — and the denial is ErrPermissionDenied (HOW), not an
// invalid-credential error (which would imply the account doesn't exist).
func TestVerifyEmailLoginCode_DeniedByPasswordOnlyPolicy(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())
	ctx := withProject("proj-1")
	pwHash, _ := passwords.Hash("Str0ng!Passw0rd")
	seedUser(repo, "alice@acme.com", pwHash, "active")

	require.NoError(t, svc.RequestEmailLoginCode(ctx, "alice@acme.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)

	_, err := svc.VerifyEmailLoginCode(ctx, "alice@acme.com", code, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied,
		"email_otp must be denied for a password-only tenant")
}

// With no governance plane wired, an email_otp login of the same user
// proceeds untouched — the enforcement is purely additive.
func TestVerifyEmailLoginCode_NoGovernance_Allowed(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	ctx := withProject("proj-1")
	pwHash, _ := passwords.Hash("Str0ng!Passw0rd")
	seedUser(repo, "alice@acme.com", pwHash, "active")

	require.NoError(t, svc.RequestEmailLoginCode(ctx, "alice@acme.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)

	res, err := svc.VerifyEmailLoginCode(ctx, "alice@acme.com", code, "", "")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
}

// OAuthLogin is denied when the tenant's policy omits oauth — the allow-list
// governs every distinct authentication method, not just password/otp. The
// denial is ErrPermissionDenied (HOW), not an account-existence error.
func TestOAuthLogin_DeniedByPolicy(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())

	code := fakeOAuthCode("alice@acme.com", "Alice", "", "google")
	_, err := svc.OAuthLogin(withProject("proj-1"), code, "google", "https://app/cb", "", "", "", "", "")
	require.ErrorIs(t, err, ErrPermissionDenied,
		"oauth must be denied for a password-only tenant")
}

// OAuthLogin is permitted when the tenant's policy includes oauth.
func TestOAuthLogin_AllowedByPolicy(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.WithLoginGovernance(withAllowedMethods(LoginMethodOAuth))

	code := fakeOAuthCode("alice@acme.com", "Alice", "", "google")
	res, err := svc.OAuthLogin(withProject("proj-1"), code, "google", "https://app/cb", "", "", "", "", "")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
}

// The hosted-flow redeem honours the same policy: a password-only tenant
// denies a code minted from an oauth login.
func TestRedeemOAuthCode_DeniedByPolicy(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := withProject("proj-1")

	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish")
	require.NoError(t, err)
	cb, err := svc.CompleteHostedOAuth(ctx, "google",
		fakeOAuthCode("alice@acme.com", "Alice", "", "google"),
		stateTokenFromAuthURL(t, begin.AuthorizationURL), "1.2.3.4", "test-agent")
	require.NoError(t, err)

	// Policy is consulted at redeem, the point tokens would be issued.
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())
	_, err = svc.RedeemOAuthCode(ctx, cb.Code, "1.2.3.4", "test-agent")
	require.ErrorIs(t, err, ErrPermissionDenied,
		"oauth redeem must be denied for a password-only tenant")
}

// ── SSORequired ─────────────────────────────────────────────────────────

// An SSO-required tenant blocks every non-SSO method with ErrSSORequired,
// steering the user to the SSO connection rather than revealing anything
// about the account.
func TestEnforceLoginPolicy_SSORequired_BlocksNonSSOMethods(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withSSORequired())
	ctx := withProject("proj-1")

	for _, method := range []string{
		LoginMethodPassword, LoginMethodEmailOTP, LoginMethodOAuth, LoginMethodPasskey,
	} {
		err := enforceErr(ctx, t, svc, "alice@acme.com", method)
		require.ErrorIs(t, err, ErrSSORequired,
			"%s must be blocked for an sso-required tenant", method)
	}
}

// The SSO method itself is never blocked by SSORequired — it is the one
// permitted path.
func TestEnforceLoginPolicy_SSORequired_AllowsSSO(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withSSORequired())
	require.NoError(t, enforceErr(withProject("proj-1"), t, svc, "alice@acme.com", LoginMethodSSO))
}

// SSO-required outranks the allow-list: even a method the allow-list happens
// to name is still blocked when SSO is required.
func TestEnforceLoginPolicy_SSORequired_OutranksAllowList(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	g := withSSORequired()
	g.Policies.(*fakePolicyStore).byTenant["proj-1|tenant-acme"].AllowedMethods = LoginMethodPassword
	svc.WithLoginGovernance(g)
	err := enforceErr(withProject("proj-1"), t, svc, "alice@acme.com", LoginMethodPassword)
	require.ErrorIs(t, err, ErrSSORequired)
}

// A public-domain (ungoverned) user is unaffected by another tenant's
// SSO-required policy.
func TestEnforceLoginPolicy_SSORequired_PublicDomainUnaffected(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withSSORequired())
	require.NoError(t, enforceErr(withProject("proj-1"), t, svc, "bob@gmail.com", LoginMethodPassword))
}

// End-to-end: PasswordLogin of an sso-required tenant's user is blocked with
// ErrSSORequired before any token is issued.
func TestPasswordLogin_SSORequired_Blocked(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withSSORequired())
	pwHash, _ := passwords.Hash("Str0ng!Passw0rd")
	seedUser(repo, "alice@acme.com", pwHash, "active")

	_, err := svc.PasswordLogin(withProject("proj-1"), "alice@acme.com", "Str0ng!Passw0rd", "", "")
	require.ErrorIs(t, err, ErrSSORequired,
		"password login must be blocked for an sso-required tenant")
}

// ── Require2FA ──────────────────────────────────────────────────────────

// enforceLoginPolicy signals a second-factor requirement for a single-factor
// primary (password/email_otp/oauth) when the tenant mandates 2FA.
func TestEnforceLoginPolicy_Require2FA_PrimaryMethodsNeedSecondFactor(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withRequire2FA())
	ctx := withProject("proj-1")

	for _, method := range []string{LoginMethodPassword, LoginMethodEmailOTP, LoginMethodOAuth} {
		decision, err := svc.enforceLoginPolicy(ctx, "alice@acme.com", method)
		require.NoError(t, err)
		require.True(t, decision.RequireSecondFactor,
			"%s is single-factor and must owe a second factor under Require2FA", method)
	}
}

// A passkey is already a strong factor, so a Require2FA tenant does not owe a
// further step for it.
func TestEnforceLoginPolicy_Require2FA_PasskeySatisfiesOnItsOwn(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withRequire2FA())
	decision, err := svc.enforceLoginPolicy(withProject("proj-1"), "alice@acme.com", LoginMethodPasskey)
	require.NoError(t, err)
	require.False(t, decision.RequireSecondFactor,
		"a passkey assertion satisfies 2FA on its own")
}

// A public-domain user is unaffected by a tenant's Require2FA policy.
func TestEnforceLoginPolicy_Require2FA_PublicDomainUnaffected(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withRequire2FA())
	decision, err := svc.enforceLoginPolicy(withProject("proj-1"), "bob@gmail.com", LoginMethodPassword)
	require.NoError(t, err)
	require.False(t, decision.RequireSecondFactor)
}

// End-to-end: a Require2FA tenant's user whose password is correct and who
// has an enrolled second factor is forced into the 2FA step — no tokens are
// minted, a login challenge is returned instead.
func TestPasswordLogin_Require2FA_ForcesSecondFactorStep(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withRequire2FA())
	pwHash, _ := passwords.Hash("Str0ng!Passw0rd")
	u := seedUser(repo, "alice@acme.com", pwHash, "active")
	seedVerifiedTotp(t, repo, u.ID)

	res, err := svc.PasswordLogin(withProject("proj-1"), "alice@acme.com", "Str0ng!Passw0rd", "", "")
	require.NoError(t, err)
	require.True(t, res.TotpRequired, "policy must force the second-factor step")
	require.NotEmpty(t, res.LoginChallengeID)
	require.Empty(t, res.AccessToken, "no tokens are minted until 2FA completes")
}

// A Require2FA tenant whose user has not enrolled any second factor cannot
// complete the 2FA step — the login is blocked with ErrTotpRequired, steering
// the user to enroll, never silently bypassing the policy.
func TestPasswordLogin_Require2FA_NoFactorEnrolled_Blocks(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withRequire2FA())
	pwHash, _ := passwords.Hash("Str0ng!Passw0rd")
	seedUser(repo, "alice@acme.com", pwHash, "active")

	_, err := svc.PasswordLogin(withProject("proj-1"), "alice@acme.com", "Str0ng!Passw0rd", "", "")
	require.ErrorIs(t, err, ErrTotpRequired,
		"a 2FA-required user with no enrolled factor must be steered to enroll, not let through")
}

// A public-domain user under no governing policy completes a plain password
// login — the 2FA enforcement is purely additive.
func TestPasswordLogin_Require2FA_PublicDomainUnaffected(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(withRequire2FA())
	pwHash, _ := passwords.Hash("Str0ng!Passw0rd")
	seedUser(repo, "bob@gmail.com", pwHash, "active")

	res, err := svc.PasswordLogin(withProject("proj-1"), "bob@gmail.com", "Str0ng!Passw0rd", "", "")
	require.NoError(t, err)
	require.False(t, res.TotpRequired)
	require.NotEmpty(t, res.AccessToken)
}
