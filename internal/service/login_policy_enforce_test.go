package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/passwords"
)

// ── Fake governance stores ─────────────────────────────────────────────
//
// The login-policy lookup walks domain → tenant → policy, all read-only, so
// the fakes serve fixtures from maps keyed exactly as the real stores are
// addressed: (projectID, lowercased-name) for domains and (projectID, id)
// for tenants/policies. Each store can also be forced to error so the
// fail-safe paths are exercised.

type fakeDomainStore struct {
	byName map[string]*Domain // key: projectID + "|" + domainName
	err    error
}

func (f *fakeDomainStore) GetDomainByName(_ context.Context, projectID, domain string) (*Domain, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byName[projectID+"|"+domain], nil
}

// The remaining DomainStore methods are unused by enforcement; they satisfy
// the interface so the fake is assignable to LoginGovernance.Domains.
func (f *fakeDomainStore) CreateDomain(context.Context, *Domain) (string, error) { return "", nil }

func (f *fakeDomainStore) GetDomain(context.Context, string, string) (*Domain, error) {
	return nil, nil
}

func (f *fakeDomainStore) SetDomainStatus(context.Context, string, string, string, int64) error {
	return nil
}

func (f *fakeDomainStore) ListDomainsByTenant(context.Context, string, string) ([]*Domain, error) {
	return nil, nil
}

type fakeTenantStore struct {
	byID map[string]*Tenant // key: projectID + "|" + tenantID
	err  error
}

func (f *fakeTenantStore) GetTenant(_ context.Context, projectID, tenantID string) (*Tenant, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byID[projectID+"|"+tenantID], nil
}

func (f *fakeTenantStore) CreateTenant(context.Context, *Tenant) (string, error) { return "", nil }
func (f *fakeTenantStore) GetTenantByPrimaryDomain(context.Context, string, string) (*Tenant, error) {
	return nil, nil
}
func (f *fakeTenantStore) SetTenantStatus(context.Context, string, string, string) error { return nil }
func (f *fakeTenantStore) ListTenants(context.Context, string) ([]*Tenant, error)        { return nil, nil }

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
	_ DomainStore      = (*fakeDomainStore)(nil)
	_ TenantStore      = (*fakeTenantStore)(nil)
	_ LoginPolicyStore = (*fakePolicyStore)(nil)
)

// claimedPasswordOnlyGovernance wires a claimed tenant `acme.com` whose
// verified domain points at it and whose policy permits password only.
func claimedPasswordOnlyGovernance() *LoginGovernance {
	const project, tenant, domain = "proj-1", "tenant-acme", "acme.com"
	return &LoginGovernance{
		Domains: &fakeDomainStore{byName: map[string]*Domain{
			project + "|" + domain: {ProjectID: project, TenantID: tenant, Domain: domain, Status: DomainStatusVerified},
		}},
		Tenants: &fakeTenantStore{byID: map[string]*Tenant{
			project + "|" + tenant: {ID: tenant, ProjectID: project, Status: TenantStatusClaimed},
		}},
		Policies: &fakePolicyStore{byTenant: map[string]*LoginPolicy{
			project + "|" + tenant: {ProjectID: project, TenantID: tenant, AllowedMethods: LoginMethodPassword},
		}},
	}
}

// ── enforceLoginPolicy ──────────────────────────────────────────────────

// A claimed tenant with a password-only policy rejects an email_otp login but
// permits a password login. Policy governs HOW, not WHETHER.
func TestEnforceLoginPolicy_PasswordOnlyTenant(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())
	ctx := withProject("proj-1")

	require.NoError(t, svc.enforceLoginPolicy(ctx, "alice@acme.com", LoginMethodPassword),
		"password is on the allow-list and must pass")

	err := svc.enforceLoginPolicy(ctx, "alice@acme.com", LoginMethodEmailOTP)
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

	require.NoError(t, svc.enforceLoginPolicy(ctx, "alice@acme.com", LoginMethodPassword))
	require.NoError(t, svc.enforceLoginPolicy(ctx, "alice@acme.com", LoginMethodEmailOTP))
	require.ErrorIs(t, svc.enforceLoginPolicy(ctx, "alice@acme.com", LoginMethodOAuth), ErrPermissionDenied)
}

// A nil governance bundle (entdb/memory) imposes no restriction.
func TestEnforceLoginPolicy_NilBundle_NoOp(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	// governance left nil.
	require.NoError(t, svc.enforceLoginPolicy(withProject("proj-1"), "alice@acme.com", LoginMethodEmailOTP))
}

// With no resolved project there is nothing to scope the lookup to.
func TestEnforceLoginPolicy_NoProject_NoOp(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())
	// cfg.DefaultProjectID is empty and no scope is set.
	require.NoError(t, svc.enforceLoginPolicy(context.Background(), "alice@acme.com", LoginMethodEmailOTP))
}

// A domain unknown to the project (e.g. a public/consumer domain) is not
// governed, so any method is allowed.
func TestEnforceLoginPolicy_UnknownDomain_NoRestriction(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())
	ctx := withProject("proj-1")
	require.NoError(t, svc.enforceLoginPolicy(ctx, "bob@gmail.com", LoginMethodEmailOTP))
}

// A pending (unverified) domain governs nothing — its tenant has not been
// claimed by proving control of the domain.
func TestEnforceLoginPolicy_UnverifiedDomain_NoRestriction(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	g := claimedPasswordOnlyGovernance()
	g.Domains.(*fakeDomainStore).byName["proj-1|acme.com"].Status = DomainStatusPending
	svc.WithLoginGovernance(g)
	require.NoError(t, svc.enforceLoginPolicy(withProject("proj-1"), "alice@acme.com", LoginMethodEmailOTP))
}

// A latent (unclaimed) tenant governs nothing even when its domain row exists
// and is marked verified — status drives authority, not the row's presence.
func TestEnforceLoginPolicy_LatentTenant_NoRestriction(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	g := claimedPasswordOnlyGovernance()
	g.Tenants.(*fakeTenantStore).byID["proj-1|tenant-acme"].Status = TenantStatusLatent
	svc.WithLoginGovernance(g)
	require.NoError(t, svc.enforceLoginPolicy(withProject("proj-1"), "alice@acme.com", LoginMethodEmailOTP))
}

// A claimed tenant with no policy row imposes no restriction (fail safe).
func TestEnforceLoginPolicy_NoPolicy_NoRestriction(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	g := claimedPasswordOnlyGovernance()
	delete(g.Policies.(*fakePolicyStore).byTenant, "proj-1|tenant-acme")
	svc.WithLoginGovernance(g)
	require.NoError(t, svc.enforceLoginPolicy(withProject("proj-1"), "alice@acme.com", LoginMethodEmailOTP))
}

// A policy with an empty AllowedMethods list imposes no restriction — an
// empty allow-list must never lock a tenant out of its own login.
func TestEnforceLoginPolicy_EmptyAllowedMethods_NoRestriction(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	g := claimedPasswordOnlyGovernance()
	g.Policies.(*fakePolicyStore).byTenant["proj-1|tenant-acme"].AllowedMethods = "   "
	svc.WithLoginGovernance(g)
	require.NoError(t, svc.enforceLoginPolicy(withProject("proj-1"), "alice@acme.com", LoginMethodEmailOTP))
}

// A malformed email with no domain part is not governed.
func TestEnforceLoginPolicy_NoDomainPart_NoRestriction(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())
	require.NoError(t, svc.enforceLoginPolicy(withProject("proj-1"), "alice", LoginMethodEmailOTP))
}

// Every lookup error fails safe: a domain/tenant/policy store outage must
// never become a login lockout.
func TestEnforceLoginPolicy_LookupErrors_FailSafe(t *testing.T) {
	boom := errors.New("boom")

	t.Run("domain lookup error", func(t *testing.T) {
		svc, _, _ := newAuthSvcWithMailer(t)
		g := claimedPasswordOnlyGovernance()
		g.Domains.(*fakeDomainStore).err = boom
		svc.WithLoginGovernance(g)
		require.NoError(t, svc.enforceLoginPolicy(withProject("proj-1"), "alice@acme.com", LoginMethodEmailOTP))
	})

	t.Run("tenant lookup error", func(t *testing.T) {
		svc, _, _ := newAuthSvcWithMailer(t)
		g := claimedPasswordOnlyGovernance()
		g.Tenants.(*fakeTenantStore).err = boom
		svc.WithLoginGovernance(g)
		require.NoError(t, svc.enforceLoginPolicy(withProject("proj-1"), "alice@acme.com", LoginMethodEmailOTP))
	})

	t.Run("policy lookup error", func(t *testing.T) {
		svc, _, _ := newAuthSvcWithMailer(t)
		g := claimedPasswordOnlyGovernance()
		g.Policies.(*fakePolicyStore).err = boom
		svc.WithLoginGovernance(g)
		require.NoError(t, svc.enforceLoginPolicy(withProject("proj-1"), "alice@acme.com", LoginMethodEmailOTP))
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
