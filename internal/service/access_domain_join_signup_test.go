package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/pkg/audit"
)

const (
	domainJoinJSON = `{"access":{"mode":"invite","admit_domain_join":true}}`
	admitTenantID  = "tenant-acme"
	admitDomainID  = "dom-acme"
	admitAddress   = "new@acme.com"
	admittedByJoin = string(audit.EventSignupAdmittedByDomainJoin)
)

// domainJoinStores hold an operator-made tenant of project-a, claimed, that
// has verified acme.com and lets its people join.
func domainJoinStores() (*fakeDomainStore, *fakeTenantStore) {
	domains, tenants := newFakeDomainStore(), newFakeTenantStore()
	tenants.put(&Tenant{ID: admitTenantID, ProjectID: "project-a", Name: "Acme", Status: TenantStatusClaimed})
	domains.byID[domains.key("project-a", admitDomainID)] = &Domain{
		ID: admitDomainID, ProjectID: "project-a", TenantID: admitTenantID, Domain: "acme.com",
		Status: DomainStatusVerified, AllowJoin: true,
	}
	return domains, tenants
}

// domainJoinScope is project-a with configJSON's access and accounts blocks,
// parsed as the control-plane resolver parses them.
func domainJoinScope(t *testing.T, configJSON string) context.Context {
	t.Helper()
	cfg, err := ParseProjectConfig(configJSON)
	require.NoError(t, err)
	return WithProjectScope(context.Background(), &ProjectScope{ProjectID: "project-a", Access: cfg.Access, Accounts: cfg.Accounts})
}

// An address on a domain an operator-made tenant verified and opened to
// joining gets its account at a proven sign-in, joins no tenant and forms
// none, and the admission is logged and audited once the account exists.
func TestDomainJoinSignup_AdmitsAProvenAddressThatJoinsNothing(t *testing.T) {
	repo := newFakeRepo()
	domains, tenants := domainJoinStores()
	af := &fakeAutoFormer{}
	w := newRecordingAuditWriter()
	core, logs := observer.New(zapcore.InfoLevel)
	svc := newTestAuthService(t, repo).WithDomainJoin(domains, tenants).WithTenantAutoFormer(af)
	svc.audit = audit.NewLogger(w, "test-tenant", nil)
	svc.logger = zap.New(core)

	require.NoError(t, invitedOAuthSignIn(domainJoinScope(t, domainJoinJSON), svc, admitAddress))

	u, _ := repo.FindUserByEmail(context.Background(), admitAddress)
	require.NotNil(t, u, "the address gets its account")
	assert.True(t, u.EmailVerified)
	assert.Empty(t, af.calls, "no tenant is formed and no domain membership made: it joins with JoinTenantByDomain")
	assert.Equal(t, 1, w.countByEventTypeActorTarget(admittedByJoin, "", u.ID))
	assert.Equal(t, []map[string]any{{
		"project_id": "project-a", "tenant_id": admitTenantID, "domain_id": admitDomainID, "email_domain": "acme.com",
	}}, w.detailsOf(admittedByJoin))
	assert.Equal(t, [][2]string{{"203.0.113.9", "invited-test"}}, w.clientsOf(admittedByJoin))
	assert.Zero(t, w.countByEventType(string(audit.EventSignupAdmittedByInvitation)))
	admitted := logs.FilterMessage("signup_admitted_by_domain_join").All()
	require.Len(t, admitted, 1)
	assert.Equal(t, u.ID, admitted[0].ContextMap()["user_id"])
	assert.Equal(t, admitTenantID, admitted[0].ContextMap()["tenant_id"])
	assert.Equal(t, "acme.com", admitted[0].ContextMap()["email_domain"])
	assert.Zero(t, logs.FilterMessage("project_access_denied").Len(), "an admission is not first logged as a refusal")
}

// Every address the rule does not admit is refused as an uninvited sign-up
// is, gets no account and no emailed code, and nothing is recorded.
func TestDomainJoinSignup_RefusesWhatTheRuleDoesNotAdmit(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configJSON string
		address    string
		unwired    bool
		change     func(d *fakeDomainStore, tn *fakeTenantStore)
	}{
		{name: "opt-in off", configJSON: `{"access":{"mode":"invite"}}`},
		{name: "joining off on the domain", change: func(d *fakeDomainStore, _ *fakeTenantStore) {
			d.byID[d.key("project-a", admitDomainID)].AllowJoin = false
		}},
		{name: "domain not verified", change: func(d *fakeDomainStore, _ *fakeTenantStore) {
			d.byID[d.key("project-a", admitDomainID)].Status = DomainStatusPending
		}},
		{name: "public mail domain", address: "new@gmail.com", change: func(d *fakeDomainStore, _ *fakeTenantStore) {
			d.byID[d.key("project-a", admitDomainID)].Domain = "gmail.com"
		}},
		{name: "another domain", address: "new@example.com"},
		{name: "self-service tenant", change: func(_ *fakeDomainStore, tn *fakeTenantStore) {
			tn.byID["project-a/"+admitTenantID].CreatedBy = "user-maker"
		}},
		{name: "latent tenant", change: func(_ *fakeDomainStore, tn *fakeTenantStore) {
			tn.byID["project-a/"+admitTenantID].Status = TenantStatusLatent
		}},
		{name: "suspended tenant", change: func(_ *fakeDomainStore, tn *fakeTenantStore) {
			tn.byID["project-a/"+admitTenantID].Status = TenantStatusSuspended
		}},
		{name: "deny layer", configJSON: `{"access":{"mode":"invite","admit_domain_join":true,"blocked_domains":["acme.com"]}}`},
		{name: "email_signup admin", configJSON: `{"access":{"mode":"invite","admit_domain_join":true},"accounts":{"email_signup":"admin"}}`},
		{name: "email_signup off", configJSON: `{"access":{"mode":"invite","admit_domain_join":true},"accounts":{"email_signup":"off"}}`},
		{name: "lookup failure", change: func(d *fakeDomainStore, _ *fakeTenantStore) {
			d.verifiedErr = errors.New("database unavailable")
		}},
		{name: "stores not wired", unwired: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configJSON, address := tc.configJSON, tc.address
			if configJSON == "" {
				configJSON = domainJoinJSON
			}
			if address == "" {
				address = admitAddress
			}
			domains, tenants := domainJoinStores()
			if tc.change != nil {
				tc.change(domains, tenants)
			}
			wire := func(svc *AuthService) *AuthService {
				if tc.unwired {
					return svc
				}
				return svc.WithDomainJoin(domains, tenants)
			}
			ctx := domainJoinScope(t, configJSON)

			repo := newFakeRepo()
			af := &fakeAutoFormer{}
			w := newRecordingAuditWriter()
			oauth := wire(newTestAuthService(t, repo)).WithTenantAutoFormer(af)
			oauth.audit = audit.NewLogger(w, "test-tenant", nil)
			require.ErrorIs(t, invitedOAuthSignIn(ctx, oauth, address), ErrSignupByInvitationOnly)
			u, _ := repo.FindUserByEmail(context.Background(), address)
			assert.Nil(t, u)
			assert.Empty(t, af.calls)
			assert.Zero(t, w.countByEventType(admittedByJoin))

			codes, codeRepo, rec := newAuthSvcWithMailer(t)
			wire(codes)
			require.NoError(t, codes.RequestEmailLoginCode(ctx, address))
			assert.Empty(t, rec.Sent(), "no code goes where redeeming it would be refused")
			seedEmailLoginCode(t, codeRepo, address, "123456")
			_, err := codes.VerifyEmailLoginCode(ctx, address, "123456", "1.2.3.4", "a")
			require.ErrorIs(t, err, ErrSignupByInvitationOnly)
		})
	}
}

// Requesting a code asks what redeeming it asks: an admitted address gets
// its code and redeeming it creates the account, while passwordless sign-up
// is on; with it off no code goes to an address with no account.
func TestDomainJoinSignup_EmailCodeSentAndRedeemedOnlyWhereItCreatesTheAccount(t *testing.T) {
	ctx := domainJoinScope(t, domainJoinJSON)

	svc, repo, rec := newAuthSvcWithMailer(t)
	af := &fakeAutoFormer{}
	svc.WithDomainJoin(domainJoinStores()).WithTenantAutoFormer(af)
	require.NoError(t, svc.RequestEmailLoginCode(ctx, admitAddress))
	require.Len(t, rec.Sent(), 1, "an admitted address gets its sign-in code")
	res, err := svc.VerifyEmailLoginCode(ctx, admitAddress, extractCodeFromEmail(t, rec.Sent()[0].Text), "1.2.3.4", "a")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	u, _ := repo.FindUserByEmail(context.Background(), admitAddress)
	require.NotNil(t, u)
	assert.True(t, u.EmailVerified)
	assert.Empty(t, af.calls)

	off, _, offRec := newAuthSvcWithMailer(t)
	off.cfg.PasswordlessSignupEnabled = false
	off.WithDomainJoin(domainJoinStores())
	require.NoError(t, off.RequestEmailLoginCode(ctx, admitAddress))
	assert.Empty(t, offRec.Sent(), "redemption would refuse an unknown address, so no code goes")
}

// A password proves nothing about the mailbox, so it creates no account
// however joinable its domain.
func TestDomainJoinSignup_PasswordSignupIsNotAdmitted(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	svc.WithDomainJoin(domainJoinStores())

	_, err := svc.PasswordSignup(domainJoinScope(t, domainJoinJSON), admitAddress, accessTestPassword, "N", "", nil, "", EmailLinkParams{})
	require.ErrorIs(t, err, ErrSignupByInvitationOnly)
	u, _ := repo.FindUserByEmail(context.Background(), admitAddress)
	assert.Nil(t, u)
}

// An account that exists signs in as before, on the domain or off it, and
// nothing records an admission for it.
func TestDomainJoinSignup_ExistingAccountIsUnaffected(t *testing.T) {
	repo := newFakeRepo()
	w := newRecordingAuditWriter()
	af := &fakeAutoFormer{}
	svc := newTestAuthService(t, repo).WithDomainJoin(domainJoinStores()).WithTenantAutoFormer(af)
	svc.audit = audit.NewLogger(w, "test-tenant", nil)
	seedUser(repo, "member@acme.com", "", "active")
	seedUser(repo, "member@example.com", "", "active")
	ctx := domainJoinScope(t, domainJoinJSON)

	require.NoError(t, invitedOAuthSignIn(ctx, svc, "member@acme.com"))
	require.NoError(t, invitedOAuthSignIn(ctx, svc, "member@example.com"))
	assert.Zero(t, w.countByEventType(admittedByJoin))
	assert.Empty(t, af.calls)
}

// An open invitation is the admission an address has when both would admit
// it, so it is recorded as invited and accepts the invitation to join.
func TestDomainJoinSignup_AnInvitationAdmitsFirst(t *testing.T) {
	repo := newFakeRepo()
	w := newRecordingAuditWriter()
	svc := newTestAuthService(t, repo).WithDomainJoin(domainJoinStores()).WithOpenInvitations(invitationsWith(pending(admitAddress)))
	svc.audit = audit.NewLogger(w, "test-tenant", nil)

	require.NoError(t, invitedOAuthSignIn(domainJoinScope(t, `{"access":{"mode":"invite","admit_domain_join":true,"admit_tenant_invitations":true}}`), svc, admitAddress))
	assert.Equal(t, 1, w.countByEventType(string(audit.EventSignupAdmittedByInvitation)))
	assert.Zero(t, w.countByEventType(admittedByJoin))
}

func TestParseProjectConfig_AdmitDomainJoinNeedsInviteMode(t *testing.T) {
	for _, mode := range []string{AccessModeOpen, AccessModeClosed, ""} {
		_, err := ParseProjectConfig(`{"access":{"mode":"` + mode + `","admit_domain_join":true}}`)
		require.Error(t, err, mode)
	}
	_, err := ParseProjectConfig(`{"access":{"mode":"allowlist","allowed_domains":["example.com"],"admit_domain_join":true}}`)
	require.Error(t, err)
	cfg, err := ParseProjectConfig(domainJoinJSON)
	require.NoError(t, err)
	assert.True(t, cfg.Access.AdmitDomainJoin)
	off, err := ParseProjectConfig(`{"access":{"mode":"invite"}}`)
	require.NoError(t, err)
	assert.False(t, off.Access.AdmitDomainJoin, "off by default")
}
