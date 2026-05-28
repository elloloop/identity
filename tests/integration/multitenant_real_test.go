//go:build realentdb || realpostgres

// End-to-end multi-tenant request-path test for #93 slice 3 (per-request
// tenant resolution). Runs against whichever real backend the build tag
// selects (entdb or postgres):
//
//  1. Boot the identity HTTP handler in mode=multi with host-based
//     tenant resolution.
//  2. OrganizationSignup creates tenant A and tenant B.
//  3. A user of A acting via A's host succeeds.
//  4. The same user's token, replayed via B's host, is rejected
//     (PermissionDenied) — cross-tenant token reuse is blocked.
//  5. Data written under A is invisible under B's scope (isolation).
//
// Skips when the backend's address/DSN env var is unset.

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

const multiTenantTestPassword = "Sw0rdfish!42-mt"

// hostBearerClient injects both a bearer token and a Host header so the
// host-based tenant resolver sees the request as arriving on a specific
// tenant subdomain. httptest serves on 127.0.0.1, so we override Host on
// the outgoing request rather than changing the dial target.
type hostBearerClient struct {
	base  *http.Client
	token string
	host  string
}

func (c hostBearerClient) Do(req *http.Request) (*http.Response, error) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.host != "" {
		req.Host = c.host
	}
	return c.base.Do(req)
}

// orgSignupBearerClient is a minimal bearer-injecting HTTP client used by
// the per-backend OrganizationSignup tests. Shared here so both the
// realentdb and realpostgres org-signup tests can reuse it.
type orgSignupBearerClient struct {
	base  *http.Client
	token string
}

func (b orgSignupBearerClient) Do(req *http.Request) (*http.Response, error) {
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.Do(req)
}

func TestMultiTenant_CrossTenantIsolation_RealBackend(t *testing.T) {
	be := newMultiTenantBackend(t)
	if be == nil {
		return // skipped inside newMultiTenantBackend
	}

	const baseDomain = "tenants.test"
	cfg := newMultiTenantConfig(be.defaultTenant, baseDomain)

	signer := jwttest.NewSigner(t, "multitenant-real")
	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		t.Fatalf("webauthn: %v", err)
	}

	built, err := app.New(app.Deps{
		Config:              cfg,
		Logger:              zap.NewNop(),
		Signer:              signer,
		Repo:                be.systemRepo,
		DB:                  be.systemDB,
		Passkeys:            pkSvc,
		TOTPKey:             []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper:  []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		EmailTransport:      be.mailer,
		TenantAdmin:         be.tenantAdmin,
		RepositoryForTenant: be.repoForTenant,
	})
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	built.Start()
	t.Cleanup(built.Stop)

	srv := httptest.NewServer(built.Handler)
	t.Cleanup(srv.Close)
	httpClient := srv.Client()
	connectClient := identityconnectgen.NewIdentityServiceClient(httpClient, srv.URL)

	stamp := time.Now().UnixNano()
	slugA := fmt.Sprintf("mt-a-%d", stamp)
	slugB := fmt.Sprintf("mt-b-%d", stamp)
	emailA := fmt.Sprintf("alice-%d@a.example.com", stamp)
	emailB := fmt.Sprintf("bob-%d@b.example.com", stamp)

	// Step 2: create tenant A and tenant B.
	respA, err := connectClient.OrganizationSignup(context.Background(), connect.NewRequest(&identitypb.OrganizationSignupRequest{
		Slug: slugA, DisplayName: "Tenant A", AdminEmail: emailA, AdminPassword: multiTenantTestPassword, AdminName: "Alice",
	}))
	if err != nil {
		t.Fatalf("OrganizationSignup A: %v", err)
	}
	respB, err := connectClient.OrganizationSignup(context.Background(), connect.NewRequest(&identitypb.OrganizationSignupRequest{
		Slug: slugB, DisplayName: "Tenant B", AdminEmail: emailB, AdminPassword: multiTenantTestPassword, AdminName: "Bob",
	}))
	if err != nil {
		t.Fatalf("OrganizationSignup B: %v", err)
	}

	hostA := slugA + "." + baseDomain
	hostB := slugB + "." + baseDomain

	// Step 3: Alice acting on her own tenant (host A + token A) succeeds.
	aliceOnA := identityconnectgen.NewIdentityServiceClient(
		hostBearerClient{base: httpClient, token: respA.Msg.AccessToken, host: hostA}, srv.URL)
	cur, err := aliceOnA.GetCurrentUser(context.Background(), connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
	if err != nil {
		t.Fatalf("Alice GetCurrentUser on tenant A: %v", err)
	}
	if cur.Msg.GetUser().GetEmail() != emailA {
		t.Fatalf("Alice on A: email = %q, want %q", cur.Msg.GetUser().GetEmail(), emailA)
	}

	// Step 4: Alice's token replayed on tenant B's host is rejected. The
	// host (B) and the token's tenant claim (A) disagree — cross-tenant
	// token reuse — so the resolver rejects with PermissionDenied before
	// the handler runs.
	aliceOnB := identityconnectgen.NewIdentityServiceClient(
		hostBearerClient{base: httpClient, token: respA.Msg.AccessToken, host: hostB}, srv.URL)
	_, err = aliceOnB.GetCurrentUser(context.Background(), connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
	if err == nil {
		t.Fatalf("Alice's token on tenant B's host must be rejected, got success")
	}
	if cerr, ok := err.(*connect.Error); !ok || cerr.Code() != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied for cross-tenant reuse, got %T %v", err, err)
	}

	// Step 5: data isolation. Alice's user row exists in A's scope but
	// not in B's scope — proven directly through the per-tenant repos.
	repoA := be.repoForTenant(slugA)
	repoB := be.repoForTenant(slugB)

	userInA, err := repoA.FindUserByEmail(context.Background(), emailA)
	if err != nil {
		t.Fatalf("FindUserByEmail A: %v", err)
	}
	if userInA == nil {
		t.Fatalf("Alice must exist in tenant A's scope")
	}
	userAInB, err := repoB.FindUserByEmail(context.Background(), emailA)
	if err != nil {
		t.Fatalf("FindUserByEmail B: %v", err)
	}
	if userAInB != nil {
		t.Fatalf("Alice (tenant A) must be invisible in tenant B's scope, got %#v", userAInB)
	}

	// And the membership view is tenant-scoped: Alice belongs to an org
	// in A's scope, to nothing in B's scope.
	orgsAInA, err := repoA.ListOrganizationsForUser(context.Background(), userInA.ID)
	if err != nil {
		t.Fatalf("ListOrganizationsForUser A: %v", err)
	}
	if len(orgsAInA) != 1 || orgsAInA[0].Slug != slugA {
		t.Fatalf("Alice in A: expected one org %q, got %v", slugA, orgsAInA)
	}
	orgsAInB, err := repoB.ListOrganizationsForUser(context.Background(), userInA.ID)
	if err != nil {
		t.Fatalf("ListOrganizationsForUser B: %v", err)
	}
	if len(orgsAInB) != 0 {
		t.Fatalf("Alice must have no org membership in tenant B's scope, got %v", orgsAInB)
	}

	_ = respB // tenant B's tokens aren't otherwise exercised here.
}

// TestMultiTenant_TenantScopedInvitation_RealBackend is the slice-4
// real-backend integration test for #93. It proves invitations honour
// the resolved tenant end to end:
//
//  1. Boot the identity handler in mode=multi with host-based resolution.
//  2. OrganizationSignup creates tenant A and tenant B.
//  3. A's admin (acting on A's host) invites bob@x into A.
//  4. Bob redeems the invitation on A's host and becomes a member of A.
//  5. Bob is visible as a member under A's scope, invisible under B's.
//  6. The A-issued invitation token, replayed on B's host, is rejected
//     (Unauthenticated) — the token lives only in A's data plane.
func TestMultiTenant_TenantScopedInvitation_RealBackend(t *testing.T) {
	be := newMultiTenantBackend(t)
	if be == nil {
		return // skipped inside newMultiTenantBackend
	}

	const baseDomain = "tenants.test"
	cfg := newMultiTenantConfig(be.defaultTenant, baseDomain)

	signer := jwttest.NewSigner(t, "multitenant-invite-real")
	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		t.Fatalf("webauthn: %v", err)
	}

	built, err := app.New(app.Deps{
		Config:              cfg,
		Logger:              zap.NewNop(),
		Signer:              signer,
		Repo:                be.systemRepo,
		DB:                  be.systemDB,
		Passkeys:            pkSvc,
		TOTPKey:             []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper:  []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		EmailTransport:      be.mailer,
		TenantAdmin:         be.tenantAdmin,
		RepositoryForTenant: be.repoForTenant,
	})
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	built.Start()
	t.Cleanup(built.Stop)

	srv := httptest.NewServer(built.Handler)
	t.Cleanup(srv.Close)
	httpClient := srv.Client()
	connectClient := identityconnectgen.NewIdentityServiceClient(httpClient, srv.URL)

	stamp := time.Now().UnixNano()
	slugA := fmt.Sprintf("inv-a-%d", stamp)
	slugB := fmt.Sprintf("inv-b-%d", stamp)
	adminAEmail := fmt.Sprintf("admin-a-%d@a.example.com", stamp)
	adminBEmail := fmt.Sprintf("admin-b-%d@b.example.com", stamp)
	bobEmail := fmt.Sprintf("bob-%d@x.example.com", stamp)

	// Step 2: create tenant A and tenant B, each with its own admin.
	respA, err := connectClient.OrganizationSignup(context.Background(), connect.NewRequest(&identitypb.OrganizationSignupRequest{
		Slug: slugA, DisplayName: "Invite Tenant A", AdminEmail: adminAEmail, AdminPassword: multiTenantTestPassword, AdminName: "Admin A",
	}))
	if err != nil {
		t.Fatalf("OrganizationSignup A: %v", err)
	}
	if _, err := connectClient.OrganizationSignup(context.Background(), connect.NewRequest(&identitypb.OrganizationSignupRequest{
		Slug: slugB, DisplayName: "Invite Tenant B", AdminEmail: adminBEmail, AdminPassword: multiTenantTestPassword, AdminName: "Admin B",
	})); err != nil {
		t.Fatalf("OrganizationSignup B: %v", err)
	}

	hostA := slugA + "." + baseDomain
	hostB := slugB + "." + baseDomain

	// Step 3: A's admin invites bob, acting on A's host with A's token.
	adminAClient := identityconnectgen.NewIdentityServiceClient(
		hostBearerClient{base: httpClient, token: respA.Msg.AccessToken, host: hostA}, srv.URL)
	invite, err := adminAClient.InviteUser(context.Background(), connect.NewRequest(&identitypb.InviteUserRequest{
		Email: bobEmail,
		Name:  "Bob",
		Role:  "member",
	}))
	if err != nil {
		t.Fatalf("InviteUser on tenant A: %v", err)
	}
	if invite.Msg.GetInvitationToken() == "" {
		t.Fatalf("InviteUser returned empty invitation token")
	}

	// Step 4: bob redeems the invitation on A's host (unauthenticated —
	// no token, only the host scopes the request to tenant A).
	bobOnA := identityconnectgen.NewIdentityServiceClient(
		hostBearerClient{base: httpClient, host: hostA}, srv.URL)
	accepted, err := bobOnA.AcceptInvitation(context.Background(), connect.NewRequest(&identitypb.AcceptInvitationRequest{
		InvitationToken: invite.Msg.InvitationToken,
		Password:        multiTenantTestPassword,
		Name:            "Bob Redeemed",
	}))
	if err != nil {
		t.Fatalf("AcceptInvitation on tenant A: %v", err)
	}
	if accepted.Msg.GetUser().GetEmail() != bobEmail {
		t.Fatalf("accepted user email = %q, want %q", accepted.Msg.GetUser().GetEmail(), bobEmail)
	}

	// Step 5: bob is a member of A (visible under A's scope, absent under
	// B's). Membership is the identity-layer OrganizationMembership added
	// by redemption — proven directly through the per-tenant repos.
	repoA := be.repoForTenant(slugA)
	repoB := be.repoForTenant(slugB)

	bobInA, err := repoA.FindUserByEmail(context.Background(), bobEmail)
	if err != nil {
		t.Fatalf("FindUserByEmail A: %v", err)
	}
	if bobInA == nil {
		t.Fatalf("bob must exist in tenant A's scope")
	}
	orgsBobInA, err := repoA.ListOrganizationsForUser(context.Background(), bobInA.ID)
	if err != nil {
		t.Fatalf("ListOrganizationsForUser A: %v", err)
	}
	if len(orgsBobInA) != 1 || orgsBobInA[0].Slug != slugA {
		t.Fatalf("bob in A: expected one org %q, got %v", slugA, orgsBobInA)
	}
	bobInB, err := repoB.FindUserByEmail(context.Background(), bobEmail)
	if err != nil {
		t.Fatalf("FindUserByEmail B: %v", err)
	}
	if bobInB != nil {
		t.Fatalf("bob (tenant A) must be invisible in tenant B's scope, got %#v", bobInB)
	}

	// Step 6: the A-issued invitation token replayed on B's host is
	// rejected. The invitation row exists only in A's data plane, so B's
	// scoped repo never finds it — Unauthenticated, identical to any bad
	// token.
	bobOnB := identityconnectgen.NewIdentityServiceClient(
		hostBearerClient{base: httpClient, host: hostB}, srv.URL)
	_, err = bobOnB.AcceptInvitation(context.Background(), connect.NewRequest(&identitypb.AcceptInvitationRequest{
		InvitationToken: invite.Msg.InvitationToken,
		Password:        multiTenantTestPassword,
		Name:            "Bob Replay",
	}))
	if err == nil {
		t.Fatalf("A-issued invitation replayed on tenant B's host must be rejected, got success")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("expected Unauthenticated for cross-tenant invitation replay, got %v (err=%v)", got, err)
	}
}

// newMultiTenantConfig returns a mode=multi config wired for host-based
// resolution against baseDomain.
func newMultiTenantConfig(defaultTenant, baseDomain string) *config.Config {
	return &config.Config{
		DefaultTenantID:               defaultTenant,
		IdentityMode:                  config.IdentityModeMulti,
		TenantResolutionSources:       "host,jwt",
		TenantHostBaseDomain:          baseDomain,
		AuthAllowLocal:                true,
		PasswordSignupEnabled:         true,
		PasswordResetEnabled:          true,
		JWTExpirySeconds:              900,
		RefreshExpirySeconds:          604800,
		LoginMaxFailedAttempts:        5,
		LoginLockoutSeconds:           900,
		LoginChallengeExpirySeconds:   300,
		PasskeyRPID:                   "localhost",
		PasskeyRPName:                 "IdentityMultiTenantTest",
		PasskeyOrigin:                 "http://localhost:9002",
		PasskeyChallengeExpirySeconds: 300,
		QRLoginBaseURL:                "http://localhost:9002",
		QRLoginExpirySeconds:          300,
		TOTPIssuer:                    "Glassa Test",
		AllowedOrigins:                "http://localhost:9002",
		AppBaseURL:                    "https://app.test",
		EmailTokenExpirySeconds:       3600,
		SMTPFrom:                      "no-reply@test.local",
	}
}

// multiTenantBackend bundles the backend-specific wiring the cross-tenant
// test needs. Built per backend via build-tagged newMultiTenantBackend.
type multiTenantBackend struct {
	defaultTenant string
	systemRepo    service.Repository
	systemDB      service.DB
	tenantAdmin   service.TenantAdmin
	repoForTenant service.RepositoryForTenant
	mailer        email.Transport
}
