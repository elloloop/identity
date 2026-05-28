//go:build realentdb

// Real-EntDB end-to-end test for the OrganizationSignup RPC landed
// by #93 slice 2. Drives the full Connect → service → repo → live
// EntDB path:
//
//  1. Boot the identity HTTP handler in mode=multi.
//  2. Call OrganizationSignup over the Connect client.
//  3. Verify the new tenant exists in tenant-shard-db.
//  4. Verify the Organization + User + OrganizationMembership rows
//     are visible inside the new tenant's repo.
//  5. Verify the issued access token round-trips through the
//     AuthMiddleware on a subsequent request.
//
// Skips when GATEWAY_ENTDB_ADDRESS is unset so a developer running
// the suite without compose up does not see a confusing connection
// error.

package integration

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo"
	entdbrepo "github.com/elloloop/identity/internal/repo/entdb"
	"github.com/elloloop/identity/internal/repo/entdb/entclient"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

const orgSignupRealPassword = "Sw0rdfish!42"

func TestOrganizationSignup_RealEntDB(t *testing.T) {
	addr := os.Getenv("GATEWAY_ENTDB_ADDRESS")
	if addr == "" {
		t.Skip("GATEWAY_ENTDB_ADDRESS not set — skipping real-entdb OrganizationSignup test")
	}

	// Each run gets a fresh slug (which IS the new tenant id) so
	// concurrent runs and re-runs against the same compose stack do
	// not collide on tenant uniqueness.
	slug := fmt.Sprintf("org-signup-%d", time.Now().UnixNano())

	client, err := entclient.New(addr)
	if err != nil {
		t.Fatalf("entdb.NewClient: %v", err)
	}
	if err := client.Connect(context.Background()); err != nil {
		t.Fatalf("entdb connect: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// In multi mode the per-deployment DefaultTenantID is only used for
	// the audit log / system bookkeeping; we still need an existing
	// tenant for app.New to wire the audit logger against.
	systemTenant := "system-" + slug
	ensureRealEntDBTenant(t, client, systemTenant)

	built, err := repo.Build(context.Background(), repo.Config{
		Driver:      repo.DriverEntDB,
		EntDBClient: client,
		TenantID:    systemTenant,
	}, nil)
	if err != nil {
		t.Fatalf("repo.Build: %v", err)
	}

	cfg := &config.Config{
		DefaultTenantID:               systemTenant,
		IdentityMode:                  config.IdentityModeMulti,
		TenantResolutionSources:       "jwt",
		AuthAllowLocal:                true,
		PasswordSignupEnabled:         true,
		PasswordResetEnabled:          true,
		JWTExpirySeconds:              900,
		RefreshExpirySeconds:          604800,
		LoginMaxFailedAttempts:        5,
		LoginLockoutSeconds:           900,
		LoginChallengeExpirySeconds:   300,
		PasskeyRPID:                   "localhost",
		PasskeyRPName:                 "IdentityRealEntDBTest",
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

	signer := jwttest.NewSigner(t, "org-signup-real")
	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		t.Fatalf("webauthn: %v", err)
	}

	tenantAdmin, err := repo.NewTenantAdmin(client)
	if err != nil {
		t.Fatalf("repo.NewTenantAdmin: %v", err)
	}
	appBuilt, err := app.New(app.Deps{
		Config:             cfg,
		Logger:             zap.NewNop(),
		Signer:             signer,
		Repo:               built.Repository,
		DB:                 built.DB,
		Passkeys:           pkSvc,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		EmailTransport:     &silentMailer{},
		TenantAdmin:        tenantAdmin,
		RepositoryForTenant: func(tenantID string) service.Repository {
			return entdbrepo.NewRepository(client, tenantID)
		},
	})
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	appBuilt.Start()
	handler := appBuilt.Handler
	t.Cleanup(appBuilt.Stop)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	httpClient := srv.Client()
	connectClient := identityconnectgen.NewIdentityServiceClient(httpClient, srv.URL)

	emailAddr := fmt.Sprintf("owner-%d@acme.example.com", time.Now().UnixNano())

	resp, err := connectClient.OrganizationSignup(context.Background(), connect.NewRequest(&identitypb.OrganizationSignupRequest{
		Slug:          slug,
		DisplayName:   "Acme Corp",
		AdminEmail:    emailAddr,
		AdminPassword: orgSignupRealPassword,
		AdminName:     "Acme Owner",
	}))
	if err != nil {
		t.Fatalf("OrganizationSignup: %v", err)
	}
	if resp.Msg.Organization.GetSlug() != slug {
		t.Fatalf("org slug = %q, want %q", resp.Msg.Organization.GetSlug(), slug)
	}
	if resp.Msg.AdminUser.GetEmail() != emailAddr {
		t.Fatalf("admin email = %q, want %q", resp.Msg.AdminUser.GetEmail(), emailAddr)
	}
	if resp.Msg.AccessToken == "" || resp.Msg.RefreshToken == "" {
		t.Fatalf("expected tokens, got access=%q refresh=%q", resp.Msg.AccessToken, resp.Msg.RefreshToken)
	}

	// Step 3: verify the tenant now exists in tenant-shard-db via the
	// per-tenant Repository — a successful CreateOrganization in that
	// repo proves the tenant id was registered.
	tenantRepo := entdbrepo.NewRepository(client, slug)
	org, err := tenantRepo.GetOrganizationBySlug(context.Background(), slug)
	if err != nil {
		t.Fatalf("GetOrganizationBySlug: %v", err)
	}
	if org == nil {
		t.Fatalf("expected organization %q in new tenant, got nil", slug)
	}
	if org.DisplayName != "Acme Corp" {
		t.Fatalf("org display name = %q, want %q", org.DisplayName, "Acme Corp")
	}

	// Step 4: verify the admin User row exists in the new tenant.
	user, err := tenantRepo.FindUserByEmail(context.Background(), emailAddr)
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if user == nil {
		t.Fatalf("expected admin user in new tenant, got nil")
	}
	if user.Role != "admin" {
		t.Fatalf("admin role = %q, want admin", user.Role)
	}
	if user.PasswordHash == "" {
		t.Fatalf("admin user has no password hash")
	}

	// Step 5: verify OrganizationMembership exists.
	orgs, err := tenantRepo.ListOrganizationsForUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("ListOrganizationsForUser: %v", err)
	}
	if len(orgs) != 1 || orgs[0].Slug != slug {
		t.Fatalf("expected exactly one org membership in %q, got %v", slug, orgs)
	}

	// Step 6: the issued access token must round-trip through
	// AuthMiddleware. Hit /jwks (no auth) first as a smoke test that
	// the server is up, then call a JWT-protected RPC.
	authedHTTP := orgSignupBearerClient{base: httpClient, token: resp.Msg.AccessToken}
	authedClient := identityconnectgen.NewIdentityServiceClient(authedHTTP, srv.URL)

	cur, err := authedClient.GetCurrentUser(context.Background(), connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
	if err != nil {
		// Per-request tenant resolution (jwt source) scopes the call to
		// the admin's tenant, so GetCurrentUser must now find them.
		t.Fatalf("GetCurrentUser after org signup: %v", err)
	}
	if cur.Msg.GetUser().GetEmail() != emailAddr {
		t.Fatalf("GetCurrentUser email = %q, want %q", cur.Msg.GetUser().GetEmail(), emailAddr)
	}
}
