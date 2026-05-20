//go:build realpostgres

// Real-Postgres end-to-end test for the OrganizationSignup RPC landed
// by #93 slice 2. Drives the full Connect → service → repo → live
// Postgres path with the postgres-flavoured TenantAdmin
// (repo.NewPostgresTenantAdmin) wired into app.New.
//
// Postgres has no tenant-shard-db-style "global registry" — the
// "tenant" is just a value in the tenant_id column — so the
// PostgresTenantAdmin is intentionally lightweight: CreateTenant
// only enforces in-process uniqueness on the tenant id, and the
// promote/remove calls are no-ops. Slug uniqueness is still enforced
// end-to-end by the organizations.(tenant_id, slug) unique index.
//
// Skips when GATEWAY_POSTGRES_DSN is unset.

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
	pgrepo "github.com/elloloop/identity/internal/repo/postgres"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

// pgSilentMailer drops every outbound mail — the real-postgres signup
// test does not assert on mail delivery.
type pgSilentMailer struct{}

func (pgSilentMailer) Send(_ context.Context, _ email.Message) error { return nil }

var _ email.Transport = (*pgSilentMailer)(nil)

const orgSignupRealPGPassword = "Sw0rdfish!42"

func TestOrganizationSignup_RealPostgres(t *testing.T) {
	dsn := os.Getenv("GATEWAY_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_POSTGRES_DSN not set — skipping real-postgres OrganizationSignup test")
	}

	slug := fmt.Sprintf("org-pg-%d", time.Now().UnixNano())
	systemTenant := "system-" + slug

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	systemPgRepo, err := pgrepo.New(ctx, pgrepo.Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		TenantID:    systemTenant,
	})
	if err != nil {
		t.Fatalf("pgrepo.New(system): %v", err)
	}
	t.Cleanup(systemPgRepo.Close)

	cfg := &config.Config{
		DefaultTenantID:               systemTenant,
		IdentityMode:                  config.IdentityModeMulti,
		AuthAllowLocal:                true,
		PasswordSignupEnabled:         true,
		PasswordResetEnabled:          true,
		JWTExpirySeconds:              900,
		RefreshExpirySeconds:          604800,
		LoginMaxFailedAttempts:        5,
		LoginLockoutSeconds:           900,
		LoginChallengeExpirySeconds:   300,
		PasskeyRPID:                   "localhost",
		PasskeyRPName:                 "IdentityRealPGTest",
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

	signer := jwttest.NewSigner(t, "org-signup-pg")
	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		t.Fatalf("webauthn: %v", err)
	}

	pgTenantAdmin := repo.NewPostgresTenantAdmin()
	// Per-tenant Repository factory: open a fresh postgres repo
	// instance for each tenant; the pool is internal to the repo so
	// each call holds its own connections. We track the close funcs
	// for cleanup.
	var tenantCloses []func()
	repoForTenant := func(tenantID string) service.Repository {
		r, err := pgrepo.New(ctx, pgrepo.Config{
			DSN:         dsn,
			MaxConns:    5,
			ConnTimeout: 5 * time.Second,
			AutoMigrate: false, // first repo already ran them
			TenantID:    tenantID,
		})
		if err != nil {
			t.Fatalf("pgrepo.New(%q): %v", tenantID, err)
		}
		tenantCloses = append(tenantCloses, r.Close)
		return r
	}
	t.Cleanup(func() {
		for _, c := range tenantCloses {
			c()
		}
	})

	built, err := app.New(app.Deps{
		Config:              cfg,
		Logger:              zap.NewNop(),
		Signer:              signer,
		Repo:                systemPgRepo,
		DB:                  systemPgRepo,
		Passkeys:            pkSvc,
		TOTPKey:             []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper:  []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		EmailTransport:      pgSilentMailer{},
		TenantAdmin:         pgTenantAdmin,
		RepositoryForTenant: repoForTenant,
	})
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	built.Start()
	handler := built.Handler
	t.Cleanup(built.Stop)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	httpClient := srv.Client()
	connectClient := identityconnectgen.NewIdentityServiceClient(httpClient, srv.URL)

	emailAddr := fmt.Sprintf("owner+%d@acme.test", time.Now().UnixNano())

	resp, err := connectClient.OrganizationSignup(context.Background(), connect.NewRequest(&identitypb.OrganizationSignupRequest{
		Slug:          slug,
		DisplayName:   "Acme Corp",
		AdminEmail:    emailAddr,
		AdminPassword: orgSignupRealPGPassword,
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

	// Verify rows landed inside the new tenant's scope.
	tenantRepo, err := pgrepo.New(ctx, pgrepo.Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: false,
		TenantID:    slug,
	})
	if err != nil {
		t.Fatalf("verify pgrepo.New: %v", err)
	}
	t.Cleanup(tenantRepo.Close)

	org, err := tenantRepo.GetOrganizationBySlug(context.Background(), slug)
	if err != nil {
		t.Fatalf("GetOrganizationBySlug: %v", err)
	}
	if org == nil || org.Slug != slug {
		t.Fatalf("expected org %q, got %#v", slug, org)
	}

	user, err := tenantRepo.FindUserByEmail(context.Background(), emailAddr)
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if user == nil || user.Role != "admin" {
		t.Fatalf("expected admin user, got %#v", user)
	}
	orgs, err := tenantRepo.ListOrganizationsForUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("ListOrganizationsForUser: %v", err)
	}
	if len(orgs) != 1 || orgs[0].Slug != slug {
		t.Fatalf("expected one org membership in %q, got %v", slug, orgs)
	}

	// Slug collision: a second OrganizationSignup with the same slug
	// must fail with AlreadyExists.
	_, err = connectClient.OrganizationSignup(context.Background(), connect.NewRequest(&identitypb.OrganizationSignupRequest{
		Slug:          slug,
		DisplayName:   "Doppelganger",
		AdminEmail:    "other+" + emailAddr,
		AdminPassword: orgSignupRealPGPassword,
	}))
	if err == nil {
		t.Fatalf("expected slug-collision error, got nil")
	}
	cerr, ok := err.(*connect.Error)
	if !ok || cerr.Code() != connect.CodeAlreadyExists {
		t.Fatalf("expected CodeAlreadyExists, got %T %v", err, err)
	}
}
