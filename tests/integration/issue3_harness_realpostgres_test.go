//go:build realpostgres

package integration

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	identityconnectgen "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/repo"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

func StartIssue3Server(t *testing.T) *issue3Harness {
	t.Helper()

	dsn := os.Getenv("GATEWAY_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_POSTGRES_DSN not set")
	}

	tenantID := fmt.Sprintf("issue3-realpostgres-%d", time.Now().UnixNano())
	cfg := newIssue3TestConfig()
	cfg.DefaultTenantID = tenantID
	// The data-plane binds to the project (ADR-0002); use a unique project id
	// per run so concurrent runs on the shared CI database stay isolated.
	cfg.DefaultProjectID = tenantID
	cfg.PasswordResetExpirySeconds = 3600

	signer := jwttest.NewSigner(t, "issue-3-realpostgres-test-kid")

	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		t.Fatalf("init webauthn: %v", err)
	}

	built, err := repo.Build(context.Background(), repo.Config{
		Driver:              repo.DriverPostgres,
		PostgresDSN:         dsn,
		PostgresMaxConns:    5,
		PostgresAutoMigrate: true,
		ProjectID:           cfg.DefaultProjectID,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("repo.Build: %v", err)
	}
	if closer, ok := built.Repository.(interface{ Close() }); ok {
		t.Cleanup(closer.Close)
	}
	// Seed the projects(id) row the project_id FK (migration 0015) needs.
	if _, err := built.ProjectStore.EnsureDefaultProject(
		context.Background(), cfg.DefaultProjectID, cfg.DefaultTenantID, "issue3",
	); err != nil {
		t.Fatalf("seed default project: %v", err)
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
		EmailTransport:     issue3SilentMailer{},
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
	clientRPC := identityconnectgen.NewIdentityServiceClient(httpClient, srv.URL)

	return &issue3Harness{
		BaseURL: srv.URL,
		Client:  clientRPC,
		HTTP:    httpClient,
		Repo:    built.Repository,
	}
}
