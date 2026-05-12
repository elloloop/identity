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
	"github.com/elloloop/identity/pkg/jwt"
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
	cfg.PasswordResetExpirySeconds = 3600

	signingKey, err := jwt.GenerateKey("issue-3-realpostgres-test-kid")
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	keyRing, err := jwt.NewKeyRing([]jwt.SigningKey{signingKey})
	if err != nil {
		t.Fatalf("build key ring: %v", err)
	}

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
		TenantID:            tenantID,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("repo.Build: %v", err)
	}
	if closer, ok := built.Repository.(interface{ Close() }); ok {
		t.Cleanup(closer.Close)
	}

<<<<<<< HEAD
	handler, stop, err := app.New(app.Deps{
=======
	handler, stop := app.New(app.Deps{
>>>>>>> e7e994c (audit: update integration harnesses for app.New return-tuple change)
		Config:         cfg,
		Logger:         zap.NewNop(),
		KeyRing:        keyRing,
		Repo:           built.Repository,
		DB:             built.DB,
		Passkeys:       pkSvc,
		TOTPKey:        []byte("01234567890123456789012345678901"),
		EmailTransport: issue3SilentMailer{},
	})
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}

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
