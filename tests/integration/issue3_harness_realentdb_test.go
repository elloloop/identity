//go:build realentdb

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
	"github.com/elloloop/identity/internal/repo/entdb/entclient"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

func StartIssue3Server(t *testing.T) *issue3Harness {
	t.Helper()

	addr := os.Getenv("GATEWAY_ENTDB_ADDRESS")
	if addr == "" {
		t.Skip("GATEWAY_ENTDB_ADDRESS not set")
	}

	tenantID := fmt.Sprintf("issue3-realentdb-%d", time.Now().UnixNano())
	cfg := newIssue3TestConfig()
	cfg.DefaultTenantID = tenantID
	cfg.PasswordResetExpirySeconds = 3600

	signer := jwttest.NewSigner(t, "issue-3-realentdb-test-kid")

	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		t.Fatalf("init webauthn: %v", err)
	}

	client, err := entclient.New(addr)
	if err != nil {
		t.Fatalf("entdb.NewClient: %v", err)
	}
	if err := client.Connect(context.Background()); err != nil {
		t.Fatalf("entdb connect: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ensureRealEntDBTenant(t, client, tenantID)

	built, err := repo.Build(context.Background(), repo.Config{
		Driver:      repo.DriverEntDB,
		EntDBClient: client,
		TenantID:    tenantID,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("repo.Build: %v", err)
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
