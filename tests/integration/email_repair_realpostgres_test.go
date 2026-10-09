//go:build realpostgres

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/repo"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

// oneProject lists only this test's project, so the repair never walks the
// projects other tests own on a shared database.
type oneProject string

func (p oneProject) ListProjectIDs(context.Context) ([]string, error) {
	return []string{string(p)}, nil
}

// TestRepairStoredEmails_RealPostgres runs the stored-email repair through the
// app against Postgres: the folded-email unique index, row-level security and
// the merge transaction are the real ones.
func TestRepairStoredEmails_RealPostgres(t *testing.T) {
	dsn := os.Getenv("GATEWAY_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	projectID := fmt.Sprintf("email-repair-%d", time.Now().UnixNano())
	cfg := newIssue3TestConfig()
	cfg.DefaultTenantID = projectID
	cfg.DefaultProjectID = projectID

	built, err := repo.Build(ctx, repo.Config{
		Driver: repo.DriverPostgres, PostgresDSN: dsn, PostgresMaxConns: 5, PostgresAutoMigrate: true, ProjectID: projectID,
	}, zap.NewNop())
	require.NoError(t, err)
	if closer, ok := built.Repository.(interface{ Close() }); ok {
		t.Cleanup(closer.Close)
	}
	_, err = built.ProjectStore.EnsureDefaultProject(ctx, projectID, projectID, "email-repair")
	require.NoError(t, err)
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: cfg.PasskeyRPID, RPName: cfg.PasskeyRPName, Origin: cfg.PasskeyOrigin})
	require.NoError(t, err)
	appBuilt, err := app.New(app.Deps{
		Config: cfg, Logger: zap.NewNop(), Signer: jwttest.NewSigner(t, "email-repair-kid"),
		Repo: built.Repository, DB: built.DB, Passkeys: pk,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		EmailTransport:     issue3SilentMailer{}, Projects: oneProject(projectID),
	})
	require.NoError(t, err)

	r := built.Repository
	create := func(email string) string {
		id, err := r.CreateUser(ctx, &service.User{Email: email, Name: "Person", Status: service.StatusActive, EmailVerified: true})
		require.NoError(t, err)
		return id
	}
	legacy := create("first.last@gmail.com")
	require.NoError(t, r.CreateOAuthIdentity(ctx, &service.OAuthIdentity{UserID: legacy, Provider: "google", ProviderUserID: "g-" + projectID, CreatedAt: 1}))
	duplicate := create("firstlast@gmail.com")
	alone := create("a.lone+news@googlemail.com")

	dry, err := appBuilt.RepairStoredEmails(ctx, false)
	require.NoError(t, err)
	require.Equal(t, 1, dry.Count(service.EmailRepairMerge))
	require.Equal(t, 1, dry.Count(service.EmailRepairRewrite))
	got, err := r.GetUser(ctx, legacy)
	require.NoError(t, err)
	require.Equal(t, "first.last@gmail.com", got.Email, "a dry run writes nothing")

	applied, err := appBuilt.RepairStoredEmails(ctx, true)
	require.NoError(t, err)
	require.Zero(t, applied.Failed(), "%+v", applied.Items)

	survivor, err := r.FindUserByEmail(ctx, "firstlast@gmail.com")
	require.NoError(t, err)
	require.Equal(t, legacy, survivor.ID)
	retired, err := r.GetUser(ctx, duplicate)
	require.NoError(t, err)
	require.Equal(t, legacy, retired.MergedIntoUserID)
	require.Empty(t, retired.Email)
	rewritten, err := r.GetUser(ctx, alone)
	require.NoError(t, err)
	require.Equal(t, "alone@gmail.com", rewritten.Email)

	again, err := appBuilt.RepairStoredEmails(ctx, true)
	require.NoError(t, err)
	require.Empty(t, again.Items)
}
