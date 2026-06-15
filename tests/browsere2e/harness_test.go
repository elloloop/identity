//go:build browsere2e

// Package browsere2e drives the server-rendered auth UI (internal/app/ui,
// served at /auth/ with window.serverConfig injected) through a real
// headless Chrome via chromedp.
//
// It is gated behind the `browsere2e` build tag so the default
// `go test ./...` unit pass never compiles or runs it. Run locally with:
//
//	go test -tags=browsere2e -timeout=600s ./tests/browsere2e/...
//
// The suite SKIPS cleanly (t.Skip) when no Chrome/Chromium binary is on
// the host, so CI runners without a browser do not fail. It also requires
// Docker: the harness boots the real identityserver against a throwaway
// postgres:16.13-alpine3.23 testcontainer (so the project_id data-plane
// storage path is exercised), seeds the default project, and serves the
// app's HTTP handler via httptest.
package browsere2e

import (
	"context"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Test-fixture constants. The auth UI and the service layer read these from
// config; naming them here keeps the harness free of scattered literals.
const (
	// jwtExpirySeconds stays under config.RevocationModeTTLAccessTokenCap so
	// Config.Validate accepts the default ttl revocation mode.
	jwtExpirySeconds     = 900
	refreshExpirySeconds = 604800

	// totpKey / totpRecoveryPepper are deterministic test secrets sized to the
	// service layer's minimums; they are never exercised by the password UI
	// flows but app.New requires non-empty values.
	totpKey            = "01234567890123456789012345678901"
	totpRecoveryPepper = "test-recovery-pepper!@#$%^&*()_+ABCDEFGH"

	// postgresImage is pinned to match the rest of the repo's container tests.
	postgresImage  = "postgres:16.13-alpine3.23"
	postgresDB     = "identity"
	postgresUser   = "identity"
	postgresPasswd = "identity"
)

// browserHarness bundles the booted server's /auth/ URL the browser
// navigates to. The in-page authenticated fetches are same-origin (relative
// paths), so only the auth URL is needed.
type browserHarness struct {
	authURL string // <server>/auth/
}

// chromePath returns the first Chrome/Chromium binary found on the host, or
// "" when none is available. The candidate list mirrors chromedp's internal
// findExecPath so the skip decision matches what chromedp would actually use.
func chromePath() string {
	var locations []string
	switch runtime.GOOS {
	case "darwin":
		locations = []string{
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		}
	case "windows":
		locations = []string{"chrome", "chrome.exe"}
	default:
		locations = []string{
			"headless_shell", "headless-shell",
			"chromium", "chromium-browser",
			"google-chrome", "google-chrome-stable",
			"/usr/bin/google-chrome", "/usr/local/bin/chrome",
			"/snap/bin/chromium", "chrome",
		}
	}
	for _, loc := range locations {
		if p, err := exec.LookPath(loc); err == nil {
			return p
		}
	}
	return ""
}

// requireChrome skips the test when no browser binary is present, so a CI
// runner without Chrome does not fail the suite.
func requireChrome(t *testing.T) string {
	t.Helper()
	p := chromePath()
	if p == "" {
		t.Skip("no Chrome/Chromium binary found on host — skipping browser e2e")
	}
	return p
}

// startPostgresContainer spins up a throwaway postgres and returns its
// sslmode=disable DSN. Terminated on test cleanup.
func startPostgresContainer(ctx context.Context, t *testing.T) string {
	t.Helper()
	pg, err := tcpg.Run(
		ctx,
		postgresImage,
		tcpg.WithDatabase(postgresDB),
		tcpg.WithUsername(postgresUser),
		tcpg.WithPassword(postgresPasswd),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { //nolint:contextcheck // cleanup must not reuse the test ctx.
		_ = pg.Terminate(context.Background())
	})
	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	return dsn
}

// newUIConfig returns a Config tuned for the browser UI tests. signupEnabled
// drives both the service-layer signup gate and the injected
// window.serverConfig.passwordSignupEnabled the page reads.
func newUIConfig(signupEnabled bool, projectID string) *config.Config {
	return &config.Config{
		DefaultTenantID:        projectID,
		DefaultProjectID:       projectID,
		AuthAllowLocal:         true,
		PasswordSignupEnabled:  signupEnabled,
		PasswordResetEnabled:   true,
		JWTExpirySeconds:       jwtExpirySeconds,
		RefreshExpirySeconds:   refreshExpirySeconds,
		LoginMaxFailedAttempts: 5,
		LoginLockoutSeconds:    900,
		PasskeyRPID:            "localhost",
		PasskeyRPName:          "IdentityBrowserE2E",
		PasskeyOrigin:          "http://localhost",
		AppBaseURL:             "https://app.test",
		// app.New rejects an empty allowed-origins list. The browser drives the
		// page same-origin (the httptest URL), so cross-origin CORS is never
		// exercised; any non-empty value satisfies the validator.
		AllowedOrigins:          "http://localhost",
		EmailTokenExpirySeconds: 3600,
		SMTPFrom:                "no-reply@test.local",
		// Rate limits left at zero: NewFixedWindowLimiter treats limit<=0 as
		// "disabled", so repeated form submissions in a single test are not
		// throttled by the per-IP middleware.
	}
}

// startServer boots the real identity HTTP handler against a fresh postgres
// testcontainer with the default project seeded, serves it via httptest, and
// returns the /auth/ URL the browser drives. signupEnabled toggles the
// PasswordSignup feature so the unhappy "signup disabled" case can assert the
// UI hides the signup affordance.
func startServer(t *testing.T, signupEnabled bool) *browserHarness {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dsn := startPostgresContainer(ctx, t)

	// One unique project id per run keeps concurrent runs isolated and, per
	// ADR-0002, is the data-plane storage shard. DefaultTenantID and
	// DefaultProjectID must be the same provisioned value or postgres
	// reject the empty/unprovisioned partition.
	projectID := "browsere2e"
	cfg := newUIConfig(signupEnabled, projectID)

	built, err := repo.Build(ctx, repo.Config{
		Driver:              repo.DriverPostgres,
		PostgresDSN:         dsn,
		PostgresMaxConns:    5,
		PostgresAutoMigrate: true,
		ProjectID:           cfg.DefaultProjectID,
	}, zap.NewNop())
	require.NoError(t, err)
	if closer, ok := built.Repository.(interface{ Close() }); ok {
		t.Cleanup(closer.Close)
	}

	// Seed the projects(id) row the project_id FK chain needs before any
	// data-plane write (signup) can land.
	_, err = built.ProjectStore.EnsureDefaultProject(
		ctx, cfg.DefaultProjectID, cfg.DefaultTenantID, "browsere2e",
	)
	require.NoError(t, err)

	signer := jwttest.NewSigner(t, "browsere2e-kid")

	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	require.NoError(t, err)

	appBuilt, err := app.New(app.Deps{
		Config:             cfg,
		Logger:             zap.NewNop(),
		Signer:             signer,
		Repo:               built.Repository,
		DB:                 built.DB,
		Passkeys:           pkSvc,
		TOTPKey:            []byte(totpKey),
		TOTPRecoveryPepper: []byte(totpRecoveryPepper),
		ProjectResolver:    built.ProjectResolver(),
	})
	require.NoError(t, err)
	appBuilt.Start()
	t.Cleanup(appBuilt.Stop)

	srv := httptest.NewServer(appBuilt.Handler)
	t.Cleanup(srv.Close)

	return &browserHarness{
		authURL: srv.URL + "/auth/",
	}
}
