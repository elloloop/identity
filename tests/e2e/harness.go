//go:build e2e

// Package e2e drives the identity service over its public HTTP/JSON
// Connect-RPC wire format — what a downstream JS or Python client sees.
// Tests boot the same handler chain cmd/identity/main.go serves (via
// internal/app + a real repo backend) on an in-process httptest server,
// then exercise it with a plain *http.Client + encoding/json. There is
// no import of the Connect-Go client codegen, deliberately — that's
// what distinguishes these tests from tests/integration: the surface
// here is HTTP-only, exactly what a third-party client speaks.
//
// The backend is selected by the GATEWAY_E2E_BACKEND env var:
//
//   - "postgres" (default) boots a throwaway postgres:16.13-alpine3.23
//     testcontainer, auto-migrates it, and seeds the default project. This
//     is the authoritative CI gate: the postgres driver implements the
//     graph-DB read path (service.DB QueryNodes/GetNode) so admin/group/
//     session/help/audit listing tests RUN here.
//   - "memory" boots the in-process memory driver — no Docker, fast smoke
//     signal. The graph-DB-only tests self-skip on it (see requireGraphDB).
//
// Each test owns its own httptest server (the identity handler is
// cheap to construct) and uses a per-test tenant id, so cases never
// collide.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/elloloop/identity/pkg/passwords"
)

// backendEnv selects the repo backend the harness boots. Postgres is the
// authoritative gate (implements the graph-DB read path); memory is the fast
// no-Docker smoke. Unset defaults to postgres.
const (
	backendEnv      = "GATEWAY_E2E_BACKEND"
	backendPostgres = "postgres"
	backendMemory   = "memory"
	backendSQLite   = "sqlite"
)

// e2eBackend resolves the configured backend, defaulting to postgres.
func e2eBackend() string {
	if b := os.Getenv(backendEnv); b != "" {
		return b
	}
	return backendPostgres
}

// sharedPostgresDSN is the sslmode=disable DSN of the single postgres
// testcontainer booted once per package run by TestMain. The suite has 55+
// top-level tests, most running t.Parallel(); a container-per-test would spin
// up dozens of postgres instances at once and exhaust the runner (manifesting
// as flaky container startup). Instead one container is shared and each test
// gets an isolated project partition (unique DefaultProjectID via WithProject),
// which is how the postgres driver scopes data-plane storage.
var sharedPostgresDSN string

// Harness is the bag of resources returned by StartServer. Tests do
// `POST <BaseURL>/identity.v1.IdentityService/<Method>` with a JSON body
// and inspect the JSON response — exactly what a downstream client
// over the wire would do.
type Harness struct {
	BaseURL  string
	HTTP     *http.Client
	TenantID string
	Server   *httptest.Server
	Mailer   *RecordingMailer
	Repo     service.Repository
	DB       service.DB
}

// RecordingMailer captures every outbound email so tests can inspect
// tokens/codes that the service would normally only deliver through
// SMTP. Safe for concurrent Send under -race: identity sends emails
// from goroutines spawned by audit logging and the sweeper.
type RecordingMailer struct {
	mu       sync.Mutex
	Messages []email.Message
}

// Send records the message and reports success.
func (m *RecordingMailer) Send(_ context.Context, msg email.Message) error {
	m.mu.Lock()
	m.Messages = append(m.Messages, msg)
	m.mu.Unlock()
	return nil
}

// Latest returns the most recently delivered email, or nil if none.
func (m *RecordingMailer) Latest() *email.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Messages) == 0 {
		return nil
	}
	msg := m.Messages[len(m.Messages)-1]
	return &msg
}

// FindContaining returns the most recent email whose Text or HTML body
// contains needle.
func (m *RecordingMailer) FindContaining(needle string) *email.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.Messages) - 1; i >= 0; i-- {
		if strings.Contains(m.Messages[i].Text, needle) || strings.Contains(m.Messages[i].HTML, needle) {
			msg := m.Messages[i]
			return &msg
		}
	}
	return nil
}

// buildBackend builds the repo for the configured backend. For postgres it
// boots a testcontainer, auto-migrates, and seeds the projects(id) FK row the
// data-plane writes require. For memory it builds the in-process driver. The
// returned *repo.Built has a project-scopeable Repository in both cases.
func buildBackend(t *testing.T, cfg *config.Config) *repo.Built {
	t.Helper()

	switch backend := e2eBackend(); backend {
	case backendMemory:
		built, err := repo.Build(context.Background(), repo.Config{
			Driver: repo.DriverMemory,
		}, zap.NewNop())
		if err != nil {
			t.Fatalf("repo.Build memory: %v", err)
		}
		return built

	case backendSQLite:
		// Pure-Go SQLite (no Docker). A per-test on-disk file in t.TempDir keeps
		// each test isolated; the driver migrates and seeds the projects(id) FK
		// row on Build. Like memory, the entdb-graph read paths self-skip — the
		// postgres gate is authoritative for those.
		built, err := repo.Build(context.Background(), repo.Config{
			Driver:     repo.DriverSQLite,
			SQLitePath: t.TempDir() + "/identity.db",
			ProjectID:  cfg.DefaultProjectID,
		}, zap.NewNop())
		if err != nil {
			t.Fatalf("repo.Build sqlite: %v", err)
		}
		if closer, ok := built.Repository.(interface{ Close() }); ok {
			t.Cleanup(closer.Close)
		}
		return built

	case backendPostgres:
		if sharedPostgresDSN == "" {
			t.Fatalf("shared postgres DSN unset — TestMain did not boot a container")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		// TestMain already migrated the shared schema; per-test builders just
		// connect to it (no AutoMigrate, so parallel tests never race the DDL).
		built, err := repo.Build(ctx, repo.Config{
			Driver:              repo.DriverPostgres,
			PostgresDSN:         sharedPostgresDSN,
			PostgresMaxConns:    5,
			PostgresAutoMigrate: false,
			ProjectID:           cfg.DefaultProjectID,
		}, zap.NewNop())
		if err != nil {
			t.Fatalf("repo.Build postgres: %v", err)
		}
		if closer, ok := built.Repository.(interface{ Close() }); ok {
			t.Cleanup(closer.Close)
		}
		// Each test owns an isolated project partition; seed its projects(id)
		// row so the project_id FK chain accepts data-plane writes.
		if _, err := built.ProjectStore.EnsureDefaultProject(
			ctx, cfg.DefaultProjectID, cfg.DefaultTenantID, "e2e",
		); err != nil {
			t.Fatalf("EnsureDefaultProject: %v", err)
		}
		return built

	default:
		t.Fatalf("unknown %s=%q (want %q, %q, or %q)", backendEnv, backend, backendPostgres, backendMemory, backendSQLite)
		return nil
	}
}

// StartServer boots identity on the configured repo backend (GATEWAY_E2E_BACKEND:
// "postgres" default, "memory" smoke) with defaults sufficient for black-box
// HTTP testing. The server is torn down via t.Cleanup so a test never leaks
// resources between cases.
func StartServer(t *testing.T) *Harness {
	t.Helper()

	tenantID := fmt.Sprintf("e2e-%d", time.Now().UnixNano())

	cfg := &config.Config{
		DefaultTenantID: tenantID,
		// The data-plane binds to the project (ADR-0002). Both backends accept
		// this id; we point the default project at the same id as the tenant so
		// the service layer reads/writes a single consistent store (postgres
		// seeds the projects(id) FK row below; memory tolerates any id).
		DefaultProjectID:              tenantID,
		AuthAllowLocal:                true,
		PasswordSignupEnabled:         true,
		PasswordResetEnabled:          true,
		JWTExpirySeconds:              900,
		RefreshExpirySeconds:          604800,
		LoginMaxFailedAttempts:        5,
		LoginLockoutSeconds:           900,
		LoginChallengeExpirySeconds:   300,
		PasskeyRPID:                   "localhost",
		PasskeyRPName:                 "Identity E2E",
		PasskeyOrigin:                 "http://localhost",
		PasskeyChallengeExpirySeconds: 300,
		QRLoginBaseURL:                "http://localhost",
		QRLoginExpirySeconds:          300,
		TOTPIssuer:                    "Identity E2E",
		AllowedOrigins:                "http://localhost",
		AppBaseURL:                    "http://localhost",
		EmailTokenExpirySeconds:       3600,
		SMTPFrom:                      "no-reply@e2e.local",
		PasswordlessSignupEnabled:     true,
		PasswordlessCodeTTLSeconds:    300,
		PasswordlessCodeMaxAttempts:   5,
		EmailSendCooldownSeconds:      0,
		RateLimitPasswordlessPerIP:    10000,
		OAuthAllowedReturnURLs:        "http://localhost",
	}

	builtRepo := buildBackend(t, cfg)

	// The project-resolution middleware binds every request to
	// cfg.DefaultProjectID (no resolver → default-project pin), so the
	// service layer reads/writes the tenantID partition. Bind the harness's
	// direct-access Repo/DB to that SAME partition so SeedUser and other test
	// helpers land where the RPC handlers look — otherwise they'd write the
	// boot-default ("") sibling and requests would never see the seeded rows.
	scopedRepo, ok := builtRepo.Repository.(interface {
		WithProject(string) service.Repository
	})
	if !ok {
		t.Fatalf("repo does not implement WithProject")
	}
	harnessRepo := scopedRepo.WithProject(tenantID)
	harnessDB, ok := harnessRepo.(service.DB)
	if !ok {
		t.Fatalf("scoped repo does not implement service.DB")
	}

	mailer := &RecordingMailer{}
	signer := jwttest.NewSigner(t, "e2e-kid")

	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		t.Fatalf("webauthn: %v", err)
	}

	built, err := app.New(app.Deps{
		Config:             cfg,
		Logger:             zap.NewNop(),
		Signer:             signer,
		Repo:               builtRepo.Repository,
		DB:                 builtRepo.DB,
		ProjectResolver:    builtRepo.ProjectResolver(),
		Passkeys:           pkSvc,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		EmailTransport:     mailer,
	})
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	built.Start()
	t.Cleanup(built.Stop)

	srv := httptest.NewServer(built.Handler)
	t.Cleanup(srv.Close)

	return &Harness{
		BaseURL:  srv.URL,
		HTTP:     srv.Client(),
		TenantID: tenantID,
		Server:   srv,
		Mailer:   mailer,
		Repo:     harnessRepo,
		DB:       harnessDB,
	}
}

// requireGraphDB guards a test that exercises a service path implemented via
// the graph-DB read path (service.DB: QueryNodes / GetNode by node type): admin
// user CRUD/invite, group CRUD/membership, help-request listing, audit-log
// querying, and session listing/sign-out-everywhere.
//
// The postgres backend (the authoritative gate) implements those, so these
// tests RUN there. The in-memory backend deliberately returns
// ErrServiceUnavailable for graph operations (internal/repo/memory/repo.go), so
// on the memory smoke they self-skip with a clear reason. The Repository-backed
// flows (password, passwordless OTP + magic-link, TOTP/2FA, QR-login, email
// verify/reset/change, refresh/revoke) need no graph DB and run on both.
func requireGraphDB(t *testing.T) {
	t.Helper()
	// Only the postgres driver implements the service.DB node/edge graph read
	// path; the memory and sqlite drivers stub it (they are the single-project
	// embedded/smoke tiers). Cases that exercise the graph run on the postgres
	// gate and self-skip on the other backends.
	if e2eBackend() != backendPostgres {
		t.Skip("graph-DB node queries (service.DB) are unimplemented on this backend; this case runs on the postgres gate")
	}
}

// rpcCall posts an RPC request and decodes the JSON response. If the
// HTTP status is non-200 the JSON body is still returned so the test
// can match on Connect-RPC error envelopes (which carry code/message).
func (h *Harness) rpcCall(t *testing.T, method string, req any, accessToken string) (map[string]any, int) {
	t.Helper()

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal %s: %v", method, err)
	}

	url := h.BaseURL + "/identity.v1.IdentityService/" + method
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request %s: %v", method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if accessToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := h.HTTP.Do(httpReq)
	if err != nil {
		t.Fatalf("rpc %s: %v", method, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s body: %v", method, err)
	}
	if len(raw) == 0 {
		return nil, resp.StatusCode
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal %s response (status=%d, body=%q): %v", method, resp.StatusCode, string(raw), err)
	}
	return out, resp.StatusCode
}

// Signup is a convenience helper. Returns access+refresh tokens and the user id.
func (h *Harness) Signup(t *testing.T, addr, password string) (accessToken, refreshToken, userID string) {
	t.Helper()
	resp, status := h.rpcCall(t, "PasswordSignup", map[string]any{
		"email":    addr,
		"password": password,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("Signup status=%d body=%v", status, resp)
	}
	at, _ := resp["accessToken"].(string)
	rt, _ := resp["refreshToken"].(string)
	user, _ := resp["user"].(map[string]any)
	uid, _ := user["id"].(string)
	if at == "" || rt == "" || uid == "" {
		t.Fatalf("Signup missing fields: %v", resp)
	}
	return at, rt, uid
}

// Login posts PasswordLogin and returns the token pair on success.
func (h *Harness) Login(t *testing.T, addr, password string) (accessToken, refreshToken string) {
	t.Helper()
	resp, status := h.rpcCall(t, "PasswordLogin", map[string]any{
		"email":    addr,
		"password": password,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("Login status=%d body=%v", status, resp)
	}
	at, _ := resp["accessToken"].(string)
	rt, _ := resp["refreshToken"].(string)
	return at, rt
}

// HealthCheck hits the /health endpoint and returns the HTTP status.
func (h *Harness) HealthCheck(t *testing.T, path string) int {
	t.Helper()
	resp, err := h.HTTP.Get(h.BaseURL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// SeedUser adds a user directly to the store for testing.
func (h *Harness) SeedUser(t *testing.T, email, name, role, status, plainPassword string) string {
	t.Helper()

	email = strings.ToLower(email)
	passwordHash := ""
	if plainPassword != "" {
		var err error
		passwordHash, err = passwords.Hash(plainPassword)
		if err != nil {
			t.Fatalf("hash password for %s: %v", email, err)
		}
	}

	now := time.Now()
	id, err := h.Repo.CreateUser(context.Background(), &service.User{
		Email:        email,
		Name:         name,
		Role:         role,
		Status:       status,
		PasswordHash: passwordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("SeedUser(%s): %v", email, err)
	}
	return id
}
