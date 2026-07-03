//go:build integration && realpostgres

// This file boots the WHOLE identity service — governance wiring included
// (project resolution, default-project + auth-domain seeding, tenant
// auto-formation, the DomainService and LoginGovernance) — against a REAL
// Postgres, and drives the redesign RPCs over HTTP via a Connect client.
//
// It deliberately does NOT reuse the lower-level startHarness path
// (harness_realpostgres_test.go), which wires the bare app.Deps and never
// constructs the governance plane. Instead it builds through
// identityserver.New, the same composition root cmd/identity uses, so the
// full governance chain is exercised end-to-end.
//
// The redesign governance features are postgres-only, so the suite is gated
// behind `integration && realpostgres` and skips when GATEWAY_POSTGRES_DSN
// is unset (it runs in CI's realpostgres job, skips locally without a DB).

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap/zaptest"

	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/identityserver"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/repo"
	"github.com/elloloop/identity/internal/service"
)

// brandedAuthDomainSuffix is appended to the per-run unique token to form
// each harness's branded serving hostname, seeded via
// GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS. The hostname must be unique per
// harness instance because project_auth_domains.hostname is globally unique:
// a fixed name would collide with a prior run's default project when the
// whole TestRedesign_ControlPlaneAdmin* set runs in one process against a
// shared control-plane Postgres. A request whose Host is this name resolves
// to the harness's default project (flow 2).
const brandedAuthDomainSuffix = ".auth.acme.test"

// harnessAdminSecret is the shared control-plane admin secret the harness
// configures (GATEWAY_ADMIN_API_SECRET), so the admin RPCs are ENABLED for
// the operator-provisioning e2e. Only that e2e presents it; every other
// redesign test ignores the admin surface entirely.
const harnessAdminSecret = "it-operator-admin-secret"

// fakeDNSResolver is the injected TXT-lookup boundary for VerifyDomain. Its
// record set is mutable so a test can publish the exact challenge it got
// from CreateDomain, then point the resolver at the wrong/no value to drive
// the failure path — all without touching real DNS.
type fakeDNSResolver struct {
	mu      sync.Mutex
	records map[string][]string
}

func newFakeDNSResolver() *fakeDNSResolver {
	return &fakeDNSResolver{records: map[string][]string{}}
}

func (f *fakeDNSResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records[strings.ToLower(host)], nil
}

// publish sets the TXT records returned for host, replacing any prior set.
func (f *fakeDNSResolver) publish(host string, values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[strings.ToLower(host)] = values
}

var _ service.DNSResolver = (*fakeDNSResolver)(nil)

// governanceStores bundles the per-project governance stores the test
// reads/seeds directly. They come from a SECOND repo.Build handle against
// the same Postgres database (its own pool) — the serving instance owns its
// own stores; the test never reaches into them. This is the only way to
// seed/assert governance state the redesign RPCs don't expose.
type governanceStores struct {
	tenants     service.TenantStore
	domains     service.DomainStore
	memberships service.MembershipStore
	invitations service.InvitationStore
	policies    service.LoginPolicyStore
	// projects is the control-plane resolver, so the admin e2e can assert a
	// newly-registered auth-domain host resolves to the freshly-created
	// project — the same resolution the project middleware performs.
	projects service.ProjectResolver
	// controlPlane is the project write-store, so a test can seed a project's
	// config_json (e.g. per-project OAuth providers) directly — the RPCs do not
	// expose config authoring.
	controlPlane service.ControlPlaneProjectStore
}

// RedesignHarness is a full-stack, postgres-backed identity service plus the
// handles a redesign-governance test needs.
type RedesignHarness struct {
	BaseURL string
	HTTP    *http.Client
	// Client issues RPCs with the httptest server's default Host (which
	// resolves to the default project via the zero-config pin).
	Client identityconnectgen.IdentityServiceClient

	ProjectID string
	TenantID  string
	// BrandedAuthDomain is this harness's per-run unique branded serving
	// hostname (seeded into the default project). Tests that exercise
	// Host→auth-domain resolution must use this, not a shared constant, so
	// the globally-unique hostname index doesn't collide across runs.
	BrandedAuthDomain string

	DNS    *fakeDNSResolver
	Mailer *RecordingMailer
	Stores governanceStores
}

// startRedesignHarness boots identityserver.New against the GATEWAY_POSTGRES_DSN
// Postgres with the full governance wiring, serves Handler() on an httptest
// server, and returns the handles the redesign tests drive.
func startRedesignHarness(t *testing.T) *RedesignHarness {
	t.Helper()

	dsn := os.Getenv("GATEWAY_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_POSTGRES_DSN not set")
	}

	logger := zaptest.NewLogger(t)
	// Post-inversion (ADR-0002) the Project is the data-plane shard, so a
	// unique project (and its storage scope) per test run keeps users/sessions
	// isolated even though every run shares one control-plane database.
	uniq := fmt.Sprintf("it-redesign-%d", time.Now().UnixNano())
	tenantID := uniq
	projectID := uniq
	brandedAuthDomain := uniq + brandedAuthDomainSuffix

	cfg := newRedesignTestConfig(dsn, projectID, tenantID, brandedAuthDomain)

	dns := newFakeDNSResolver()
	mailer := NewRecordingMailer()

	srv, err := identityserver.New(context.Background(), identityserver.Options{
		Config:          cfg,
		Logger:          logger,
		MetricsRegistry: prometheus.NewRegistry(), // isolated: avoid cross-harness collisions
		EmailTransport:  mailer,
		DNSResolver:     dns,
	})
	if err != nil {
		t.Fatalf("identityserver.New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Second handle to the same Postgres for seeding/asserting governance
	// state the RPCs don't surface. AutoMigrate=false: the serving instance
	// already migrated.
	built, err := repo.Build(context.Background(), repo.Config{
		Driver:              repo.DriverPostgres,
		PostgresDSN:         dsn,
		PostgresMaxConns:    5,
		PostgresAutoMigrate: false,
		ProjectID:           projectID,
	}, logger)
	if err != nil {
		t.Fatalf("repo.Build (governance handle): %v", err)
	}
	if closer, ok := built.Repository.(interface{ Close() }); ok {
		t.Cleanup(closer.Close)
	}

	return &RedesignHarness{
		BaseURL:           httpSrv.URL,
		HTTP:              httpSrv.Client(),
		Client:            identityconnectgen.NewIdentityServiceClient(httpSrv.Client(), httpSrv.URL),
		ProjectID:         projectID,
		TenantID:          tenantID,
		BrandedAuthDomain: brandedAuthDomain,
		DNS:               dns,
		Mailer:            mailer,
		Stores: governanceStores{
			tenants:      built.TenantStoreIface(),
			domains:      built.DomainStoreIface(),
			memberships:  built.MembershipStoreIface(),
			invitations:  built.InvitationStoreIface(),
			policies:     built.LoginPolicyStore,
			projects:     built.ProjectResolver(),
			controlPlane: built.ControlPlaneStore(),
		},
	}
}

// newRedesignTestConfig returns a Config that drives the full governance
// plane: the postgres driver with auto-migrate, a seeded default project and
// a branded auth domain, local-password auth, and both password and
// passwordless signup on. Borrows the non-governance defaults from
// newTestConfig so the two harnesses agree on expiries/limits.
func newRedesignTestConfig(dsn, projectID, tenantID, brandedAuthDomain string) config.Config {
	base := newTestConfig()
	base.RepoDriver = string(repo.DriverPostgres)
	base.PostgresDSN = dsn
	base.PostgresMaxConns = 5
	base.PostgresAutoMigrate = true
	base.DefaultProjectID = projectID
	base.DefaultTenantID = tenantID
	base.DefaultProjectAuthDomains = brandedAuthDomain
	base.AdminAPISecret = harnessAdminSecret
	base.AuthAllowLocal = true
	base.PasswordSignupEnabled = true
	base.PasswordlessSignupEnabled = true
	return *base
}

// AuthedClient returns a Connect client that carries a bearer token on every
// request (default Host → default project).
func (h *RedesignHarness) AuthedClient(accessToken string) identityconnectgen.IdentityServiceClient {
	return identityconnectgen.NewIdentityServiceClient(
		&redesignHTTPClient{base: h.HTTP, token: accessToken},
		h.BaseURL,
	)
}

// ClientWithHost returns a Connect client whose every request carries Host
// (and optional headers), so branded-domain resolution and an explicit
// X-Project-Key can be exercised over the wire.
func (h *RedesignHarness) ClientWithHost(host string, headers map[string]string) identityconnectgen.IdentityServiceClient {
	return identityconnectgen.NewIdentityServiceClient(
		&redesignHTTPClient{base: h.HTTP, host: host, headers: headers},
		h.BaseURL,
	)
}

// redesignHTTPClient is a connect.HTTPClient that rewrites the request Host
// and injects a bearer token / arbitrary headers. Rewriting req.Host (not
// just the Host header) is what makes the project resolver's Host→auth-domain
// match fire against the branded name rather than 127.0.0.1.
type redesignHTTPClient struct {
	base    *http.Client
	token   string
	host    string
	headers map[string]string
}

func (c *redesignHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.host != "" {
		req.Host = c.host
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	return c.base.Do(req)
}

// ── shared assertion / decode helpers ───────────────────────────────────

// validPassword satisfies the strength policy (upper, lower, digit, special,
// >= 8 chars) so password signup/login succeed.
const validPassword = "Sup3r$ecret!"

// decodeTokenProjectClaim returns the `project` claim from a JWT access
// token WITHOUT verifying the signature — the test only asserts which
// project the server stamped on the token, not the token's validity.
func decodeTokenProjectClaim(t *testing.T, accessToken string) string {
	t.Helper()
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWT: %q", accessToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	var claims struct {
		Project string `json:"project"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal token claims: %v", err)
	}
	return claims.Project
}

// projectKeyHeader is the credential header the project resolver reads.
const projectKeyHeader = middleware.ProjectKeyHeader
