//go:build integration

// Package integration contains end-to-end tests that exercise the
// real identity service binary's HTTP/Connect handler chain. The
// harness builds the same wiring used by cmd/identity/main.go via
// internal/app, but lets each build-tagged StartServer choose the
// backing store so the same test suite can run against memory,
// and Postgres.
package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/graph"

	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/idv"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/passkeys"
)

// Harness is the bag of resources returned by StartServer. Tests use
// the Connect client to make RPC calls, BaseURL to hit health/JWKS
// endpoints, and Signer if they need to inspect signed tokens.
type Harness struct {
	BaseURL  string
	Client   identityconnectgen.IdentityServiceClient
	HTTP     *http.Client
	Signer   *jwttest.Signer
	TenantID string
	Repo     service.Repository
	DB       service.DB
	Audit    *RecordingDB
	Mailer   *RecordingMailer
	Server   *httptest.Server
}

// RecordingMailer captures every email.Send call so tests can assert
// on the messages the service would have dispatched. It satisfies
// email.Transport.
type RecordingMailer struct {
	mu   sync.Mutex
	sent []email.Message
}

// NewRecordingMailer returns an empty recorder.
func NewRecordingMailer() *RecordingMailer { return &RecordingMailer{} }

// Send captures the message and returns nil.
func (m *RecordingMailer) Send(_ context.Context, msg email.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

// Sent returns a copy of every captured message in delivery order.
func (m *RecordingMailer) Sent() []email.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]email.Message, len(m.sent))
	copy(out, m.sent)
	return out
}

// Reset clears the captured set. Useful between phases of a test.
func (m *RecordingMailer) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = nil
}

var _ email.Transport = (*RecordingMailer)(nil)

const (
	testTypeUser             = 1
	testTypeRefreshToken     = 5
	testTypePasswordReset    = 19
	testTypePasskeyCred      = 20
	testTypePasskeyChallenge = 21
	testTypeQrLoginSession   = 22
	testTypeAuditEvent       = 26

	testUserEmailField           = "1"
	testRefreshUserIDField       = "2"
	testPasswordResetUserIDField = "2"
	testPasskeySignCountField    = "4"
	testPasskeyChallengeField    = "1"
	testQrExpiresAtField         = "8"
	testQrUpdatedAtField         = "10"
	testAuditEventTypeField      = "1"
)

// HarnessOption configures StartServer.
type HarnessOption func(*harnessOptions)

type harnessOptions struct {
	oauthRegistry  *oauth.Registry
	nativeVerifier *oauth.NativeVerifier
	nativeProjects service.NativeOAuthProjectStore
	config         func(*config.Config)
	idvProvider    idv.Provider
}

func applyHarnessOptions(cfg *config.Config, opts []HarnessOption) harnessOptions {
	hOpts := harnessOptions{}
	for _, o := range opts {
		o(&hOpts)
	}
	if hOpts.config != nil {
		hOpts.config(cfg)
	}
	return hOpts
}

// WithOAuthRegistry overrides the OAuth registry used by the harness.
// Pass nil to leave OAuth disabled (the default).
func WithOAuthRegistry(r *oauth.Registry) HarnessOption {
	return func(o *harnessOptions) { o.oauthRegistry = r }
}

// WithConfig mutates the test config before the service graph is built.
func WithConfig(fn func(*config.Config)) HarnessOption {
	return func(o *harnessOptions) { o.config = fn }
}

// WithNativeOAuth injects a native ID-token verifier (typically pointed at a
// mock JWKS) and the optional product-lookup store used by NativeOAuthLogin.
func WithNativeOAuth(v *oauth.NativeVerifier, projects service.NativeOAuthProjectStore) HarnessOption {
	return func(o *harnessOptions) {
		o.nativeVerifier = v
		o.nativeProjects = projects
	}
}

// WithIDVProvider sets the identity-verification provider on the harness.
// Pass nil to leave IDV disabled (the default — RPCs return Unimplemented).
func WithIDVProvider(p idv.Provider) HarnessOption {
	return func(o *harnessOptions) { o.idvProvider = p }
}

func startHarness(
	t *testing.T,
	cfg *config.Config,
	repo service.Repository,
	db service.DB,
	auditDB *RecordingDB,
	mailer *RecordingMailer,
	hOpts harnessOptions,
) *Harness {
	t.Helper()

	signer := jwttest.NewSigner(t, "test-kid")

	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		t.Fatalf("init webauthn: %v", err)
	}

	built, err := app.New(app.Deps{
		Config:              cfg,
		Logger:              zap.NewNop(),
		Signer:              signer,
		Repo:                repo,
		DB:                  db,
		Passkeys:            pkSvc,
		TOTPKey:             []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper:  []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		EmailTransport:      mailer,
		OAuthRegistry:       hOpts.oauthRegistry,
		NativeOAuthVerifier: hOpts.nativeVerifier,
		NativeOAuthProjects: hOpts.nativeProjects,
		IDVProvider:         hOpts.idvProvider,
		// Send synchronously so the recording mailer is readable immediately
		// after a request (the served deployment dispatches async).
		SynchronousEmailSend: true,
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
	client := identityconnectgen.NewIdentityServiceClient(httpClient, srv.URL)

	return &Harness{
		BaseURL:  srv.URL,
		Client:   client,
		HTTP:     httpClient,
		Signer:   signer,
		TenantID: cfg.DefaultTenantID,
		Repo:     repo,
		DB:       db,
		Audit:    auditDB,
		Mailer:   mailer,
		Server:   srv,
	}
}

// AuthedClient returns a Connect client whose every request carries
// "Authorization: Bearer <accessToken>". Used to exercise endpoints
// like GetCurrentUser that require an authenticated caller.
func (h *Harness) AuthedClient(accessToken string) identityconnectgen.IdentityServiceClient {
	return identityconnectgen.NewIdentityServiceClient(
		bearerHTTPClient{base: h.HTTP, token: accessToken},
		h.BaseURL,
	)
}

func (h *Harness) FindUserIDByEmail(t *testing.T, email string) string {
	t.Helper()

	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for {
		user, err := h.Repo.FindUserByEmail(ctx, email)
		if err == nil && user != nil {
			return user.ID
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("FindUserByEmail(%q): %v", email, err)
			}
			t.Fatalf("FindUserByEmail(%q): user not found", email)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *Harness) WaitForUser(t *testing.T, email string, predicate func(*service.User) bool) *service.User {
	t.Helper()

	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for {
		user, err := h.Repo.FindUserByEmail(ctx, email)
		if err == nil && user != nil && predicate(user) {
			return user
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("FindUserByEmail(%q): %v", email, err)
			}
			t.Fatalf("user %q did not reach expected state", email)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// testInspector is the optional test-support surface a Repository driver may
// expose so the integration harness can count/update rows without the EntDB
// node/edge graph. The MemRepo has its own fast-path (below); SQL drivers that
// do not implement the EntDB graph (sqlite) satisfy this interface so the same
// suite runs on them. Drivers that DO have a real graph (postgres, entdb) leave
// it unimplemented and fall through to the h.DB.QueryNodes path.
type testInspector interface {
	CountRefreshTokensForUserTest(ctx context.Context, userID string) (int, error)
	CountUsersByEmailTest(ctx context.Context, email string) (int, error)
	CountPasswordResetTokensForUserTest(ctx context.Context, userID string) (int, error)
}

func (h *Harness) CountRefreshTokensForUser(t *testing.T, userID string) int {
	t.Helper()
	if repo, ok := h.Repo.(*MemRepo); ok {
		return repo.CountRefreshTokensForUser(userID)
	}
	if insp, ok := h.Repo.(testInspector); ok {
		n, err := insp.CountRefreshTokensForUserTest(context.Background(), userID)
		if err != nil {
			t.Fatalf("CountRefreshTokensForUserTest(%q): %v", userID, err)
		}
		return n
	}
	return h.queryNodeCount(t, testTypeRefreshToken, map[string]any{
		testRefreshUserIDField: userID,
	})
}

func (h *Harness) CountUsersByEmail(t *testing.T, email string) int {
	t.Helper()
	if repo, ok := h.Repo.(*MemRepo); ok {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		n := 0
		for _, user := range repo.users {
			if user.Email == email {
				n++
			}
		}
		return n
	}
	if insp, ok := h.Repo.(testInspector); ok {
		n, err := insp.CountUsersByEmailTest(context.Background(), email)
		if err != nil {
			t.Fatalf("CountUsersByEmailTest(%q): %v", email, err)
		}
		return n
	}
	return h.queryNodeCount(t, testTypeUser, map[string]any{
		testUserEmailField: email,
	})
}

func (h *Harness) CountPasswordResetTokensForUser(t *testing.T, userID string) int {
	t.Helper()
	if repo, ok := h.Repo.(*MemRepo); ok {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		n := 0
		for _, tok := range repo.passwordResets {
			if tok.UserID == userID {
				n++
			}
		}
		return n
	}
	if insp, ok := h.Repo.(testInspector); ok {
		n, err := insp.CountPasswordResetTokensForUserTest(context.Background(), userID)
		if err != nil {
			t.Fatalf("CountPasswordResetTokensForUserTest(%q): %v", userID, err)
		}
		return n
	}
	return h.queryNodeCount(t, testTypePasswordReset, map[string]any{
		testPasswordResetUserIDField: userID,
	})
}

func (h *Harness) CountAuditEventsByType(t *testing.T, eventType string) int {
	t.Helper()
	if h.Audit != nil {
		return h.Audit.CountByEventType(eventType)
	}
	return h.queryNodeCount(t, testTypeAuditEvent, map[string]any{
		testAuditEventTypeField: eventType,
	})
}

// WaitForAuditEventCountAtLeast polls CountAuditEventsByType until the
// count reaches `want` or the 2s deadline elapses. The audit logger is
// async (bounded channel + background goroutine), so tests asserting
// "this RPC emitted event X" race the write goroutine — this helper
// closes that race deterministically.
func (h *Harness) WaitForAuditEventCountAtLeast(t *testing.T, eventType string, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := h.CountAuditEventsByType(t, eventType); got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit event %q count did not reach %d (last=%d)",
				eventType, want, h.CountAuditEventsByType(t, eventType))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *Harness) ListPasskeyCredentials(t *testing.T, userID string) []*service.PasskeyCredRecord {
	t.Helper()

	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for {
		recs, err := h.Repo.ListPasskeyCredentials(ctx, userID)
		if err == nil && len(recs) > 0 {
			return recs
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("ListPasskeyCredentials(%q): %v", userID, err)
			}
			t.Fatalf("ListPasskeyCredentials(%q): no credentials found", userID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *Harness) SetPasskeyChallengeValue(t *testing.T, challengeID, challenge string) {
	t.Helper()

	if repo, ok := h.Repo.(*MemRepo); ok {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		rec := repo.passkeyChallenges[challengeID]
		if rec == nil {
			t.Fatalf("passkey challenge %q not found", challengeID)
		}
		rec.Challenge = challenge
		return
	}

	rec := h.waitForPasskeyChallenge(t, challengeID)
	h.updateNode(t, testTypePasskeyChallenge, rec.NodeID, map[string]any{
		testPasskeyChallengeField: challenge,
	})
	h.waitForPasskeyChallengeValue(t, challengeID, challenge)
}

func (h *Harness) SetPasskeyCredentialSignCount(t *testing.T, credentialID string, signCount int64) {
	t.Helper()

	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec, err := h.Repo.GetPasskeyCredentialByCredID(ctx, credentialID)
		if err == nil && rec != nil {
			if err := h.Repo.UpdatePasskeyCredential(ctx, rec.NodeID, map[string]any{"sign_count": signCount}); err != nil {
				t.Fatalf("UpdatePasskeyCredential(%q): %v", credentialID, err)
			}
			return
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("GetPasskeyCredentialByCredID(%q): %v", credentialID, err)
			}
			t.Fatalf("GetPasskeyCredentialByCredID(%q): credential not found", credentialID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *Harness) ExpireQrLoginSession(t *testing.T, sessionID string) {
	t.Helper()

	if repo, ok := h.Repo.(*MemRepo); ok {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		for _, rec := range repo.qrSessions {
			if rec.SessionID == sessionID {
				rec.ExpiresAt = time.Now().Add(-time.Millisecond).UnixMilli()
				return
			}
		}
		t.Fatalf("FindQrLoginSession(%q): session not found", sessionID)
	}

	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec, err := h.Repo.FindQrLoginSession(ctx, sessionID)
		if err == nil && rec != nil {
			nowMs := time.Now().UnixMilli()
			h.updateNode(t, testTypeQrLoginSession, rec.NodeID, map[string]any{
				testQrExpiresAtField: nowMs - 1,
				testQrUpdatedAtField: nowMs,
			})
			h.WaitForQrLoginSession(t, sessionID, func(rec *service.QrLoginSessionRecord) bool {
				return rec.ExpiresAt <= time.Now().UnixMilli()
			})
			return
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("FindQrLoginSession(%q): %v", sessionID, err)
			}
			t.Fatalf("FindQrLoginSession(%q): session not found", sessionID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *Harness) WaitForRefreshTokenCount(t *testing.T, userID string, want int) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := h.CountRefreshTokensForUser(t, userID); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("refresh token count for %q did not reach %d", userID, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *Harness) WaitForUserCount(t *testing.T, email string, want int) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := h.CountUsersByEmail(t, email); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("user count for %q did not reach %d", email, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *Harness) WaitForQrLoginSession(t *testing.T, sessionID string, predicate func(*service.QrLoginSessionRecord) bool) *service.QrLoginSessionRecord {
	t.Helper()

	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec, err := h.Repo.FindQrLoginSession(ctx, sessionID)
		if err == nil && rec != nil && predicate(rec) {
			return rec
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("FindQrLoginSession(%q): %v", sessionID, err)
			}
			t.Fatalf("qr session %q did not reach expected state", sessionID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *Harness) WaitForTotpCredential(t *testing.T, userID string, predicate func(*service.TotpCredRecord) bool) *service.TotpCredRecord {
	t.Helper()

	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec, err := h.Repo.GetTotpCredential(ctx, userID)
		if err == nil && rec != nil && predicate(rec) {
			return rec
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("GetTotpCredential(%q): %v", userID, err)
			}
			t.Fatalf("totp credential for %q did not reach expected state", userID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *Harness) queryNodeCount(t *testing.T, typeID int, filter map[string]any) int {
	t.Helper()

	// `system:admin` has tenant-wide read on tenant-shard-db v1.12+,
	// where `user:system` only sees rows it created. The harness test
	// fixtures cross actor boundaries (admin creating users, users
	// creating their own refresh tokens), so a count assertion needs
	// the tenant-admin actor to see all rows.
	nodes, err := h.DB.QueryNodes(context.Background(), h.TenantID, "system:admin", typeID, filter)
	if err != nil {
		t.Fatalf("QueryNodes(type=%d, filter=%v): %v", typeID, filter, err)
	}
	return len(nodes)
}

func (h *Harness) waitForPasskeyChallenge(t *testing.T, challengeID string) *service.PasskeyChallengeRecord {
	t.Helper()

	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec, err := h.Repo.GetPasskeyChallenge(ctx, challengeID)
		if err == nil && rec != nil {
			return rec
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("GetPasskeyChallenge(%q): %v", challengeID, err)
			}
			t.Fatalf("GetPasskeyChallenge(%q): challenge not found", challengeID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *Harness) waitForPasskeyChallengeValue(t *testing.T, challengeID, want string) {
	t.Helper()

	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec, err := h.Repo.GetPasskeyChallenge(ctx, challengeID)
		if err == nil && rec != nil && rec.Challenge == want {
			return
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("GetPasskeyChallenge(%q): %v", challengeID, err)
			}
			t.Fatalf("passkey challenge %q did not reach expected value", challengeID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// testNodeUpdater is the optional test-support surface for in-place node
// patches on drivers without the EntDB graph (sqlite). It maps the two node
// types the harness mutates (passkey challenges, qr login sessions) onto the
// driver's typed update methods.
type testNodeUpdater interface {
	UpdatePasskeyChallengeTest(ctx context.Context, nodeID string, patch map[string]any) error
	UpdateQrLoginSessionTest(ctx context.Context, nodeID string, patch map[string]any) error
}

func (h *Harness) updateNode(t *testing.T, typeID int, nodeID string, patch map[string]any) {
	t.Helper()

	if upd, ok := h.Repo.(testNodeUpdater); ok {
		var err error
		switch typeID {
		case testTypePasskeyChallenge:
			err = upd.UpdatePasskeyChallengeTest(context.Background(), nodeID, patch)
		case testTypeQrLoginSession:
			err = upd.UpdateQrLoginSessionTest(context.Background(), nodeID, patch)
		default:
			t.Fatalf("updateNode: testNodeUpdater has no mapping for type=%d", typeID)
		}
		if err != nil {
			t.Fatalf("updateNode(type=%d node=%q): %v", typeID, nodeID, err)
		}
		return
	}

	// Use the tenant-admin actor so updates cross user boundaries
	// without ACCESS_DENIED on v1.12+ — see queryNodeCount above.
	_, err := h.DB.ExecuteAtomic(context.Background(), h.TenantID, "system:admin", []graph.Operation{{
		Type:   graph.OpUpdateNode,
		TypeID: typeID,
		NodeID: nodeID,
		Patch:  patch,
	}})
	if err != nil {
		t.Fatalf("ExecuteAtomic(update type=%d node=%q): %v", typeID, nodeID, err)
	}
}

// bearerHTTPClient is a connect.HTTPClient that injects a Bearer
// token on every request. Connect-Go's NewIdentityServiceClient
// accepts any HTTPClient — we don't have to mutate connect.Request
// headers from the call site.
type bearerHTTPClient struct {
	base  *http.Client
	token string
}

func (b bearerHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.Do(req)
}

// newReq is a small convenience wrapper used by tests to attach
// X-Forwarded-For / User-Agent headers without ceremony.
func newReq[T any](msg *T, headers map[string]string) *connect.Request[T] {
	r := connect.NewRequest(msg)
	for k, v := range headers {
		r.Header().Set(k, v)
	}
	return r
}

// newTestConfig returns a Config tuned for integration tests. We
// override the DB and key ring elsewhere; this only sets non-zero
// values that the service layer reads (expiries, password limits,
// CORS origins, etc).
// testProjectSecretsKey is a valid base64-encoded 32-byte (all-zero) AES key.
// The postgres control plane requires GATEWAY_PROJECT_SECRETS_KEY; harnesses
// that boot postgres inherit this so config.Validate passes.
const testProjectSecretsKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func newTestConfig() *config.Config {
	return &config.Config{
		DefaultTenantID:   "test-tenant",
		ProjectSecretsKey: testProjectSecretsKey,
		// Integration harness models an open-signup deployment. Under default-DENY
		// the mode must be set explicitly (GATEWAY_DEFAULT_PROJECT_ACCESS_MODE=open).
		DefaultProjectAccessMode:        "open",
		AuthAllowLocal:                  true,
		PasswordSignupEnabled:           true,
		PasswordResetEnabled:            true,
		PasswordlessSignupEnabled:       true,
		PasswordlessCodeTTLSeconds:      300,
		PasswordlessCodeMaxAttempts:     5,
		PasswordlessMagicLinkTTLSeconds: 900,
		JWTExpirySeconds:                900,
		RefreshExpirySeconds:            604800,
		LoginMaxFailedAttempts:          5,
		LoginLockoutSeconds:             900,
		LoginChallengeExpirySeconds:     300,
		PasskeyRPID:                     "localhost",
		PasskeyRPName:                   "IdentityIntegrationTests",
		PasskeyOrigin:                   "http://localhost:9002",
		PasskeyChallengeExpirySeconds:   300,
		QRLoginBaseURL:                  "http://localhost:9002",
		QRLoginExpirySeconds:            300,
		TOTPIssuer:                      "Glassa Test",
		AllowedOrigins:                  "http://localhost:9002",
		AppBaseURL:                      "https://app.test",
		EmailTokenExpirySeconds:         3600,
		SMTPFrom:                        "no-reply@test.local",
	}
}

// ──────────────────────────────────────────────────────────────────
// MemRepo: in-memory implementation of service.Repository.
//
// This mirrors internal/service/testutil_test.go's fakeRepo, which
// is unfortunately scoped to the service package's test files (so
// not importable from this build-tagged package). Keeping it here
// also keeps the production binary's dependencies clean — the
// production binary still uses service.StubRepository.
// ──────────────────────────────────────────────────────────────────

// MemRepo is an in-memory implementation of service.Repository
// suitable for integration tests of password / session / refresh
// flows. All operations are mutex-protected so tests using
// t.Parallel() are race-free.
type MemRepo struct {
	attestedDevices     map[string]*service.AttestedDeviceRecord
	assuranceChallenges map[string]*service.AssuranceChallengeRecord
	mu                  sync.Mutex

	seq                int64
	users              map[string]*service.User
	refreshTokens      map[string]*service.RefreshTokenRecord
	passkeyCreds       map[string]*service.PasskeyCredRecord
	passkeyChallenges  map[string]*service.PasskeyChallengeRecord
	qrSessions         map[string]*service.QrLoginSessionRecord
	oauthOneTimeCodes  map[string]*service.OAuthOneTimeCodeRecord
	nativeRedemptions  map[string]*service.NativeTokenRedemptionRecord
	emailLoginCodes    map[string]*service.EmailLoginCodeRecord
	magicLinkTokens    map[string]*service.MagicLinkTokenRecord
	phoneVerifyCodes   map[string]*service.PhoneVerificationCodeRecord
	totpCreds          map[string]*service.TotpCredRecord
	recoveryCodes      map[string]*service.RecoveryCodeRecord
	loginChallenges    map[string]*service.LoginChallengeRecord
	invitations        map[string]*service.InvitationRecord
	passwordResets     map[string]*service.PasswordResetToken
	emailVerifications map[string]*service.EmailVerificationToken
	emailChanges       map[string]*service.EmailChangeToken
	oauthIdentities    map[string]*service.OAuthIdentity
	idvRecords         map[string]*service.IdentityVerificationRecord
	parentalConsents   map[string]*service.ParentalConsentRecord
	guardianEdges      map[string]*service.GuardianEdge
	sessions           map[string]*service.SessionRecord
	auditEvents        []*service.AuditEvent
}

// NewMemRepo returns an empty MemRepo.
func NewMemRepo() *MemRepo {
	return &MemRepo{
		users:              make(map[string]*service.User),
		refreshTokens:      make(map[string]*service.RefreshTokenRecord),
		passkeyCreds:       make(map[string]*service.PasskeyCredRecord),
		passkeyChallenges:  make(map[string]*service.PasskeyChallengeRecord),
		qrSessions:         make(map[string]*service.QrLoginSessionRecord),
		oauthOneTimeCodes:  make(map[string]*service.OAuthOneTimeCodeRecord),
		nativeRedemptions:  make(map[string]*service.NativeTokenRedemptionRecord),
		emailLoginCodes:    make(map[string]*service.EmailLoginCodeRecord),
		magicLinkTokens:    make(map[string]*service.MagicLinkTokenRecord),
		phoneVerifyCodes:   make(map[string]*service.PhoneVerificationCodeRecord),
		totpCreds:          make(map[string]*service.TotpCredRecord),
		recoveryCodes:      make(map[string]*service.RecoveryCodeRecord),
		loginChallenges:    make(map[string]*service.LoginChallengeRecord),
		invitations:        make(map[string]*service.InvitationRecord),
		passwordResets:     make(map[string]*service.PasswordResetToken),
		emailVerifications: make(map[string]*service.EmailVerificationToken),
		emailChanges:       make(map[string]*service.EmailChangeToken),
		oauthIdentities:    make(map[string]*service.OAuthIdentity),
		idvRecords:         make(map[string]*service.IdentityVerificationRecord),
		parentalConsents:   make(map[string]*service.ParentalConsentRecord),
		guardianEdges:      make(map[string]*service.GuardianEdge),
		sessions:           make(map[string]*service.SessionRecord),
	}
}

func (r *MemRepo) nextID() string {
	r.seq++
	return fmt.Sprintf("mem-%d", r.seq)
}

// CountRefreshTokensForUser is a test helper for assertions about
// session count.
func (r *MemRepo) CountRefreshTokensForUser(userID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, t := range r.refreshTokens {
		if t.UserID == userID {
			n++
		}
	}
	return n
}

// ── Users ─────────────────────────────────────────────────────────

func (r *MemRepo) FindUserByEmail(_ context.Context, email string) (*service.User, error) {
	// The empty address matches nobody, mirroring every production driver's
	// early return. Without this an anonymous user (Email == "") is
	// resolvable by a lookup for "" — the inverse of what the conformance
	// suite pins.
	if email == "" {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.Email == email {
			cp := *u
			return &cp, nil
		}
	}
	return nil, nil
}

// FindUserByUsername mirrors the production drivers' partial-index username
// lookup: an empty username matches nobody.
func (r *MemRepo) FindUserByUsername(_ context.Context, username string) (*service.User, error) {
	if username == "" {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.Username != "" && u.Username == username {
			cp := *u
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) ListUsers(_ context.Context, filter service.UserListFilter) ([]*service.User, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = service.DefaultUserListLimit
	}
	if limit > service.MaxUserListLimit {
		limit = service.MaxUserListLimit
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	r.mu.Lock()
	matched := make([]*service.User, 0, len(r.users))
	for _, u := range r.users {
		if filter.Email != "" && !strings.EqualFold(u.Email, filter.Email) {
			continue
		}
		if filter.ExternalID != "" && u.ExternalID != filter.ExternalID {
			continue
		}
		// Mirrors the drivers' NOT is_anonymous predicate: credential-less
		// accounts have no email, so a surface presenting users by address
		// must not receive them unless it opts in.
		if !filter.IncludeAnonymous && u.IsAnonymous {
			continue
		}
		cp := *u
		matched = append(matched, &cp)
	}
	r.mu.Unlock()

	// Stable ordering identical to the SQL drivers: created_at asc, then id.
	sort.Slice(matched, func(i, j int) bool {
		ti, tj := matched[i].CreatedAt.UnixMilli(), matched[j].CreatedAt.UnixMilli()
		if ti != tj {
			return ti < tj
		}
		return matched[i].ID < matched[j].ID
	})

	if offset >= len(matched) {
		return nil, nil
	}
	end := offset + limit
	if end > len(matched) {
		end = len(matched)
	}
	return matched[offset:end], nil
}

func (r *MemRepo) CountUsers(_ context.Context, filter service.UserListFilter) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, u := range r.users {
		if filter.Email != "" && !strings.EqualFold(u.Email, filter.Email) {
			continue
		}
		if filter.ExternalID != "" && u.ExternalID != filter.ExternalID {
			continue
		}
		// Mirrors the drivers' NOT is_anonymous predicate: credential-less
		// accounts have no email, so a surface presenting users by address
		// must not receive them unless it opts in.
		if !filter.IncludeAnonymous && u.IsAnonymous {
			continue
		}
		n++
	}
	return n, nil
}

func (r *MemRepo) ListUsersPendingDeletionBefore(_ context.Context, cutoffMs int64, limit int) ([]*service.User, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("mem: ListUsersPendingDeletionBefore: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	matched := make([]*service.User, 0)
	for _, u := range r.users {
		if u.Status != service.StatusPendingDeletion {
			continue
		}
		if u.DeletionScheduledAtMs <= 0 || u.DeletionScheduledAtMs > cutoffMs {
			continue
		}
		cp := *u
		matched = append(matched, &cp)
	}
	r.mu.Unlock()

	sort.Slice(matched, func(i, j int) bool {
		if matched[i].DeletionScheduledAtMs != matched[j].DeletionScheduledAtMs {
			return matched[i].DeletionScheduledAtMs < matched[j].DeletionScheduledAtMs
		}
		return matched[i].ID < matched[j].ID
	})
	if len(matched) > limit {
		matched = matched[:limit]
	}
	return matched, nil
}

func (r *MemRepo) GetUser(_ context.Context, userID string) (*service.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}

func (r *MemRepo) CreateUser(_ context.Context, u *service.User) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.users {
		// Case-insensitive + ErrAlreadyExists-wrapped, matching the production
		// memory driver and the cross-driver conformance contract. The
		// uniqueness index is PARTIAL (WHERE email <> '') since 0028/0013, so
		// users without an address — every anonymous user — never collide.
		if u.Email != "" && strings.EqualFold(existing.Email, u.Email) {
			return "", fmt.Errorf("user %q: %w", u.Email, service.ErrAlreadyExists)
		}
		if u.ExternalID != "" && existing.ExternalID == u.ExternalID {
			return "", fmt.Errorf("external_id %q: %w", u.ExternalID, service.ErrAlreadyExists)
		}
		// Partial unique index on (project_id, username) WHERE username <> ''
		// — a managed child's handle is its login identifier, so a duplicate
		// has to be refused here exactly as the SQL drivers refuse it.
		if u.Username != "" && existing.Username == u.Username {
			return "", fmt.Errorf("username %q: %w", u.Username, service.ErrAlreadyExists)
		}
	}
	id := u.ID
	if id == "" {
		id = r.nextID()
	}
	u.ID = id
	cp := *u
	r.users[id] = &cp
	return id, nil
}

func (r *MemRepo) UpdateUser(_ context.Context, userID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	// Same partial unique index as CreateUser: a rename onto a taken handle
	// is refused BEFORE any mutation, so a rejected update leaves the store
	// untouched exactly as a rolled-back transaction would.
	if v, ok := fields["username"]; ok {
		if username, _ := v.(string); username != "" {
			for id, other := range r.users {
				if id != userID && other.Username == username {
					return fmt.Errorf("username %q: %w", username, service.ErrAlreadyExists)
				}
			}
		}
	}
	// Likewise the partial unique index on email.
	if v, ok := fields["email"]; ok {
		if addr, _ := v.(string); addr != "" {
			for id, other := range r.users {
				if id != userID && strings.EqualFold(other.Email, addr) {
					return fmt.Errorf("email %q: %w", addr, service.ErrAlreadyExists)
				}
			}
		}
	}
	if v, ok := fields["external_id"]; ok {
		if ext, _ := v.(string); ext != "" {
			for id, other := range r.users {
				if id != userID && other.ExternalID == ext {
					return fmt.Errorf("external_id %q: %w", ext, service.ErrAlreadyExists)
				}
			}
		}
	}
	applyUserFields(u, fields)
	return nil
}

// DeleteUser physically removes the user and every user-owned row,
// mirroring the production memory driver. Idempotent; email-keyed
// login codes / magic-link tokens are out of scope (no user_id).
func (r *MemRepo) DeleteUser(_ context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleteUserRowsLocked(userID)
	return nil
}

// deleteUserRowsLocked drains the user and every user-owned row. The caller
// must hold r.mu. Shared with DeleteStaleAnonymousUsers so the sweep
// cascades exactly like the SQL drivers' foreign keys do.
func (r *MemRepo) deleteUserRowsLocked(userID string) {
	for id, t := range r.refreshTokens {
		if t.UserID == userID {
			delete(r.refreshTokens, id)
		}
	}
	for id, s := range r.sessions {
		if s.UserID == userID {
			delete(r.sessions, id)
		}
	}
	for id, c := range r.passkeyCreds {
		if c.UserID == userID {
			delete(r.passkeyCreds, id)
		}
	}
	for id, c := range r.passkeyChallenges {
		if c.UserID == userID {
			delete(r.passkeyChallenges, id)
		}
	}
	for id, s := range r.qrSessions {
		if s.UserID == userID {
			delete(r.qrSessions, id)
		}
	}
	for id, c := range r.oauthOneTimeCodes {
		if c.UserID == userID {
			delete(r.oauthOneTimeCodes, id)
		}
	}
	for id, c := range r.totpCreds {
		if c.UserID == userID {
			delete(r.totpCreds, id)
		}
	}
	for id, c := range r.recoveryCodes {
		if c.UserID == userID {
			delete(r.recoveryCodes, id)
		}
	}
	for id, c := range r.loginChallenges {
		if c.UserID == userID {
			delete(r.loginChallenges, id)
		}
	}
	for id, inv := range r.invitations {
		if inv.UserID == userID {
			delete(r.invitations, id)
		}
	}
	for id, t := range r.passwordResets {
		if t.UserID == userID {
			delete(r.passwordResets, id)
		}
	}
	for id, t := range r.emailVerifications {
		if t.UserID == userID {
			delete(r.emailVerifications, id)
		}
	}
	for id, t := range r.emailChanges {
		if t.UserID == userID {
			delete(r.emailChanges, id)
		}
	}
	for id, oi := range r.oauthIdentities {
		if oi.UserID == userID {
			delete(r.oauthIdentities, id)
		}
	}
	for id, rec := range r.idvRecords {
		if rec.UserID == userID {
			delete(r.idvRecords, id)
		}
	}
	for id, c := range r.phoneVerifyCodes {
		if c.UserID == userID {
			delete(r.phoneVerifyCodes, id)
		}
	}
	for key, e := range r.guardianEdges {
		if e.GuardianUserID == userID || e.ChildUserID == userID {
			delete(r.guardianEdges, key)
		}
	}
	delete(r.users, userID)
}

func (r *MemRepo) IncrementFailedLoginCount(_ context.Context, userID string) (int32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return 0, fmt.Errorf("user %s not found", userID)
	}
	u.FailedLoginCount++
	return int32(u.FailedLoginCount), nil
}

func (r *MemRepo) ResetFailedLoginCount(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	u.FailedLoginCount = 0
	u.LockedUntil = 0
	return nil
}

func (r *MemRepo) SetUserLockedUntil(_ context.Context, userID string, lockedUntilMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	u.LockedUntil = lockedUntilMs
	return nil
}

// The harness repository is held to the same Repository contract as the three
// real drivers (see memrepo_conformance_test.go), so its field handling has to
// be complete rather than "whatever the integration tests happened to need".
//
// Split by destination type so each switch assigns concretely and stays well
// inside the complexity limit — one switch over every field would exceed it,
// and dispatching through accessor functions would trade a plain assignment
// for indirection the call site does not need.
//
// A wrong-typed value is SKIPPED, not written as the zero value, matching
// what the SQL drivers do with a value that does not fit the column.

func applyUserStringField(u *service.User, key string, v any) bool {
	s, ok := v.(string)
	if !ok {
		// A known key with a wrong-typed value is still "handled": the
		// drivers skip it rather than falling through to another type.
		return isUserStringField(key)
	}
	switch key {
	case "name":
		u.Name = s
	case "email":
		u.Email = s
	case "avatar_url":
		u.AvatarURL = s
	case "password_hash":
		u.PasswordHash = s
	case "status":
		u.Status = s
	case "recovery_email":
		u.RecoveryEmail = s
	case "external_id":
		u.ExternalID = s
	case "phone_number":
		u.PhoneNumber = s
	case "market":
		u.Market = s
	case "username":
		u.Username = s
	default:
		return false
	}
	return true
}

func isUserStringField(key string) bool {
	switch key {
	case "name", "email", "avatar_url", "password_hash", "status",
		"recovery_email", "external_id", "phone_number", "market", "username":
		return true
	}
	return false
}

func applyUserBoolField(u *service.User, key string, v any) bool {
	b, ok := v.(bool)
	if !ok {
		return isUserBoolField(key)
	}
	switch key {
	case "totp_required":
		u.TotpRequired = b
	case "email_verified":
		u.EmailVerified = b
	case "is_anonymous":
		u.IsAnonymous = b
	case "phone_verified":
		u.PhoneVerified = b
	case "idv_verified":
		u.IDVVerified = b
	default:
		return false
	}
	return true
}

func isUserBoolField(key string) bool {
	switch key {
	case "totp_required", "email_verified", "is_anonymous", "phone_verified", "idv_verified":
		return true
	}
	return false
}

func applyUserInt64Field(u *service.User, key string, v any) bool {
	x, ok := memFieldInt64(v)
	if !ok {
		return isUserInt64Field(key)
	}
	switch key {
	case "locked_until":
		u.LockedUntil = x
	case "last_login_at":
		u.LastLoginAtMs = x
	case "email_verified_at":
		u.EmailVerifiedAt = x
	case "anonymous_last_seen_ms":
		u.AnonymousLastSeenMs = x
	case "phone_verified_at":
		u.PhoneVerifiedAt = x
	case "idv_verified_at":
		u.IDVVerifiedAt = x
	case "date_of_birth_ms":
		u.DateOfBirthMs = x
	case "deletion_scheduled_at_ms":
		u.DeletionScheduledAtMs = x
	case "failed_login_count":
		u.FailedLoginCount = int(x)
	case "updated_at":
		u.UpdatedAt = time.UnixMilli(x)
	default:
		return false
	}
	return true
}

func isUserInt64Field(key string) bool {
	switch key {
	case "locked_until", "last_login_at", "email_verified_at", "anonymous_last_seen_ms",
		"phone_verified_at", "idv_verified_at", "date_of_birth_ms",
		"deletion_scheduled_at_ms", "failed_login_count", "updated_at":
		return true
	}
	return false
}

func memFieldInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	}
	return 0, false
}

// applyUserFields writes a Repository UpdateUser patch onto a stored user. An
// unknown field name is ignored, exactly as the SQL drivers ignore one that
// names no column.
func applyUserFields(u *service.User, fields map[string]any) {
	for k, v := range fields {
		if applyUserStringField(u, k, v) {
			continue
		}
		if applyUserBoolField(u, k, v) {
			continue
		}
		applyUserInt64Field(u, k, v)
	}
}

// ── Refresh Tokens ────────────────────────────────────────────────

func (r *MemRepo) FindRefreshTokenByHash(_ context.Context, hash string) (*service.RefreshTokenRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.refreshTokens {
		if t.TokenHash == hash && t.ConsumedAtMs == 0 {
			cp := *t
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) FindRefreshTokenByHashIncludingConsumed(_ context.Context, hash string) (*service.RefreshTokenRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.refreshTokens {
		if t.TokenHash == hash {
			cp := *t
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) CreateRefreshToken(_ context.Context, rec *service.RefreshTokenRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.refreshTokens[id] = &cp
	return id, nil
}

func (r *MemRepo) DeleteRefreshToken(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.refreshTokens, nodeID)
	return nil
}

func (r *MemRepo) DeleteRefreshTokensForUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, t := range r.refreshTokens {
		if t.UserID == userID {
			delete(r.refreshTokens, id)
		}
	}
	return nil
}

// ConsumeRefreshTokenByHash atomically marks the row consumed. Returns
// service.ErrUnauthenticated if the row is missing or already consumed,
// so concurrent rotations resolve to exactly one winner.
func (r *MemRepo) ConsumeRefreshTokenByHash(_ context.Context, hash string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.refreshTokens {
		if t.TokenHash == hash {
			if t.ConsumedAtMs != 0 {
				return service.ErrUnauthenticated
			}
			t.ConsumedAtMs = atMs
			return nil
		}
	}
	return service.ErrUnauthenticated
}

// ── Passkey Credentials ───────────────────────────────────────────

func (r *MemRepo) ListPasskeyCredentials(_ context.Context, userID string) ([]*service.PasskeyCredRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*service.PasskeyCredRecord
	for _, c := range r.passkeyCreds {
		if c.UserID == userID {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *MemRepo) GetPasskeyCredentialByCredID(_ context.Context, credentialID string) (*service.PasskeyCredRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.passkeyCreds {
		if c.CredentialID == credentialID {
			cp := *c
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) CreatePasskeyCredential(_ context.Context, rec *service.PasskeyCredRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.passkeyCreds[id] = &cp
	return id, nil
}

func (r *MemRepo) UpdatePasskeyCredential(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.passkeyCreds[nodeID]
	if !ok {
		return fmt.Errorf("passkey credential %s not found", nodeID)
	}
	if v, ok := fields["sign_count"]; ok {
		c.SignCount, _ = v.(int64)
	}
	if v, ok := fields["last_used_at"]; ok {
		c.LastUsedAt, _ = v.(int64)
	}
	return nil
}

func (r *MemRepo) DeletePasskeyCredentialsForUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.passkeyCreds {
		if c.UserID == userID {
			delete(r.passkeyCreds, id)
		}
	}
	return nil
}

// ── Passkey Challenges ────────────────────────────────────────────

func (r *MemRepo) GetPasskeyChallenge(_ context.Context, nodeID string) (*service.PasskeyChallengeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.passkeyChallenges[nodeID]
	if !ok {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}

func (r *MemRepo) CreatePasskeyChallenge(_ context.Context, rec *service.PasskeyChallengeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.passkeyChallenges[id] = &cp
	return id, nil
}

func (r *MemRepo) DeletePasskeyChallenge(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.passkeyChallenges, nodeID)
	return nil
}

// ── QR Login Sessions ─────────────────────────────────────────────

func (r *MemRepo) FindQrLoginSession(_ context.Context, sessionID string) (*service.QrLoginSessionRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.qrSessions {
		if s.SessionID == sessionID {
			cp := *s
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) CreateQrLoginSession(_ context.Context, rec *service.QrLoginSessionRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.qrSessions[id] = &cp
	return id, nil
}

func (r *MemRepo) UpdateQrLoginSession(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.qrSessions[nodeID]
	if !ok {
		return fmt.Errorf("qr session %s not found", nodeID)
	}
	if v, ok := fields["status"]; ok {
		s.Status, _ = v.(string)
	}
	if v, ok := fields["user_id"]; ok {
		s.UserID, _ = v.(string)
	}
	if v, ok := fields["approved_device_info"]; ok {
		s.ApprovedDeviceInfo, _ = v.(string)
	}
	if v, ok := fields["updated_at"]; ok {
		s.UpdatedAt, _ = v.(int64)
	}
	return nil
}

func (r *MemRepo) ConsumeQrLoginSession(_ context.Context, nodeID string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.qrSessions[nodeID]
	if !ok {
		return service.ErrQrLoginNotPending
	}
	if s.Status != "approved" {
		return service.ErrQrLoginNotPending
	}
	s.Status = "consumed"
	s.UpdatedAt = atMs
	return nil
}

func (r *MemRepo) CreateOAuthOneTimeCode(_ context.Context, rec *service.OAuthOneTimeCodeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.oauthOneTimeCodes[id] = &cp
	return id, nil
}

func (r *MemRepo) ConsumeOAuthOneTimeCode(_ context.Context, codeHash string, atMs int64) (*service.OAuthOneTimeCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.oauthOneTimeCodes {
		if c.CodeHash != codeHash {
			continue
		}
		if c.ConsumedAt != 0 || c.ExpiresAt <= atMs {
			return nil, service.ErrOAuthCodeInvalid
		}
		c.ConsumedAt = atMs
		cp := *c
		return &cp, nil
	}
	return nil, service.ErrOAuthCodeInvalid
}

func (r *MemRepo) RecordNativeTokenRedemption(_ context.Context, rec *service.NativeTokenRedemptionRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.nativeRedemptions {
		if e.ReplayKey == rec.ReplayKey {
			return "", service.ErrNativeTokenReplayed
		}
	}
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.nativeRedemptions[id] = &cp
	return id, nil
}

func (r *MemRepo) UpsertEmailLoginCode(_ context.Context, rec *service.EmailLoginCodeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.emailLoginCodes {
		if c.Email == rec.Email {
			delete(r.emailLoginCodes, id)
		}
	}
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.emailLoginCodes[id] = &cp
	return id, nil
}

func (r *MemRepo) FindEmailLoginCodeByEmail(_ context.Context, email string) (*service.EmailLoginCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.emailLoginCodes {
		if c.Email == email {
			cp := *c
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) IncrementEmailLoginCodeAttempts(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.emailLoginCodes[nodeID]
	if !ok {
		return errors.New("email login code not found")
	}
	c.AttemptCount++
	return nil
}

func (r *MemRepo) ConsumeEmailLoginCode(_ context.Context, email string, atMs int64) (*service.EmailLoginCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.emailLoginCodes {
		if c.Email != email {
			continue
		}
		if c.ConsumedAt != 0 || c.ExpiresAt <= atMs {
			return nil, service.ErrEmailLoginCodeInvalid
		}
		c.ConsumedAt = atMs
		cp := *c
		return &cp, nil
	}
	return nil, service.ErrEmailLoginCodeInvalid
}

func (r *MemRepo) CreateMagicLinkToken(_ context.Context, rec *service.MagicLinkTokenRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.magicLinkTokens[id] = &cp
	return id, nil
}

func (r *MemRepo) ConsumeMagicLinkToken(_ context.Context, tokenHash string, atMs int64) (*service.MagicLinkTokenRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, tkn := range r.magicLinkTokens {
		if tkn.TokenHash != tokenHash {
			continue
		}
		if tkn.ConsumedAt != 0 || tkn.ExpiresAt <= atMs {
			return nil, service.ErrMagicLinkInvalid
		}
		tkn.ConsumedAt = atMs
		cp := *tkn
		return &cp, nil
	}
	return nil, service.ErrMagicLinkInvalid
}

func (r *MemRepo) UpsertPhoneVerificationCode(_ context.Context, rec *service.PhoneVerificationCodeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.phoneVerifyCodes {
		if c.UserID == rec.UserID {
			delete(r.phoneVerifyCodes, id)
		}
	}
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.phoneVerifyCodes[id] = &cp
	return id, nil
}

func (r *MemRepo) FindPhoneVerificationCodeByUser(_ context.Context, userID string) (*service.PhoneVerificationCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.phoneVerifyCodes {
		if c.UserID == userID {
			cp := *c
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) IncrementPhoneVerificationCodeAttempts(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.phoneVerifyCodes[nodeID]
	if !ok {
		return fmt.Errorf("phone verification code %s not found", nodeID)
	}
	c.AttemptCount++
	return nil
}

func (r *MemRepo) ConsumePhoneVerificationCode(_ context.Context, userID string, atMs int64) (*service.PhoneVerificationCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.phoneVerifyCodes {
		if c.UserID != userID {
			continue
		}
		if c.ConsumedAt != 0 || c.ExpiresAt <= atMs {
			return nil, service.ErrPhoneCodeInvalid
		}
		c.ConsumedAt = atMs
		cp := *c
		return &cp, nil
	}
	return nil, service.ErrPhoneCodeInvalid
}

func (r *MemRepo) SetUserPhoneVerified(_ context.Context, userID, phoneNumber string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	u.PhoneNumber = phoneNumber
	u.PhoneVerified = true
	u.PhoneVerifiedAt = atMs
	return nil
}

// ── TOTP Credentials ──────────────────────────────────────────────

func (r *MemRepo) GetTotpCredential(_ context.Context, userID string) (*service.TotpCredRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.totpCreds {
		if c.UserID == userID {
			cp := *c
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) CreateTotpCredential(_ context.Context, rec *service.TotpCredRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.totpCreds[id] = &cp
	return id, nil
}

func (r *MemRepo) UpdateTotpCredential(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.totpCreds[nodeID]
	if !ok {
		return fmt.Errorf("totp credential %s not found", nodeID)
	}
	if v, ok := fields["verified"]; ok {
		c.Verified, _ = v.(bool)
	}
	if v, ok := fields["last_used_at"]; ok {
		c.LastUsedAt, _ = v.(int64)
	}
	return nil
}

func (r *MemRepo) DeleteTotpCredential(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.totpCreds, nodeID)
	return nil
}

func (r *MemRepo) DeleteTotpCredentialsForUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.totpCreds {
		if c.UserID == userID {
			delete(r.totpCreds, id)
		}
	}
	return nil
}

// ── Recovery Codes ────────────────────────────────────────────────

func (r *MemRepo) CreateRecoveryCode(_ context.Context, rec *service.RecoveryCodeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.recoveryCodes[id] = &cp
	return id, nil
}

func (r *MemRepo) FindRecoveryCodeByHash(_ context.Context, userID, hash string) (*service.RecoveryCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rc := range r.recoveryCodes {
		if rc.UserID == userID && rc.CodeHash == hash {
			cp := *rc
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) UpdateRecoveryCode(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rc, ok := r.recoveryCodes[nodeID]
	if !ok {
		return fmt.Errorf("recovery code %s not found", nodeID)
	}
	if v, ok := fields["used"]; ok {
		rc.Used, _ = v.(bool)
	}
	if v, ok := fields["used_at"]; ok {
		rc.UsedAt, _ = v.(int64)
	}
	return nil
}

func (r *MemRepo) DeleteRecoveryCodesForUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, rc := range r.recoveryCodes {
		if rc.UserID == userID {
			delete(r.recoveryCodes, id)
		}
	}
	return nil
}

// ── Login Challenges ──────────────────────────────────────────────

func (r *MemRepo) CreateLoginChallenge(_ context.Context, rec *service.LoginChallengeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	rec.NodeID = id
	cp := *rec
	r.loginChallenges[id] = &cp
	return id, nil
}

func (r *MemRepo) GetLoginChallengeByChallengeID(_ context.Context, challengeID string) (*service.LoginChallengeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, lc := range r.loginChallenges {
		if lc.ChallengeID == challengeID {
			cp := *lc
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) DeleteLoginChallenge(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.loginChallenges, nodeID)
	return nil
}

// ── Invitations ───────────────────────────────────────────────────

func (r *MemRepo) FindInvitationByHash(_ context.Context, tokenHash string) (*service.InvitationRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, inv := range r.invitations {
		if inv.TokenHash == tokenHash {
			cp := *inv
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) UpdateInvitation(_ context.Context, nodeID string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	inv, ok := r.invitations[nodeID]
	if !ok {
		return fmt.Errorf("invitation %s not found", nodeID)
	}
	if v, ok := fields["accepted_at"]; ok {
		inv.AcceptedAt, _ = v.(int64)
	}
	return nil
}

// ── Password Reset Tokens ─────────────────────────────────────────

func (r *MemRepo) CreatePasswordResetToken(_ context.Context, t *service.PasswordResetToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	t.NodeID = id
	cp := *t
	r.passwordResets[id] = &cp
	return nil
}

func (r *MemRepo) FindPasswordResetTokenByHash(_ context.Context, hash string) (*service.PasswordResetToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.passwordResets {
		if t.TokenHash == hash {
			cp := *t
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) MarkPasswordResetTokenConsumed(_ context.Context, id string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.passwordResets[id]
	if !ok {
		return fmt.Errorf("password reset token %s not found", id)
	}
	t.ConsumedAt = atMs
	return nil
}

// ── Email Verification Tokens ─────────────────────────────────────

func (r *MemRepo) CreateEmailVerificationToken(_ context.Context, t *service.EmailVerificationToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	t.NodeID = id
	cp := *t
	r.emailVerifications[id] = &cp
	return nil
}

func (r *MemRepo) FindEmailVerificationTokenByHash(_ context.Context, hash string) (*service.EmailVerificationToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.emailVerifications {
		if t.TokenHash == hash {
			cp := *t
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) MarkEmailVerificationTokenConsumed(_ context.Context, id string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.emailVerifications[id]
	if !ok {
		return fmt.Errorf("email verification token %s not found", id)
	}
	t.ConsumedAt = atMs
	return nil
}

func (r *MemRepo) SetUserIDVVerified(_ context.Context, userID string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	u.IDVVerified = true
	u.IDVVerifiedAt = atMs
	return nil
}

func (r *MemRepo) SetUserEmailVerified(_ context.Context, userID string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	u.EmailVerified = true
	u.EmailVerifiedAt = atMs
	return nil
}

// ── Email Change Tokens ───────────────────────────────────────────

func (r *MemRepo) CreateEmailChangeToken(_ context.Context, t *service.EmailChangeToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID()
	t.NodeID = id
	cp := *t
	r.emailChanges[id] = &cp
	return nil
}

func (r *MemRepo) FindEmailChangeTokenByHash(_ context.Context, hash string) (*service.EmailChangeToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.emailChanges {
		if t.TokenHash == hash {
			cp := *t
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) FindUserByProviderID(_ context.Context, provider, providerUserID string) (*service.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, oi := range r.oauthIdentities {
		if oi.Provider == provider && oi.ProviderUserID == providerUserID {
			u, ok := r.users[oi.UserID]
			if !ok {
				return nil, nil
			}
			cp := *u
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) MarkEmailChangeTokenConsumed(_ context.Context, id string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.emailChanges[id]
	if !ok {
		return fmt.Errorf("email change token %s not found", id)
	}
	t.ConsumedAt = atMs
	return nil
}

func (r *MemRepo) UpdateUserEmail(_ context.Context, userID, newEmail string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}
	// Enforce uniqueness across users, on the same terms as CreateUser and the
	// SQL drivers: case-insensitive, and wrapping ErrAlreadyExists so callers
	// can tell a collision from any other failure.
	for id, other := range r.users {
		if id != userID && newEmail != "" && strings.EqualFold(other.Email, newEmail) {
			return fmt.Errorf("email %q: %w", newEmail, service.ErrAlreadyExists)
		}
	}
	u.Email = newEmail
	u.EmailVerified = true
	u.EmailVerifiedAt = atMs
	u.UpdatedAt = time.UnixMilli(atMs)
	return nil
}

func (r *MemRepo) CreateOAuthIdentity(_ context.Context, oi *service.OAuthIdentity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.oauthIdentities {
		if existing.Provider == oi.Provider && existing.ProviderUserID == oi.ProviderUserID {
			return fmt.Errorf("oauth identity already linked: %s/%s", oi.Provider, oi.ProviderUserID)
		}
	}
	id := r.nextID()
	oi.NodeID = id
	cp := *oi
	r.oauthIdentities[id] = &cp
	return nil
}

func (r *MemRepo) ListOAuthIdentitiesForUser(_ context.Context, userID string) ([]*service.OAuthIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*service.OAuthIdentity
	for _, oi := range r.oauthIdentities {
		if oi.UserID == userID {
			cp := *oi
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *MemRepo) DeleteOAuthIdentity(_ context.Context, userID, provider, providerUserID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, oi := range r.oauthIdentities {
		if oi.UserID == userID && oi.Provider == provider && oi.ProviderUserID == providerUserID {
			delete(r.oauthIdentities, id)
			return nil
		}
	}
	return service.ErrNotFound
}

// ── Audit Events ────────────────────────────────────────────────────────

func (r *MemRepo) CreateAuditEvent(_ context.Context, e *service.AuditEvent) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := e.ID
	if id == "" {
		id = r.nextID()
	}
	cp := *e
	cp.ID = id
	r.auditEvents = append(r.auditEvents, &cp)
	return id, nil
}

func (r *MemRepo) ListAuditEventsForUser(_ context.Context, userID string, limit int) ([]*service.AuditEvent, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("MemRepo: ListAuditEventsForUser: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*service.AuditEvent, 0)
	for _, e := range r.auditEvents {
		if e.ActorUserID == userID || e.TargetUserID == userID {
			cp := *e
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r *MemRepo) DeleteAuditEventsBefore(_ context.Context, cutoffMs int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.auditEvents[:0]
	deleted := 0
	for _, e := range r.auditEvents {
		if e.CreatedAt < cutoffMs {
			deleted++
			continue
		}
		kept = append(kept, e)
	}
	r.auditEvents = kept
	return deleted, nil
}

// ── Identity Verification ──────────────────────────────────────────────

func (r *MemRepo) CreateIdentityVerification(_ context.Context, rec *service.IdentityVerificationRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec.VerificationID == "" {
		return errors.New("idv: missing verification id")
	}
	if _, ok := r.idvRecords[rec.VerificationID]; ok {
		return fmt.Errorf("idv: %s already exists", rec.VerificationID)
	}
	if rec.NodeID == "" {
		rec.NodeID = r.nextID()
	}
	cp := *rec
	r.idvRecords[rec.VerificationID] = &cp
	return nil
}

func (r *MemRepo) GetIdentityVerification(_ context.Context, verificationID string) (*service.IdentityVerificationRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.idvRecords[verificationID]
	if !ok {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

func (r *MemRepo) GetLatestIdentityVerificationForUser(_ context.Context, userID string) (*service.IdentityVerificationRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var latest *service.IdentityVerificationRecord
	for _, rec := range r.idvRecords {
		if rec.UserID != userID {
			continue
		}
		if latest == nil || rec.CreatedAt > latest.CreatedAt {
			latest = rec
		}
	}
	if latest == nil {
		return nil, nil
	}
	cp := *latest
	return &cp, nil
}

func (r *MemRepo) UpdateIdentityVerificationStatus(_ context.Context, verificationID, status, rejectionReason string, completedAtMs, updatedAtMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.idvRecords[verificationID]
	if !ok {
		return fmt.Errorf("idv: %s not found", verificationID)
	}
	rec.Status = status
	rec.RejectionReason = rejectionReason
	rec.CompletedAt = completedAtMs
	rec.UpdatedAt = updatedAtMs
	return nil
}

func (r *MemRepo) CreateParentalConsent(_ context.Context, rec *service.ParentalConsentRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec.ConsentID == "" {
		return fmt.Errorf("parental consent: missing consent id")
	}
	if _, ok := r.parentalConsents[rec.ConsentID]; ok {
		return fmt.Errorf("parental consent: %s already exists", rec.ConsentID)
	}
	cp := *rec
	r.parentalConsents[rec.ConsentID] = &cp
	return nil
}

// ListActiveParentalConsentsForChild mirrors the drivers: every non-revoked
// consent for the child, newest grant first.
// SetDateOfBirthOnce mirrors the drivers' compare-and-set: the write lands
// only while the account still has no date of birth.
// GetUsersByIDs mirrors the drivers' batch fetch: ordered by id, unknown ids
// absent rather than an error.
func (r *MemRepo) GetUsersByIDs(_ context.Context, ids []string) ([]*service.User, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*service.User, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		if u, ok := r.users[id]; ok {
			cp := *u
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (r *MemRepo) SetDateOfBirthOnce(_ context.Context, userID string, dobMs int64, status string, nowMs int64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok || u.DateOfBirthMs != 0 {
		return false, nil
	}
	u.DateOfBirthMs = dobMs
	if status != "" {
		u.Status = status
	}
	u.UpdatedAt = time.UnixMilli(nowMs)
	return true, nil
}

func (r *MemRepo) ListActiveParentalConsentsForChild(_ context.Context, childUserID string) ([]*service.ParentalConsentRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*service.ParentalConsentRecord, 0, 2)
	for _, rec := range r.parentalConsents {
		if rec.ChildUserID != childUserID || rec.RevokedAt != 0 {
			continue
		}
		cp := *rec
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].GrantedAt != out[j].GrantedAt {
			return out[i].GrantedAt > out[j].GrantedAt
		}
		return out[i].ConsentID < out[j].ConsentID
	})
	return out, nil
}

func (r *MemRepo) GetActiveParentalConsentForChild(_ context.Context, childUserID string) (*service.ParentalConsentRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var latest *service.ParentalConsentRecord
	for _, rec := range r.parentalConsents {
		if rec.ChildUserID != childUserID || rec.RevokedAt != 0 {
			continue
		}
		if latest == nil || rec.GrantedAt > latest.GrantedAt {
			latest = rec
		}
	}
	if latest == nil {
		return nil, nil
	}
	cp := *latest
	return &cp, nil
}

func (r *MemRepo) MarkParentalConsentRevoked(_ context.Context, consentID, revokedByUserID string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.parentalConsents[consentID]
	if !ok {
		return fmt.Errorf("parental consent: %s not found", consentID)
	}
	rec.RevokedAt = atMs
	rec.RevokedByUserID = revokedByUserID
	return nil
}

func (r *MemRepo) UpsertGuardianEdge(_ context.Context, e *service.GuardianEdge) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := e.GuardianUserID + "\x00" + e.ChildUserID
	if _, ok := r.guardianEdges[key]; ok {
		return nil // idempotent re-upsert preserves created_at_ms
	}
	cp := *e
	r.guardianEdges[key] = &cp
	return nil
}

func (r *MemRepo) DeleteGuardianEdge(_ context.Context, guardianUserID, childUserID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.guardianEdges, guardianUserID+"\x00"+childUserID)
	return nil
}

func (r *MemRepo) GetGuardianEdge(_ context.Context, guardianUserID, childUserID string) (*service.GuardianEdge, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.guardianEdges[guardianUserID+"\x00"+childUserID]
	if !ok {
		return nil, nil
	}
	cp := *e
	return &cp, nil
}

func (r *MemRepo) ListGuardiansOfChild(_ context.Context, childUserID string, limit, offset int) ([]*service.GuardianEdge, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("ListGuardiansOfChild: limit must be > 0, got %d", limit)
	}
	if offset < 0 {
		offset = 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*service.GuardianEdge
	for _, e := range r.guardianEdges {
		if e.ChildUserID != childUserID {
			continue
		}
		cp := *e
		out = append(out, &cp)
	}
	// Stable ordering identical to the SQL drivers (ORDER BY
	// guardian_user_id): the listing reaches clients through GetGuardians,
	// so map-iteration order would make the same call answer differently
	// every time on this driver alone.
	sort.Slice(out, func(i, j int) bool { return out[i].GuardianUserID < out[j].GuardianUserID })
	if offset >= len(out) {
		return nil, nil
	}
	out = out[offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r *MemRepo) ListChildrenOfGuardian(_ context.Context, guardianUserID string, limit, offset int) ([]*service.GuardianEdge, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("ListChildrenOfGuardian: limit must be > 0, got %d", limit)
	}
	if offset < 0 {
		offset = 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*service.GuardianEdge
	for _, e := range r.guardianEdges {
		if e.GuardianUserID != guardianUserID {
			continue
		}
		cp := *e
		out = append(out, &cp)
	}
	// Stable ordering identical to the SQL drivers (ORDER BY child_user_id).
	sort.Slice(out, func(i, j int) bool { return out[i].ChildUserID < out[j].ChildUserID })
	if offset >= len(out) {
		return nil, nil
	}
	out = out[offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// CreateManagedChildAccount mirrors the production drivers' single-
// transaction semantics under one lock hold: a duplicate username fails
// BEFORE any mutation, so no partial (account, edge, consent) state is
// reachable.
func (r *MemRepo) CreateManagedChildAccount(_ context.Context, u *service.User, edge *service.GuardianEdge, consent *service.ParentalConsentRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if u.Username != "" {
		for _, existing := range r.users {
			if existing.Username == u.Username {
				return fmt.Errorf("username %q: %w", u.Username, service.ErrAlreadyExists)
			}
		}
	}
	id := u.ID
	if id == "" {
		id = r.nextID()
	}
	u.ID = id
	cp := *u
	r.users[id] = &cp

	edge.ChildUserID = id
	ecp := *edge
	r.guardianEdges[edge.GuardianUserID+"\x00"+id] = &ecp

	consent.ChildUserID = id
	ccp := *consent
	r.parentalConsents[consent.ConsentID] = &ccp
	return nil
}

func (r *MemRepo) DeleteExpiredWebAuthnChallenges(_ context.Context, beforeMs int64, limit int) error {
	// The Repository contract refuses an unbounded delete batch, so a buggy
	// caller cannot stall the store — the real drivers all reject this.
	if limit <= 0 {
		return fmt.Errorf("integration: DeleteExpiredWebAuthnChallenges: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.passkeyChallenges {
		if limit > 0 && n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.passkeyChallenges, id)
			n++
		}
	}
	return nil
}

func (r *MemRepo) DeleteExpiredEmailVerificationTokens(_ context.Context, beforeMs int64, limit int) error {
	// The Repository contract refuses an unbounded delete batch, so a buggy
	// caller cannot stall the store — the real drivers all reject this.
	if limit <= 0 {
		return fmt.Errorf("integration: DeleteExpiredEmailVerificationTokens: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, t := range r.emailVerifications {
		if limit > 0 && n >= limit {
			break
		}
		if t.ExpiresAt < beforeMs {
			delete(r.emailVerifications, id)
			n++
		}
	}
	return nil
}

func (r *MemRepo) DeleteExpiredPasswordResetTokens(_ context.Context, beforeMs int64, limit int) error {
	// The Repository contract refuses an unbounded delete batch, so a buggy
	// caller cannot stall the store — the real drivers all reject this.
	if limit <= 0 {
		return fmt.Errorf("integration: DeleteExpiredPasswordResetTokens: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, t := range r.passwordResets {
		if limit > 0 && n >= limit {
			break
		}
		if t.ExpiresAt < beforeMs {
			delete(r.passwordResets, id)
			n++
		}
	}
	return nil
}

func (r *MemRepo) DeleteExpiredEmailChangeTokens(_ context.Context, beforeMs int64, limit int) error {
	// The Repository contract refuses an unbounded delete batch, so a buggy
	// caller cannot stall the store — the real drivers all reject this.
	if limit <= 0 {
		return fmt.Errorf("integration: DeleteExpiredEmailChangeTokens: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, t := range r.emailChanges {
		if limit > 0 && n >= limit {
			break
		}
		if t.ExpiresAt < beforeMs {
			delete(r.emailChanges, id)
			n++
		}
	}
	return nil
}

func (r *MemRepo) DeleteExpiredLoginChallenges(_ context.Context, beforeMs int64, limit int) error {
	// The Repository contract refuses an unbounded delete batch, so a buggy
	// caller cannot stall the store — the real drivers all reject this.
	if limit <= 0 {
		return fmt.Errorf("integration: DeleteExpiredLoginChallenges: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.loginChallenges {
		if limit > 0 && n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.loginChallenges, id)
			n++
		}
	}
	return nil
}

func (r *MemRepo) DeleteExpiredOAuthOneTimeCodes(_ context.Context, beforeMs int64, limit int) error {
	// The Repository contract refuses an unbounded delete batch, so a buggy
	// caller cannot stall the store — the real drivers all reject this.
	if limit <= 0 {
		return fmt.Errorf("integration: DeleteExpiredOAuthOneTimeCodes: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.oauthOneTimeCodes {
		if limit > 0 && n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.oauthOneTimeCodes, id)
			n++
		}
	}
	return nil
}

func (r *MemRepo) DeleteExpiredNativeTokenRedemptions(_ context.Context, beforeMs int64, limit int) error {
	// The Repository contract refuses an unbounded delete batch, so a buggy
	// caller cannot stall the store — the real drivers all reject this.
	if limit <= 0 {
		return fmt.Errorf("integration: DeleteExpiredNativeTokenRedemptions: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, e := range r.nativeRedemptions {
		if limit > 0 && n >= limit {
			break
		}
		if e.ExpiresAt < beforeMs {
			delete(r.nativeRedemptions, id)
			n++
		}
	}
	return nil
}

func (r *MemRepo) DeleteExpiredEmailLoginCodes(_ context.Context, beforeMs int64, limit int) error {
	// The Repository contract refuses an unbounded delete batch, so a buggy
	// caller cannot stall the store — the real drivers all reject this.
	if limit <= 0 {
		return fmt.Errorf("integration: DeleteExpiredEmailLoginCodes: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.emailLoginCodes {
		if limit > 0 && n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.emailLoginCodes, id)
			n++
		}
	}
	return nil
}

func (r *MemRepo) DeleteExpiredMagicLinkTokens(_ context.Context, beforeMs int64, limit int) error {
	// The Repository contract refuses an unbounded delete batch, so a buggy
	// caller cannot stall the store — the real drivers all reject this.
	if limit <= 0 {
		return fmt.Errorf("integration: DeleteExpiredMagicLinkTokens: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, tkn := range r.magicLinkTokens {
		if limit > 0 && n >= limit {
			break
		}
		if tkn.ExpiresAt < beforeMs {
			delete(r.magicLinkTokens, id)
			n++
		}
	}
	return nil
}

func (r *MemRepo) DeleteExpiredPhoneVerificationCodes(_ context.Context, beforeMs int64, limit int) error {
	// The Repository contract refuses an unbounded delete batch, so a buggy
	// caller cannot stall the store — the real drivers all reject this.
	if limit <= 0 {
		return fmt.Errorf("integration: DeleteExpiredPhoneVerificationCodes: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.phoneVerifyCodes {
		if limit > 0 && n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.phoneVerifyCodes, id)
			n++
		}
	}
	return nil
}

func (r *MemRepo) DeleteExpiredQrLoginSessions(_ context.Context, beforeMs int64, limit int) error {
	// The Repository contract refuses an unbounded delete batch, so a buggy
	// caller cannot stall the store — the real drivers all reject this.
	if limit <= 0 {
		return fmt.Errorf("integration: DeleteExpiredQrLoginSessions: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, s := range r.qrSessions {
		if limit > 0 && n >= limit {
			break
		}
		if s.ExpiresAt < beforeMs {
			delete(r.qrSessions, id)
			n++
		}
	}
	return nil
}

func (r *MemRepo) DeleteExpiredInvitations(_ context.Context, beforeMs int64, limit int) error {
	// The Repository contract refuses an unbounded delete batch, so a buggy
	// caller cannot stall the store — the real drivers all reject this.
	if limit <= 0 {
		return fmt.Errorf("integration: DeleteExpiredInvitations: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, inv := range r.invitations {
		if limit > 0 && n >= limit {
			break
		}
		if inv.ExpiresAt < beforeMs {
			delete(r.invitations, id)
			n++
		}
	}
	return nil
}

// ── Sessions ──────────────────────────────────────────────────────

func (r *MemRepo) CreateSession(_ context.Context, s *service.SessionRecord) (string, error) {
	if s == nil {
		return "", fmt.Errorf("%w: nil session", service.ErrInvalidArgument)
	}
	if s.SID == "" {
		return "", fmt.Errorf("%w: missing sid", service.ErrInvalidArgument)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions == nil {
		r.sessions = make(map[string]*service.SessionRecord)
	}
	for _, existing := range r.sessions {
		if existing.SID == s.SID {
			return "", fmt.Errorf("%w: sid %q", service.ErrAlreadyExists, s.SID)
		}
	}
	id := r.nextID()
	s.NodeID = id
	cp := *s
	r.sessions[id] = &cp
	return id, nil
}

func (r *MemRepo) GetSessionBySid(_ context.Context, sid string) (*service.SessionRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		if s.SID == sid {
			cp := *s
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) RevokeSession(_ context.Context, sid string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		if s.SID == sid && s.RevokedAtMs == 0 {
			s.RevokedAtMs = atMs
		}
	}
	return nil
}

func (r *MemRepo) RevokeSessionsForUser(_ context.Context, userID string, atMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		if s.UserID == userID && s.RevokedAtMs == 0 {
			s.RevokedAtMs = atMs
		}
	}
	return nil
}

// CountSessionsForUser is a test helper.
func (r *MemRepo) CountSessionsForUser(userID string) (active, revoked int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		if s.UserID != userID {
			continue
		}
		if s.RevokedAtMs == 0 {
			active++
		} else {
			revoked++
		}
	}
	return active, revoked
}

// compile-time interface assertion

// ── Client assurance (attested devices + one-shot challenges) ─────────
//
// The integration harness's MemRepo mirrors the memory driver's semantics:
// key_id is unique, the counter advances only via a compare-and-swap, and a
// challenge is consumed exactly once.

func (r *MemRepo) CreateAttestedDevice(_ context.Context, d *service.AttestedDeviceRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.attestedDevices == nil {
		r.attestedDevices = make(map[string]*service.AttestedDeviceRecord)
	}
	for _, existing := range r.attestedDevices {
		if existing.KeyID == d.KeyID {
			return "", fmt.Errorf("memrepo: CreateAttestedDevice: %w", service.ErrAlreadyExists)
		}
	}
	id := d.NodeID
	if id == "" {
		id = fmt.Sprintf("attdev-%d", len(r.attestedDevices)+1)
	}
	cp := *d
	cp.NodeID = id
	r.attestedDevices[id] = &cp
	d.NodeID = id
	return id, nil
}

func (r *MemRepo) GetAttestedDeviceByKeyID(_ context.Context, keyID string) (*service.AttestedDeviceRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.attestedDevices {
		if d.KeyID == keyID {
			cp := *d
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *MemRepo) UpdateAttestedDeviceCounter(_ context.Context, nodeID string, fromCount, toCount, lastUsedAtMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.attestedDevices[nodeID]
	if !ok {
		return fmt.Errorf("%w: attested device", service.ErrNotFound)
	}
	if d.SignCount != fromCount {
		return service.ErrCounterStale
	}
	d.SignCount = toCount
	d.LastUsedAt = lastUsedAtMs
	return nil
}

func (r *MemRepo) DeleteStaleAttestedDevices(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memrepo: DeleteStaleAttestedDevices: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, d := range r.attestedDevices {
		if n >= limit {
			break
		}
		if d.LastUsedAt < beforeMs {
			delete(r.attestedDevices, id)
			n++
		}
	}
	return nil
}

func (r *MemRepo) DeleteStaleAnonymousUsers(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memrepo: DeleteStaleAnonymousUsers: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// Oldest-first, matching the contract all three production drivers
	// implement — iterating the map directly would delete an arbitrary
	// subset once the batch limit bites, so a harness-backed test could
	// observe a different survivor than production produces.
	type victim struct {
		id          string
		lastLoginMs int64
	}
	stale := make([]victim, 0, limit)
	for id, u := range r.users {
		if u.IsAnonymous && u.AnonymousLastSeenMs < beforeMs {
			stale = append(stale, victim{id: id, lastLoginMs: u.AnonymousLastSeenMs})
		}
	}
	sort.Slice(stale, func(i, j int) bool {
		if stale[i].lastLoginMs != stale[j].lastLoginMs {
			return stale[i].lastLoginMs < stale[j].lastLoginMs
		}
		return stale[i].id < stale[j].id
	})
	if len(stale) > limit {
		stale = stale[:limit]
	}
	for _, v := range stale {
		// Drain the user-owned rows too: the SQL drivers get this from FK
		// cascades, so dropping only the users entry would leave orphans.
		r.deleteUserRowsLocked(v.id)
	}
	return nil
}

func (r *MemRepo) CreateAssuranceChallenge(_ context.Context, c *service.AssuranceChallengeRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.assuranceChallenges == nil {
		r.assuranceChallenges = make(map[string]*service.AssuranceChallengeRecord)
	}
	id := c.NodeID
	if id == "" {
		id = fmt.Sprintf("assurchal-%d", len(r.assuranceChallenges)+1)
	}
	cp := *c
	cp.NodeID = id
	r.assuranceChallenges[id] = &cp
	c.NodeID = id
	return id, nil
}

func (r *MemRepo) ConsumeAssuranceChallenge(_ context.Context, nodeID string) (*service.AssuranceChallengeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.assuranceChallenges[nodeID]
	if !ok {
		return nil, nil
	}
	delete(r.assuranceChallenges, nodeID)
	cp := *c
	return &cp, nil
}

func (r *MemRepo) DeleteExpiredAssuranceChallenges(_ context.Context, beforeMs int64, limit int) error {
	// The Repository contract refuses an unbounded delete batch, so a buggy
	// caller cannot stall the store — the real drivers all reject this.
	if limit <= 0 {
		return fmt.Errorf("memrepo: DeleteExpiredAssuranceChallenges: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, c := range r.assuranceChallenges {
		if n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.assuranceChallenges, id)
			n++
		}
	}
	return nil
}

var _ service.Repository = (*MemRepo)(nil)

// silence unused import when graph is only referenced via the
// service.DB stub; keep the import line stable for future replacement.
var _ = (*graph.Node)(nil)
