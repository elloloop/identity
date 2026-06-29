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
	oauthRegistry *oauth.Registry
	config        func(*config.Config)
	idvProvider   idv.Provider
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
	oauthRegistry *oauth.Registry,
	idvProvider idv.Provider,
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
		Config:             cfg,
		Logger:             zap.NewNop(),
		Signer:             signer,
		Repo:               repo,
		DB:                 db,
		Passkeys:           pkSvc,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		EmailTransport:     mailer,
		OAuthRegistry:      oauthRegistry,
		IDVProvider:        idvProvider,
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
func newTestConfig() *config.Config {
	return &config.Config{
		DefaultTenantID:                 "test-tenant",
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
	mu sync.Mutex

	seq                int64
	users              map[string]*service.User
	refreshTokens      map[string]*service.RefreshTokenRecord
	passkeyCreds       map[string]*service.PasskeyCredRecord
	passkeyChallenges  map[string]*service.PasskeyChallengeRecord
	qrSessions         map[string]*service.QrLoginSessionRecord
	oauthOneTimeCodes  map[string]*service.OAuthOneTimeCodeRecord
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
	sessions           map[string]*service.SessionRecord
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

func (r *MemRepo) FindUserByExternalID(_ context.Context, externalID string) (*service.User, error) {
	if externalID == "" {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.ExternalID == externalID {
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
		if existing.Email == u.Email {
			return "", fmt.Errorf("user %q already exists", u.Email)
		}
		if u.ExternalID != "" && existing.ExternalID == u.ExternalID {
			return "", fmt.Errorf("external_id %q: %w", u.ExternalID, service.ErrAlreadyExists)
		}
	}
	id := r.nextID()
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
	delete(r.users, userID)
	return nil
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

func applyUserFields(u *service.User, fields map[string]any) {
	for k, v := range fields {
		switch k {
		case "name":
			u.Name, _ = v.(string)
		case "email":
			u.Email, _ = v.(string)
		case "avatar_url":
			u.AvatarURL, _ = v.(string)
		case "password_hash":
			u.PasswordHash, _ = v.(string)
		case "status":
			u.Status, _ = v.(string)
		case "totp_required":
			u.TotpRequired, _ = v.(bool)
		case "failed_login_count":
			switch x := v.(type) {
			case int:
				u.FailedLoginCount = x
			case int64:
				u.FailedLoginCount = int(x)
			}
		case "locked_until":
			switch x := v.(type) {
			case int64:
				u.LockedUntil = x
			case int:
				u.LockedUntil = int64(x)
			}
		case "updated_at":
			if x, ok := v.(int64); ok {
				u.UpdatedAt = time.UnixMilli(x)
			}
		case "last_login_at":
			if x, ok := v.(int64); ok {
				u.LastLoginAtMs = x
			}
		case "recovery_email":
			u.RecoveryEmail, _ = v.(string)
		case "external_id":
			u.ExternalID, _ = v.(string)
		case "email_verified":
			if b, ok := v.(bool); ok {
				u.EmailVerified = b
			}
		case "email_verified_at":
			switch x := v.(type) {
			case int64:
				u.EmailVerifiedAt = x
			case int:
				u.EmailVerifiedAt = int64(x)
			}
		}
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
	// Enforce uniqueness across users.
	for id, other := range r.users {
		if id != userID && other.Email == newEmail {
			return fmt.Errorf("email %q already in use", newEmail)
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

func (r *MemRepo) DeleteExpiredWebAuthnChallenges(_ context.Context, beforeMs int64, limit int) error {
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

func (r *MemRepo) DeleteExpiredEmailLoginCodes(_ context.Context, beforeMs int64, limit int) error {
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
	return
}

// compile-time interface assertion
var _ service.Repository = (*MemRepo)(nil)

// silence unused import when graph is only referenced via the
// service.DB stub; keep the import line stable for future replacement.
var _ = (*graph.Node)(nil)
