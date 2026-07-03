package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/graph"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/events"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/elloloop/identity/pkg/scim"
)

// fieldEventType is the graph data key the audit logger stamps the event type
// under (pkg/audit fieldEventType, unexported). Captured writes read it back to
// assert which audit event a SCIM mutation produced.
const fieldEventType = "1"

// captureNodeWriter records audit writes so a test can assert both the event
// type and the project the write landed under (ExecuteAtomic's tenant arg is
// the resolved project id — ADR-0002).
type captureNodeWriter struct {
	mu     sync.Mutex
	writes []auditWrite
}

type auditWrite struct {
	projectID string
	eventType string
}

func (w *captureNodeWriter) ExecuteAtomic(_ context.Context, projectID, _ string, ops []graph.Operation) (*graph.CommitResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, op := range ops {
		et, _ := op.Data[fieldEventType].(string)
		w.writes = append(w.writes, auditWrite{projectID: projectID, eventType: et})
	}
	return &graph.CommitResult{Success: true, Applied: true}, nil
}

func (w *captureNodeWriter) all() []auditWrite {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]auditWrite(nil), w.writes...)
}

// captureEventPublisher records emitted lifecycle events.
type captureEventPublisher struct {
	mu     sync.Mutex
	events []events.Event
}

func (p *captureEventPublisher) Emit(_ context.Context, e events.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, e)
	return nil
}

func (p *captureEventPublisher) all() []events.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]events.Event(nil), p.events...)
}

const scimEventTenantID = "tenant-x"

// newSCIMObservedHandler builds a SCIM handler wired to capture fakes for the
// audit log and the lifecycle-event publisher. The audit logger resolves its
// project from the request scope exactly like production (service.ScopedDB), so
// the handler's fixed-scope override is exercised end-to-end.
func newSCIMObservedHandler(t *testing.T) (http.Handler, service.Repository, *captureEventPublisher, *captureNodeWriter) {
	t.Helper()
	repo := memory.New()
	aud := &captureNodeWriter{}
	auditLog := audit.NewLogger(aud, testSCIMProjectID, zap.NewNop()).
		WithProjectScoper(func(ctx context.Context) (audit.NodeWriter, string) {
			pid := testSCIMProjectID
			if sc := service.ProjectScopeFromContext(ctx); sc != nil && sc.ProjectID != "" {
				pid = sc.ProjectID
			}
			return aud, pid
		})
	pub := &captureEventPublisher{}
	mux := http.NewServeMux()
	(&scimHandler{
		repo:        repo,
		projectID:   testSCIMProjectID,
		bearerToken: testSCIMToken,
		audit:       auditLog,
		publisher:   pub,
		tenantID:    scimEventTenantID,
		logger:      zap.NewNop(),
	}).register(mux, true)
	return mux, service.ProjectBoundRepository(repo, testSCIMProjectID), pub, aud
}

// TestSCIM_EmitsAuditAndLifecycleEvents is the #302 invariant: a SCIM
// create/deactivate/delete records the SAME audit entries and emits the SAME
// user.* lifecycle events as the equivalent admin/gRPC operation — so a SCIM
// offboard fires the downstream-deprovisioning webhooks.
func TestSCIM_EmitsAuditAndLifecycleEvents(t *testing.T) {
	h, _, pub, aud := newSCIMObservedHandler(t)

	// Create → user.created event + user_invited audit.
	rec := scimReq(t, h, http.MethodPost, "/scim/v2/Users", testSCIMToken, `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"eve@example.com","active":true
	}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("create returned no id: %v", created)
	}

	evs := pub.all()
	if len(evs) != 1 || evs[0].Type != events.EventUserCreated {
		t.Fatalf("after create: events = %+v, want one user.created", evs)
	}
	if evs[0].User.Email != "eve@example.com" {
		t.Fatalf("user.created email = %q", evs[0].User.Email)
	}
	if evs[0].ProjectID != testSCIMProjectID || evs[0].TenantID != scimEventTenantID {
		t.Fatalf("user.created scope = project %q tenant %q", evs[0].ProjectID, evs[0].TenantID)
	}
	if evs[0].ID == "" {
		t.Fatal("user.created must carry an id for idempotency")
	}
	assertAuditWrite(t, aud, "user_invited")

	// PATCH active:false → user.deactivated event + user_deactivated audit.
	rec = scimReq(t, h, http.MethodPatch, "/scim/v2/Users/"+id, testSCIMToken, `{
		"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"active","value":false}]
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("deactivate status = %d body=%s", rec.Code, rec.Body.String())
	}
	evs = pub.all()
	if len(evs) != 2 || evs[1].Type != events.EventUserDeactivated {
		t.Fatalf("after deactivate: events = %+v, want user.deactivated", evs)
	}
	if evs[1].User.Status != "deactivated" {
		t.Fatalf("user.deactivated status = %q, want deactivated", evs[1].User.Status)
	}
	assertAuditWrite(t, aud, "user_deactivated")

	// DELETE → user.deactivated event (a hard delete is a deprovision signal) +
	// user_deleted audit.
	rec = scimReq(t, h, http.MethodDelete, "/scim/v2/Users/"+id, testSCIMToken, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", rec.Code)
	}
	evs = pub.all()
	if len(evs) != 3 || evs[2].Type != events.EventUserDeactivated {
		t.Fatalf("after delete: events = %+v, want user.deactivated", evs)
	}
	assertAuditWrite(t, aud, "user_deleted")

	// Every audit write must attribute to the configured SCIM project.
	for _, w := range aud.all() {
		if w.projectID != testSCIMProjectID {
			t.Fatalf("audit %q landed under project %q, want %q", w.eventType, w.projectID, testSCIMProjectID)
		}
	}
}

// TestSCIM_ReactivateEmitsUpdated asserts a PATCH active:true on a deactivated
// user records a user_reactivated audit entry and emits user.updated.
func TestSCIM_ReactivateEmitsUpdated(t *testing.T) {
	h, repo, pub, aud := newSCIMObservedHandler(t)
	ctx := context.Background()
	id, err := repo.CreateUser(ctx, &service.User{Email: "re@example.com", Status: "deactivated", Role: "member"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := scimReq(t, h, http.MethodPatch, "/scim/v2/Users/"+id, testSCIMToken, `{
		"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"active","value":true}]
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("reactivate status = %d body=%s", rec.Code, rec.Body.String())
	}
	evs := pub.all()
	if len(evs) != 1 || evs[0].Type != events.EventUserUpdated {
		t.Fatalf("reactivate events = %+v, want one user.updated", evs)
	}
	assertAuditWrite(t, aud, "user_reactivated")
}

// TestSCIM_AuditAttributionOverridesForgedScope asserts the handler's fixed
// project scope wins over a foreign ProjectScope forged on the request: the
// audit write must attribute to GATEWAY_SCIM_PROJECT_ID, never the forged one.
func TestSCIM_AuditAttributionOverridesForgedScope(t *testing.T) {
	h, _, _, aud := newSCIMObservedHandler(t)

	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"v@example.com","active":true}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testSCIMToken)
	req = req.WithContext(service.WithProjectScope(req.Context(),
		&service.ProjectScope{ProjectID: "attacker-project"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", rec.Code, rec.Body.String())
	}
	writes := aud.all()
	if len(writes) != 1 || writes[0].projectID != testSCIMProjectID {
		t.Fatalf("audit writes = %+v, want one under %q", writes, testSCIMProjectID)
	}
}

func assertAuditWrite(t *testing.T, aud *captureNodeWriter, eventType string) {
	t.Helper()
	for _, w := range aud.all() {
		if w.eventType == eventType {
			return
		}
	}
	t.Fatalf("no audit write of type %q found in %+v", eventType, aud.all())
}

// countingListRepo records how many times CountUsers / ListUsers run so a test
// can prove the count=0 path never issues the page SELECT.
type countingListRepo struct {
	service.StubRepository
	countCalls int
	listCalls  int
	total      int
}

func (r *countingListRepo) CountUsers(context.Context, service.UserListFilter) (int, error) {
	r.countCalls++
	return r.total, nil
}

func (r *countingListRepo) ListUsers(context.Context, service.UserListFilter) ([]*service.User, error) {
	r.listCalls++
	return nil, nil
}

// TestSCIM_ListCountZeroShortCircuits asserts count=0 runs the count query only
// and skips the discarded page SELECT, while a positive count still pages.
func TestSCIM_ListCountZeroShortCircuits(t *testing.T) {
	ctx := context.Background()

	r := &countingListRepo{total: 42}
	s := &repoSCIMStore{repo: r}
	users, total, err := s.ListUsers(ctx, scim.ListFilter{Count: 0, StartIndex: 1})
	if err != nil {
		t.Fatalf("count=0 list: %v", err)
	}
	if total != 42 || len(users) != 0 {
		t.Fatalf("count=0 → total=%d users=%d, want 42/0", total, len(users))
	}
	if r.countCalls != 1 || r.listCalls != 0 {
		t.Fatalf("count=0 must query count only: countCalls=%d listCalls=%d", r.countCalls, r.listCalls)
	}

	r = &countingListRepo{total: 42}
	s = &repoSCIMStore{repo: r}
	if _, _, err := s.ListUsers(ctx, scim.ListFilter{Count: 10, StartIndex: 1}); err != nil {
		t.Fatalf("count=10 list: %v", err)
	}
	if r.listCalls != 1 {
		t.Fatalf("positive count must page: listCalls=%d, want 1", r.listCalls)
	}
}

// fakeNativeProjects is a control-plane project-by-id lookup for the SCIM
// boot-validation test.
type fakeNativeProjects struct {
	proj *service.AdminProject
	err  error
}

func (f fakeNativeProjects) ActiveProjectByID(context.Context, string) (*service.AdminProject, error) {
	return f.proj, f.err
}

func scimBootConfig() *config.Config {
	cfg := eventsTestConfig()
	cfg.SCIMEnabled = true
	cfg.SCIMBearerToken = strings.Repeat("s", config.MinSCIMBearerTokenLength+8)
	cfg.SCIMProjectID = "scim-project"
	return cfg
}

func newSCIMBootApp(t *testing.T, cfg *config.Config, lookup service.NativeOAuthProjectStore) (*Built, error) {
	t.Helper()
	signer := jwttest.NewSigner(t, "scim-boot")
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Identity Test", Origin: "http://localhost:9002"})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	repo := memory.New()
	return New(Deps{
		Config:              cfg,
		Logger:              zap.NewNop(),
		Signer:              signer,
		Repo:                repo,
		DB:                  repo,
		Passkeys:            pk,
		TOTPKey:             []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper:  []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		NativeOAuthProjects: lookup,
	})
}

// TestSCIM_BootValidatesProject asserts GATEWAY_SCIM_PROJECT_ID is verified at
// BOOT: a typo (no such active project) fails startup with a clear error rather
// than 500-ing on the first request, an infrastructure failure is surfaced, a
// real active project boots, and a driver without a control plane skips the
// check.
func TestSCIM_BootValidatesProject(t *testing.T) {
	t.Run("unknown project id fails startup", func(t *testing.T) {
		_, err := newSCIMBootApp(t, scimBootConfig(), fakeNativeProjects{proj: nil})
		if err == nil || !strings.Contains(err.Error(), "does not name an active project") {
			t.Fatalf("boot error = %v, want unknown-project failure", err)
		}
	})

	t.Run("lookup error fails startup", func(t *testing.T) {
		_, err := newSCIMBootApp(t, scimBootConfig(), fakeNativeProjects{err: errors.New("db down")})
		if err == nil || !strings.Contains(err.Error(), "verify GATEWAY_SCIM_PROJECT_ID") {
			t.Fatalf("boot error = %v, want lookup-failure", err)
		}
	})

	t.Run("active project boots", func(t *testing.T) {
		built, err := newSCIMBootApp(t, scimBootConfig(), fakeNativeProjects{proj: &service.AdminProject{ID: "scim-project"}})
		if err != nil {
			t.Fatalf("boot with active project: %v", err)
		}
		built.Stop()
	})

	t.Run("no control plane skips the check", func(t *testing.T) {
		// nil lookup = memory driver: nothing to verify against, boot proceeds.
		built, err := newSCIMBootApp(t, scimBootConfig(), nil)
		if err != nil {
			t.Fatalf("boot without control plane: %v", err)
		}
		built.Stop()
	})
}
