package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// fakeManagedHelp is a ManagedHelpStore the test programs; it records what
// it was asked.
type fakeManagedHelp struct {
	t      *testing.T
	record func(ManagedHelpRequest) (*ManagedHelpRecorded, error)
	asked  []ManagedHelpRequest
}

func (f *fakeManagedHelp) RecordManagedHelp(_ context.Context, req ManagedHelpRequest) (*ManagedHelpRecorded, error) {
	require.NotNil(f.t, f.record, "RecordManagedHelp called")
	f.asked = append(f.asked, req)
	return f.record(req)
}

type managedHelpFixture struct {
	svc    *AuthService
	rec    *recordingTransport
	store  *fakeManagedHelp
	audit  *recordingAuditWriter
	filed  int
	routed func(address string)
}

func newManagedHelpFixture(t *testing.T) *managedHelpFixture {
	t.Helper()
	svc, rec := newAuthSvcWithMailerForRepo(t, newFakeRepo())
	svc.cfg.ManagedAccountsEnabled = true
	w := newRecordingAuditWriter()
	svc.audit = audit.NewLogger(w, "test", zap.NewNop())
	store := &fakeManagedHelp{t: t}
	svc.WithManagedHelp(store)
	f := &managedHelpFixture{svc: svc, rec: rec, store: store, audit: w}
	f.routed = func(address string) {
		svc.RouteAdminHelp(context.Background(), address, "203.0.113.7", "test-agent", func(context.Context) { f.filed++ })
	}
	return f
}

func managedHelpRecord(outcome string) *ManagedHelpRecorded {
	rec := &ManagedHelpRecorded{
		Account:  &User{ID: "u-ann", Email: "ann@acme.example.com", Name: "Ann", ManagedByTenantID: "t-acme"},
		TenantID: "t-acme",
		Outcome:  outcome,
	}
	if outcome == ManagedHelpNotify {
		rec.Recipients = []*User{
			{ID: "u-owner", Email: "owner@acme.example.com", Name: "Olive"},
			{ID: "u-admin", Email: "admin@acme.example.com"},
		}
	}
	return rec
}

func TestRouteAdminHelp_ManagedAccountTellsItsTenant(t *testing.T) {
	f := newManagedHelpFixture(t)
	f.store.record = func(ManagedHelpRequest) (*ManagedHelpRecorded, error) {
		return managedHelpRecord(ManagedHelpNotify), nil
	}

	f.routed(" Ann@Acme.Example.com ")

	assert.Zero(t, f.filed, "the project's admins are not asked")
	require.Len(t, f.store.asked, 1)
	asked := f.store.asked[0]
	assert.Equal(t, "ann@acme.example.com", asked.Address)
	assert.Equal(t, sha256Hex("203.0.113.7"), asked.SourceKey, "the source is kept only as a hash")
	assert.Equal(t, asked.NowMs-managedHelpWindow.Milliseconds(), asked.SinceMs)
	assert.Equal(t, f.svc.cfg.ManagedHelpTenantLimit(), asked.MaxPerTenant)
	assert.Equal(t, f.svc.cfg.ManagedHelpSourceLimit(), asked.MaxPerTenantSource)

	sent := f.rec.Sent()
	require.Len(t, sent, 2)
	assert.Equal(t, "owner@acme.example.com", sent[0].To)
	assert.Equal(t, "admin@acme.example.com", sent[1].To)
	for _, m := range sent {
		assert.Contains(t, m.Text, "ann@acme.example.com")
		assert.NotContains(t, m.Text, "203.0.113.7")
		assert.NotContains(t, m.Text, "test-agent")
	}
	assert.Contains(t, sent[0].Text, "Olive")

	assert.Equal(t, 1, f.audit.countByEventTypeActorTarget(string(audit.EventManagedAccountHelpRequested), "", "u-ann"))
	assert.Equal(t, []map[string]any{{"tenant_id": "t-acme", "outcome": ManagedHelpNotify, "recipients": float64(2)}},
		f.audit.detailsOf(string(audit.EventManagedAccountHelpRequested)))
	assert.Equal(t, [][2]string{{"203.0.113.7", "test-agent"}}, f.audit.clientsOf(string(audit.EventManagedAccountHelpRequested)))
}

func TestRouteAdminHelp_NoNoticeOutsideTheCaps(t *testing.T) {
	for outcome, audited := range map[string]int{
		ManagedHelpDuplicate:     0,
		ManagedHelpTenantLimited: 1,
		ManagedHelpSourceLimited: 1,
	} {
		t.Run(outcome, func(t *testing.T) {
			f := newManagedHelpFixture(t)
			f.store.record = func(ManagedHelpRequest) (*ManagedHelpRecorded, error) { return managedHelpRecord(outcome), nil }

			f.routed("ann@acme.example.com")

			assert.Zero(t, f.filed)
			assert.Empty(t, f.rec.Sent())
			assert.Equal(t, audited, f.audit.countByEventType(string(audit.EventManagedAccountHelpRequested)))
		})
	}
}

func TestRouteAdminHelp_AnythingElseIsFiledForTheProject(t *testing.T) {
	f := newManagedHelpFixture(t)
	f.store.record = func(ManagedHelpRequest) (*ManagedHelpRecorded, error) { return nil, ErrNotFound }

	f.routed("bo@example.com")
	f.routed("not an address")

	assert.Equal(t, 2, f.filed)
	assert.Len(t, f.store.asked, 1, "an unusable address is not looked up")
	assert.Empty(t, f.rec.Sent())
}

func TestRouteAdminHelp_StoreErrorFilesNothing(t *testing.T) {
	f := newManagedHelpFixture(t)
	f.store.record = func(ManagedHelpRequest) (*ManagedHelpRecorded, error) { return nil, errors.New("boom") }

	f.routed("ann@acme.example.com")

	assert.Zero(t, f.filed, "a request that may be about a managed account never reaches the project's admins")
	assert.Empty(t, f.rec.Sent())
}

func TestRouteAdminHelp_FilesAtOnceWhenOff(t *testing.T) {
	for name, mutate := range map[string]func(*managedHelpFixture){
		"flag off": func(f *managedHelpFixture) { f.svc.cfg.ManagedAccountsEnabled = false },
		"no store": func(f *managedHelpFixture) { f.svc.WithManagedHelp(nil) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newManagedHelpFixture(t)
			mutate(f)

			f.routed("ann@acme.example.com")

			assert.Equal(t, 1, f.filed)
			assert.Empty(t, f.store.asked)
		})
	}
}

func TestRouteAdminHelp_FilesAtOnceWhenTheProjectSendsNoEmail(t *testing.T) {
	f := newManagedHelpFixture(t)
	ctx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "p", EmailDelivery: ProjectEmailDeliveryConfig{Disabled: true},
	})

	f.svc.RouteAdminHelp(ctx, "ann@acme.example.com", "203.0.113.7", "test-agent", func(context.Context) { f.filed++ })

	assert.Equal(t, 1, f.filed)
	assert.Empty(t, f.store.asked)
}

func TestRouteAdminHelp_ASendFailureIsLogged(t *testing.T) {
	f := newManagedHelpFixture(t)
	f.store.record = func(ManagedHelpRequest) (*ManagedHelpRecorded, error) {
		return managedHelpRecord(ManagedHelpNotify), nil
	}
	f.rec.fail = errors.New("smtp down")

	f.routed("ann@acme.example.com")

	assert.Zero(t, f.filed)
	assert.Equal(t, 1, f.audit.countByEventType(string(audit.EventManagedAccountHelpRequested)))
}

func TestHelpService_RequestAdminHelp_GoesThroughTheRouter(t *testing.T) {
	db := newFakeDB()
	router := &recordingRouter{}
	svc := newTestHelpService(db).WithAdminHelpRouter(router)

	require.NoError(t, svc.RequestAdminHelp(context.Background(), " Ann@Acme.Example.com ", "help me", "203.0.113.7", "test-agent"))
	assert.Equal(t, []string{"ann@acme.example.com|203.0.113.7|test-agent"}, router.calls)
	nodes, _ := db.QueryNodes(context.Background(), "", "", typeAdminHelpReq, nil)
	assert.Empty(t, nodes, "nothing is filed until the router says so")

	router.file(context.Background())
	nodes, _ = db.QueryNodes(context.Background(), "", "", typeAdminHelpReq, nil)
	require.Len(t, nodes, 1)
	assert.Equal(t, "help me", pstr(nodes[0].Payload, hfReason))
}

type recordingRouter struct {
	calls []string
	file  func(context.Context)
}

func (r *recordingRouter) RouteAdminHelp(_ context.Context, address, sourceIP, userAgent string, ordinary func(context.Context)) {
	r.calls = append(r.calls, address+"|"+sourceIP+"|"+userAgent)
	r.file = ordinary
}
