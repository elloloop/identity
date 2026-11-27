package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus/testutil"
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
		svc.RouteAdminHelp(context.Background(), address, "locked out", "203.0.113.7", "test-agent", func(context.Context) { f.filed++ })
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
	assert.Equal(t, f.svc.managedHelpSourceKey("203.0.113.7"), asked.SourceKey, "the source is kept only as a keyed hash")
	assert.NotContains(t, asked.SourceKey, "203.0.113.7")
	assert.Equal(t, asked.NowMs-managedHelpWindow.Milliseconds(), asked.SinceMs)
	assert.Equal(t, f.svc.cfg.ManagedHelpTenantLimit(), asked.MaxPerTenant)
	assert.Equal(t, f.svc.cfg.ManagedHelpSourceLimit(), asked.MaxPerTenantSource)

	sent := f.rec.Sent()
	require.Len(t, sent, 2)
	assert.Equal(t, "owner@acme.example.com", sent[0].To)
	assert.Equal(t, "admin@acme.example.com", sent[1].To)
	for _, m := range sent {
		assert.Equal(t, "Ann asked for help signing in", m.Subject)
		assert.Contains(t, m.Text, "Ann (ann@acme.example.com) asked for help signing in.")
		assert.NotContains(t, m.Text, "Open Members", "no members page configured, no button")
		assert.NotContains(t, m.Text, "203.0.113.7")
		assert.NotContains(t, m.Text, "test-agent")
		assert.NotContains(t, m.Text, "locked out", "the caller's reason stays in the audit entry")
	}
	assert.Contains(t, sent[0].Text, "Olive")

	assert.Equal(t, 1, f.audit.countByEventTypeActorTarget(string(audit.EventManagedAccountHelpRequested), "", "u-ann"))
	assert.Equal(t, []map[string]any{{"tenant_id": "t-acme", "outcome": ManagedHelpNotify, "recipients": float64(2), "reason": "locked out"}},
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
			_, err := f.svc.WithManagedHelpMetrics(nil)
			require.NoError(t, err)
			f.store.record = func(ManagedHelpRequest) (*ManagedHelpRecorded, error) { return managedHelpRecord(outcome), nil }

			f.routed("ann@acme.example.com")

			assert.Zero(t, f.filed)
			assert.Empty(t, f.rec.Sent())
			assert.Equal(t, audited, f.audit.countByEventType(string(audit.EventManagedAccountHelpRequested)))
			assert.InDelta(t, float64(audited), testutil.ToFloat64(f.svc.managedHelpLimited.WithLabelValues(outcome)), 0,
				"a cap's refusal is counted as identity_managed_help_limited_total; a duplicate is not")
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

	assert.Zero(t, f.filed, "a request the store could not judge is not filed for the project's admins")
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

	f.svc.RouteAdminHelp(ctx, "ann@acme.example.com", "locked out", "203.0.113.7", "test-agent", func(context.Context) { f.filed++ })

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
	assert.Equal(t, []string{"ann@acme.example.com|help me|203.0.113.7|test-agent"}, router.calls)
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

func (r *recordingRouter) RouteAdminHelp(_ context.Context, address, reason, sourceIP, userAgent string, ordinary func(context.Context)) {
	r.calls = append(r.calls, address+"|"+reason+"|"+sourceIP+"|"+userAgent)
	r.file = ordinary
}

// A tenant with no active owner or admin to tell hands the request to the
// project's admins.
func TestRouteAdminHelp_NoRecipientsFilesForTheProject(t *testing.T) {
	f := newManagedHelpFixture(t)
	f.store.record = func(ManagedHelpRequest) (*ManagedHelpRecorded, error) {
		rec := managedHelpRecord(ManagedHelpNoRecipients)
		return rec, nil
	}

	f.routed("ann@acme.example.com")

	assert.Equal(t, 1, f.filed)
	assert.Empty(t, f.rec.Sent())
	assert.Zero(t, f.audit.countByEventType(string(audit.EventManagedAccountHelpRequested)))
}

// A dispatch that is dropped still files the request: every slot taken, or
// the project's email policy failing to load where the dispatch runs.
func TestRouteAdminHelp_ADroppedDispatchStillFiles(t *testing.T) {
	t.Run("every slot taken", func(t *testing.T) {
		f := newManagedHelpFixture(t)
		_, err := f.svc.WithAsyncEmailDispatch(nil)
		require.NoError(t, err)
		for range cap(f.svc.emailSendSlots) {
			f.svc.emailSendSlots <- struct{}{}
		}
		f.routed("ann@acme.example.com")
		assert.Equal(t, 1, f.filed, "filed inline")
		assert.Empty(t, f.store.asked)
	})
	t.Run("policy lookup fails", func(t *testing.T) {
		f := newManagedHelpFixture(t)
		f.svc.activeProjects = failingActiveProjects{}
		f.routed("ann@acme.example.com")
		assert.Equal(t, 1, f.filed)
		assert.Empty(t, f.store.asked)
	})
}

// failingActiveProjects is an ActiveProjectStore whose reads fail.
type failingActiveProjects struct{}

func (failingActiveProjects) ActiveProjectByID(context.Context, string) (*AdminProject, error) {
	return nil, errors.New("control plane down")
}

func TestManagedHelpSourceKey(t *testing.T) {
	f := newManagedHelpFixture(t)
	key := f.svc.managedHelpSourceKey
	assert.Equal(t, key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff::9"), "one /64 is one source")
	assert.NotEqual(t, key("2001:db8:1:2::1"), key("2001:db8:1:3::1"))
	assert.Equal(t, key("203.0.113.7"), key("::ffff:203.0.113.7"), "a mapped IPv4 address is the address")
	assert.NotEqual(t, key("203.0.113.7"), key("203.0.113.8"))
	assert.NotEqual(t, sha256Hex("203.0.113.7"), key("203.0.113.7"), "keyed with the server secret")
	other, _ := newAuthSvcWithMailerForRepo(t, newFakeRepo())
	other.totpRecoveryPepper = []byte("another-server-secret-of-enough-length!")
	assert.NotEqual(t, key("203.0.113.7"), other.managedHelpSourceKey("203.0.113.7"), "another secret, another key")

	assert.Equal(t, "2001:db8:1:2::/64", normalizeHelpSource("2001:db8:1:2::1%eth0"))
	assert.Equal(t, "not an address", normalizeHelpSource("not an address"))
}

// The notice names the account by its stored display name and address and
// links to the tenant's members page; an account with no name is named by
// its address alone.
func TestManagedHelpNotice_NamesTheAccountAndLinksToMembers(t *testing.T) {
	f := newManagedHelpFixture(t)
	f.svc.cfg.TenantMembersPageURL = "https://app.example.com/settings/members"
	f.store.record = func(ManagedHelpRequest) (*ManagedHelpRecorded, error) {
		return managedHelpRecord(ManagedHelpNotify), nil
	}

	f.routed("ann@acme.example.com")

	sent := f.rec.Sent()
	require.Len(t, sent, 2)
	for _, m := range sent {
		assert.Equal(t, "Ann asked for help signing in", m.Subject)
		assert.Contains(t, m.Text, "Ann (ann@acme.example.com) asked for help signing in.")
		assert.Contains(t, m.Text, "Open Members: https://app.example.com/settings/members?tenant_id=t-acme")
		assert.Contains(t, m.HTML, `href="https://app.example.com/settings/members?tenant_id=t-acme"`)
		assert.Contains(t, m.HTML, ">Open Members</a>")
	}

	rec := managedHelpRecord(ManagedHelpNotify)
	rec.Account.Name = "  "
	notice := managedHelpNotice(f.svc.cfg, rec)
	assert.Equal(t, "ann@acme.example.com asked for help signing in", notice.headline)
	assert.Equal(t, "ann@acme.example.com asked for help signing in.", notice.detail)
}

// The reason is normalised once: the router and the filed request see the
// same trimmed reason, cut to helpReasonMaxBytes on a character boundary.
func TestHelpReason(t *testing.T) {
	assert.Equal(t, "help me", helpReason("  help me \n"))
	long := strings.Repeat("a", helpReasonMaxBytes-1) + "é" + "tail"
	got := helpReason(long)
	assert.Equal(t, strings.Repeat("a", helpReasonMaxBytes-1), got, "a split character is dropped whole")
	assert.True(t, utf8.ValidString(got))
	assert.LessOrEqual(t, len(helpReason(strings.Repeat("ü", 2000))), helpReasonMaxBytes)

	db := newFakeDB()
	svc := newTestHelpService(db)
	require.NoError(t, svc.RequestAdminHelp(context.Background(), "ann@acme.example.com", "  locked out  ", "203.0.113.7", "test-agent"))
	nodes, err := db.QueryNodes(context.Background(), "", "", typeAdminHelpReq, nil)
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	assert.Equal(t, "locked out", nodes[0].Payload[hfReason], "the filed request keeps the same reason")

	router := &recordingRouter{}
	svc = newTestHelpService(newFakeDB()).WithAdminHelpRouter(router)
	require.NoError(t, svc.RequestAdminHelp(context.Background(), "ann@acme.example.com", "  locked out  ", "203.0.113.7", "test-agent"))
	assert.Equal(t, []string{"ann@acme.example.com|locked out|203.0.113.7|test-agent"}, router.calls)
}
