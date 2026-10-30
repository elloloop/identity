package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/elloloop/identity/pkg/audit"
)

// seedTenants puts n tenants into project, created one millisecond apart
// starting at 1000, with ids t-000 … in creation order, cycling through the
// three statuses so a listing is seen to keep every one.
func seedTenants(f *adminFixture, project string, n int) {
	statuses := []string{TenantStatusClaimed, TenantStatusLatent, TenantStatusSuspended}
	for i := 0; i < n; i++ {
		f.tenants.put(&Tenant{
			ID:          fmt.Sprintf("t-%03d", i),
			ProjectID:   project,
			Name:        fmt.Sprintf("Tenant %d", i),
			Status:      statuses[i%len(statuses)],
			CreatedAtMs: int64(1000 + i),
			UpdatedAtMs: int64(1000 + i),
		})
	}
}

func tenantIDs(ts []*Tenant) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.ID)
	}
	return out
}

func TestAdminTenantReads_Gated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	disabled := newAdminFixture("")
	if _, err := disabled.svc.AdminGetTenant(ctx, asAdmin("anything"), "proj", "t"); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("AdminGetTenant disabled: err = %v, want ErrUnimplemented", err)
	}
	if _, err := disabled.svc.AdminListTenants(ctx, asAdmin("anything"), "proj", 0, ""); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("AdminListTenants disabled: err = %v, want ErrUnimplemented", err)
	}

	f := newAdminFixture(testAdminSecret)
	seedTenants(f, "proj", 1)
	for _, presented := range []string{"", "wrong", testAdminSecret + "x"} {
		if _, err := f.svc.AdminGetTenant(ctx, asAdmin(presented), "proj", "t-000"); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("AdminGetTenant(secret=%q): err = %v, want ErrPermissionDenied", presented, err)
		}
		if _, err := f.svc.AdminListTenants(ctx, asAdmin(presented), "proj", 0, ""); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("AdminListTenants(secret=%q): err = %v, want ErrPermissionDenied", presented, err)
		}
	}
}

func TestAdminGetTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newAdminFixture(testAdminSecret)
	f.tenants.put(&Tenant{
		ID: "t-1", ProjectID: "proj", Name: "Acme", PrimaryDomain: "acme.example",
		Status: TenantStatusSuspended, CreatedBy: "u-1", CreatedAtMs: 10, UpdatedAtMs: 20,
	})

	got, err := f.svc.AdminGetTenant(ctx, asAdmin(testAdminSecret), " proj ", " t-1 ")
	if err != nil {
		t.Fatalf("AdminGetTenant: %v", err)
	}
	want := Tenant{
		ID: "t-1", ProjectID: "proj", Name: "Acme", PrimaryDomain: "acme.example",
		Status: TenantStatusSuspended, CreatedBy: "u-1", CreatedAtMs: 10, UpdatedAtMs: 20,
	}
	if *got != want {
		t.Fatalf("AdminGetTenant = %+v, want %+v", *got, want)
	}

	if _, err := f.svc.AdminGetTenant(ctx, asAdmin(testAdminSecret), "proj", "t-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown tenant: err = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.AdminGetTenant(ctx, asAdmin(testAdminSecret), "other-proj", "t-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another project's tenant: err = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.AdminGetTenant(ctx, asAdmin(testAdminSecret), "  ", "t-1"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank project: err = %v, want ErrInvalidArgument", err)
	}
	if _, err := f.svc.AdminGetTenant(ctx, asAdmin(testAdminSecret), "proj", "  "); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank tenant: err = %v, want ErrInvalidArgument", err)
	}

	boom := errors.New("boom")
	f.tenants.getErr = boom
	if _, err := f.svc.AdminGetTenant(ctx, asAdmin(testAdminSecret), "proj", "t-1"); !errors.Is(err, boom) {
		t.Fatalf("store error: err = %v, want %v", err, boom)
	}
}

func TestAdminListTenants_PagesNewestFirstThroughEveryStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newAdminFixture(testAdminSecret)
	seedTenants(f, "proj", 5)
	seedTenants(f, "other-proj", 3)
	// Two tenants created in the same millisecond are ordered by id, so a
	// page boundary between them neither repeats nor skips one.
	f.tenants.put(&Tenant{ID: "t-tie-a", ProjectID: "proj", Status: TenantStatusClaimed, CreatedAtMs: 1002})
	f.tenants.put(&Tenant{ID: "t-tie-b", ProjectID: "proj", Status: TenantStatusClaimed, CreatedAtMs: 1002})

	var got []string
	statuses := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page, err := f.svc.AdminListTenants(ctx, asAdmin(testAdminSecret), "proj", 2, cursor)
		if err != nil {
			t.Fatalf("AdminListTenants page %d: %v", pages, err)
		}
		pages++
		if len(page.Tenants) > 2 {
			t.Fatalf("page %d holds %d tenants, want at most 2", pages, len(page.Tenants))
		}
		for _, tn := range page.Tenants {
			got = append(got, tn.ID)
			statuses[tn.Status] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
		if pages > 10 {
			t.Fatal("listing never ended")
		}
	}

	want := []string{"t-004", "t-003", "t-tie-b", "t-tie-a", "t-002", "t-001", "t-000"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("listing = %v, want %v", got, want)
	}
	if pages != 4 {
		t.Fatalf("pages = %d, want 4", pages)
	}
	for _, s := range []string{TenantStatusClaimed, TenantStatusLatent, TenantStatusSuspended} {
		if !statuses[s] {
			t.Fatalf("listing left out every %q tenant", s)
		}
	}
}

func TestAdminListTenants_ExactPageHasNoCursor(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	seedTenants(f, "proj", 3)

	page, err := f.svc.AdminListTenants(context.Background(), asAdmin(testAdminSecret), "proj", 3, "")
	if err != nil {
		t.Fatalf("AdminListTenants: %v", err)
	}
	if len(page.Tenants) != 3 || page.NextCursor != "" {
		t.Fatalf("page = %v cursor %q, want 3 tenants and no cursor", tenantIDs(page.Tenants), page.NextCursor)
	}
}

func TestAdminListTenants_EmptyProject(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	seedTenants(f, "proj", 2)

	page, err := f.svc.AdminListTenants(context.Background(), asAdmin(testAdminSecret), "no-tenants", 0, "")
	if err != nil {
		t.Fatalf("AdminListTenants: %v", err)
	}
	if len(page.Tenants) != 0 || page.NextCursor != "" {
		t.Fatalf("page = %v cursor %q, want empty", tenantIDs(page.Tenants), page.NextCursor)
	}
}

func TestAdminListTenants_PageSize(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newAdminFixture(testAdminSecret)
	seedTenants(f, "proj", maxTenantPageSize+1)

	for _, tc := range []struct {
		limit int32
		want  int
	}{
		{limit: 0, want: defaultTenantPageSize},
		{limit: -5, want: defaultTenantPageSize},
		{limit: 7, want: 7},
		{limit: maxTenantPageSize, want: maxTenantPageSize},
		{limit: maxTenantPageSize + 1, want: maxTenantPageSize},
		{limit: 1 << 30, want: maxTenantPageSize},
	} {
		page, err := f.svc.AdminListTenants(ctx, asAdmin(testAdminSecret), "proj", tc.limit, "")
		if err != nil {
			t.Fatalf("limit %d: %v", tc.limit, err)
		}
		if len(page.Tenants) != tc.want || page.NextCursor == "" {
			t.Fatalf("limit %d: %d tenants, cursor %q; want %d and a cursor", tc.limit, len(page.Tenants), page.NextCursor, tc.want)
		}
	}
}

func TestAdminListTenants_RefusesBadArguments(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newAdminFixture(testAdminSecret)
	seedTenants(f, "proj", 1)

	if _, err := f.svc.AdminListTenants(ctx, asAdmin(testAdminSecret), " ", 0, ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank project: err = %v, want ErrInvalidArgument", err)
	}
	for _, cursor := range []string{
		"not base64!",
		base64.RawURLEncoding.EncodeToString([]byte("no-dot")),
		base64.RawURLEncoding.EncodeToString([]byte("abc.t-1")),
		base64.RawURLEncoding.EncodeToString([]byte("-1.t-1")),
		base64.RawURLEncoding.EncodeToString([]byte("12.")),
		// Postgres refuses either as a query argument (SQLSTATE 22021).
		base64.RawURLEncoding.EncodeToString([]byte("12.t-\x00-1")),
		base64.RawURLEncoding.EncodeToString([]byte("12.t-\xff\xfe")),
	} {
		if _, err := f.svc.AdminListTenants(ctx, asAdmin(testAdminSecret), "proj", 0, cursor); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("cursor %q: err = %v, want ErrInvalidArgument", cursor, err)
		}
	}

	boom := errors.New("boom")
	f.tenants.getErr = boom
	if _, err := f.svc.AdminListTenants(ctx, asAdmin(testAdminSecret), "proj", 0, ""); !errors.Is(err, boom) {
		t.Fatalf("store error: err = %v, want %v", err, boom)
	}
}

func TestTenantCursorRoundTrip(t *testing.T) {
	t.Parallel()
	for _, p := range []TenantPosition{
		{CreatedAtMs: 0, ID: "a"},
		{CreatedAtMs: 1_700_000_000_000, ID: "0b5e7c1e-uuid"},
		{CreatedAtMs: 5, ID: "id.with.dots"},
	} {
		got, err := decodeTenantCursor(encodeTenantCursor(p))
		if err != nil {
			t.Fatalf("decode(encode(%+v)): %v", p, err)
		}
		if got != p {
			t.Fatalf("decode(encode(%+v)) = %+v", p, got)
		}
	}
	if _, err := decodeTenantCursor(""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty cursor: err = %v, want ErrInvalidArgument", err)
	}
}

// The operator's client, as the handler passes it, which the status changes
// record in the audit trail.
const (
	testOperatorIP = "203.0.113.7"
	testOperatorUA = "operator-cli/1.0"
)

// statusMove names one of the two operator status changes so a table can
// drive both, from the operator's client.
type statusMove struct {
	name  string
	call  func(svc *ControlPlaneAdminService, ctx context.Context, secret, projectID, tenantID, reason string) (*Tenant, error)
	from  string
	to    string
	event audit.EventType
}

var statusMoves = []statusMove{
	{
		name: "suspend", from: TenantStatusClaimed, to: TenantStatusSuspended, event: audit.EventTenantSuspended,
		call: func(svc *ControlPlaneAdminService, ctx context.Context, secret, projectID, tenantID, reason string) (*Tenant, error) {
			return svc.AdminSuspendTenant(ctx, asAdmin(secret), projectID, tenantID, reason, testOperatorIP, testOperatorUA)
		},
	},
	{
		name: "restore", from: TenantStatusSuspended, to: TenantStatusClaimed, event: audit.EventTenantRestored,
		call: func(svc *ControlPlaneAdminService, ctx context.Context, secret, projectID, tenantID, reason string) (*Tenant, error) {
			return svc.AdminRestoreTenant(ctx, asAdmin(secret), projectID, tenantID, reason, testOperatorIP, testOperatorUA)
		},
	},
}

// putOnceClaimed seeds a tenant a person created, so a restore admits it.
func putOnceClaimed(f *adminFixture, id, status string) {
	f.tenants.put(&Tenant{ID: id, ProjectID: "proj", Name: "Acme", Status: status, CreatedBy: "u-creator", UpdatedAtMs: 7})
}

func TestAdminTenantStatus_Gated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, m := range statusMoves {
		disabled := newAdminFixture("")
		if _, err := m.call(disabled.svc, ctx, "anything", "proj", "t-1", "why"); !errors.Is(err, ErrUnimplemented) {
			t.Fatalf("%s disabled: err = %v, want ErrUnimplemented", m.name, err)
		}

		f := newAdminFixture(testAdminSecret)
		f.tenants.put(&Tenant{ID: "t-1", ProjectID: "proj", Status: m.from})
		for _, presented := range []string{"", "wrong", testAdminSecret + "x"} {
			if _, err := m.call(f.svc, ctx, presented, "proj", "t-1", "why"); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("%s(secret=%q): err = %v, want ErrPermissionDenied", m.name, presented, err)
			}
		}
		if f.tenants.writes != 0 || f.audit.countByEventType(string(m.event)) != 0 {
			t.Fatalf("%s: a refused call wrote %d times and audited %d", m.name, f.tenants.writes, f.audit.countByEventType(string(m.event)))
		}
	}
}

func TestAdminTenantStatus_MovesAndAudits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, m := range statusMoves {
		f := newAdminFixture(testAdminSecret)
		putOnceClaimed(f, "t-1", m.from)

		got, err := m.call(f.svc, ctx, testAdminSecret, " proj ", " t-1 ", "  billing dispute\n")
		if err != nil {
			t.Fatalf("%s: %v", m.name, err)
		}
		if got.Status != m.to || got.Name != "Acme" || got.UpdatedAtMs == 7 {
			t.Fatalf("%s = %+v, want the tenant %s and updated", m.name, *got, m.to)
		}
		if stored, _ := f.tenants.GetTenant(ctx, "proj", "t-1"); stored.Status != m.to {
			t.Fatalf("%s: stored status = %q, want %q", m.name, stored.Status, m.to)
		}
		details := f.audit.detailsOf(string(m.event))
		if len(details) != 1 {
			t.Fatalf("%s: %d %s events, want 1", m.name, len(details), m.event)
		}
		want := map[string]any{"project_id": "proj", "tenant_id": "t-1", "reason": "billing dispute"}
		for k, v := range want {
			if details[0][k] != v {
				t.Fatalf("%s: audit detail %s = %v, want %v (all: %v)", m.name, k, details[0][k], v, details[0])
			}
		}
		if clients := f.audit.clientsOf(string(m.event)); clients[0] != [2]string{testOperatorIP, testOperatorUA} {
			t.Fatalf("%s: audited client = %v, want the operator's", m.name, clients[0])
		}

		// Asking again finds the tenant already moved: the same answer, no
		// second write and no second record.
		again, err := m.call(f.svc, ctx, testAdminSecret, "proj", "t-1", "retry")
		if err != nil {
			t.Fatalf("%s again: %v", m.name, err)
		}
		if *again != *got || f.tenants.writes != 1 || f.audit.countByEventType(string(m.event)) != 1 {
			t.Fatalf("%s again = %+v (writes %d, events %d), want %+v unchanged", m.name, *again, f.tenants.writes, f.audit.countByEventType(string(m.event)), *got)
		}
	}
}

func TestAdminTenantStatus_RefusesWrongStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tc := range []struct {
		move   statusMove
		status string
	}{
		{move: statusMoves[0], status: TenantStatusLatent},
		{move: statusMoves[1], status: TenantStatusLatent},
	} {
		f := newAdminFixture(testAdminSecret)
		f.tenants.put(&Tenant{ID: "t-1", ProjectID: "proj", Status: tc.status})
		_, err := tc.move.call(f.svc, ctx, testAdminSecret, "proj", "t-1", "why")
		if !errors.Is(err, ErrTenantStatusConflict) {
			t.Fatalf("%s a %s tenant: err = %v, want ErrTenantStatusConflict", tc.move.name, tc.status, err)
		}
		if f.tenants.writes != 0 || f.audit.countByEventType(string(tc.move.event)) != 0 {
			t.Fatalf("%s a %s tenant wrote or audited", tc.move.name, tc.status)
		}
	}
}

// TestAdminRestoreTenant_RefusesATenantNeverClaimed: a suspended tenant with
// no creator, owner or admin was suspended while latent, so restoring it
// would claim it without a verified domain. It is refused until an operator
// adds its first admin; a creator, or an owner or admin in any status, shows
// it was claimed.
func TestAdminRestoreTenant_RefusesATenantNeverClaimed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	restore := statusMoves[1]

	f := newAdminFixture(testAdminSecret)
	f.tenants.put(&Tenant{ID: "t-1", ProjectID: "proj", Status: TenantStatusSuspended})
	if _, err := f.members.UpsertMembership(ctx, &TenantMembership{ProjectID: "proj", TenantID: "t-1", UserID: "u-member", Role: RoleMember, Source: MembershipSourceDomain, Status: MembershipStatusActive}); err != nil {
		t.Fatal(err)
	}
	_, err := restore.call(f.svc, ctx, testAdminSecret, "proj", "t-1", "why")
	if !errors.Is(err, ErrTenantStatusConflict) {
		t.Fatalf("restore a tenant with no creator, owner or admin: err = %v, want ErrTenantStatusConflict", err)
	}
	if f.tenants.writes != 0 || f.audit.countByEventType(string(restore.event)) != 0 {
		t.Fatal("a refused restore wrote or audited")
	}

	for _, role := range []string{RoleOwner, RoleAdmin} {
		for _, status := range []string{MembershipStatusActive, MembershipStatusInactive} {
			f := newAdminFixture(testAdminSecret)
			f.tenants.put(&Tenant{ID: "t-1", ProjectID: "proj", Status: TenantStatusSuspended})
			if _, err := f.members.UpsertMembership(ctx, &TenantMembership{ProjectID: "proj", TenantID: "t-1", UserID: "u-gov", Role: role, Source: MembershipSourceAdded, Status: status}); err != nil {
				t.Fatal(err)
			}
			got, err := restore.call(f.svc, ctx, testAdminSecret, "proj", "t-1", "why")
			if err != nil || got.Status != TenantStatusClaimed {
				t.Fatalf("restore a tenant with an %s %s: %+v, %v", status, role, got, err)
			}
		}
	}

	boom := errors.New("boom")
	f = newAdminFixture(testAdminSecret)
	f.tenants.put(&Tenant{ID: "t-1", ProjectID: "proj", Status: TenantStatusSuspended})
	f.members.listErr = boom
	if _, err := restore.call(f.svc, ctx, testAdminSecret, "proj", "t-1", "why"); !errors.Is(err, boom) {
		t.Fatalf("membership read error: err = %v, want %v", err, boom)
	}
}

func TestAdminTenantStatus_RefusesBadArguments(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, m := range statusMoves {
		f := newAdminFixture(testAdminSecret)
		putOnceClaimed(f, "t-1", m.from)

		for _, tc := range []struct {
			name, project, tenant, reason string
		}{
			{name: "blank project", project: " ", tenant: "t-1", reason: "why"},
			{name: "blank tenant", project: "proj", tenant: " ", reason: "why"},
			{name: "no reason", project: "proj", tenant: "t-1", reason: "   "},
			{name: "long reason", project: "proj", tenant: "t-1", reason: strings.Repeat("x", operatorReasonMaxRunes+1)},
			{name: "control character", project: "proj", tenant: "t-1", reason: "why\x00"},
		} {
			if _, err := m.call(f.svc, ctx, testAdminSecret, tc.project, tc.tenant, tc.reason); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("%s, %s: err = %v, want ErrInvalidArgument", m.name, tc.name, err)
			}
		}
		if _, err := m.call(f.svc, ctx, testAdminSecret, "proj", "t-1", strings.Repeat("x", operatorReasonMaxRunes)); err != nil {
			t.Fatalf("%s with a reason of the maximum length: %v", m.name, err)
		}
		if _, err := m.call(f.svc, ctx, testAdminSecret, "proj", "t-missing", "why"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s an unknown tenant: err = %v, want ErrNotFound", m.name, err)
		}
		if _, err := m.call(f.svc, ctx, testAdminSecret, "other-proj", "t-1", "why"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s another project's tenant: err = %v, want ErrNotFound", m.name, err)
		}
	}
}

func TestAdminTenantStatus_StoreErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	boom := errors.New("boom")

	f := newAdminFixture(testAdminSecret)
	f.tenants.put(&Tenant{ID: "t-1", ProjectID: "proj", Status: TenantStatusClaimed})
	f.tenants.setErr = boom
	if _, err := f.svc.AdminSuspendTenant(ctx, asAdmin(testAdminSecret), "proj", "t-1", "why", "", ""); !errors.Is(err, boom) {
		t.Fatalf("write error: err = %v, want %v", err, boom)
	}
	if f.audit.countByEventType(string(audit.EventTenantSuspended)) != 0 {
		t.Fatal("a failed write was audited")
	}

	f.tenants.setErr = nil
	f.tenants.getErr = boom
	if _, err := f.svc.AdminSuspendTenant(ctx, asAdmin(testAdminSecret), "proj", "t-1", "why", "", ""); !errors.Is(err, boom) {
		t.Fatalf("read error: err = %v, want %v", err, boom)
	}
}

// racingTenantStore lets another change land between the service's read of
// a tenant and its write: the tenant is moved to then just before the
// compare-and-set runs.
type racingTenantStore struct {
	*fakeTenantStore
	then string
}

func (s *racingTenantStore) SetTenantStatus(ctx context.Context, projectID, tenantID, from, to string) (bool, error) {
	s.byID[projectID+"/"+tenantID].Status = s.then
	return s.fakeTenantStore.SetTenantStatus(ctx, projectID, tenantID, from, to)
}

func TestAdminTenantStatus_ConcurrentChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		then    string
		wantErr error
	}{
		// Another operator suspended it first: the same end, reported as
		// done, and recorded once, by them.
		{name: "already suspended", then: TenantStatusSuspended},
		// It changed to something suspension does not apply to: a lost
		// race, which a retry resolves, not a status the call cannot move.
		{name: "now latent", then: TenantStatusLatent, wantErr: ErrTenantStatusChanged},
	} {
		f := newAdminFixtureWithTenants(testAdminSecret, false, testAdminSecretsKey(), func(fake *fakeTenantStore) TenantStore {
			return &racingTenantStore{fakeTenantStore: fake, then: tc.then}
		})
		f.tenants.put(&Tenant{ID: "t-1", ProjectID: "proj", Status: TenantStatusClaimed})

		got, err := f.svc.AdminSuspendTenant(ctx, asAdmin(testAdminSecret), "proj", "t-1", "why", "", "")
		if !errors.Is(err, tc.wantErr) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
		}
		if tc.wantErr == nil && got.Status != TenantStatusSuspended {
			t.Fatalf("%s: status = %q, want suspended", tc.name, got.Status)
		}
		if n := f.audit.countByEventType(string(audit.EventTenantSuspended)); n != 0 {
			t.Fatalf("%s: %d events recorded for a change this call did not make", tc.name, n)
		}
	}
}
