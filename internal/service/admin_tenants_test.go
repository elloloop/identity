package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
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
	if _, err := disabled.svc.AdminGetTenant(ctx, "anything", "proj", "t"); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("AdminGetTenant disabled: err = %v, want ErrUnimplemented", err)
	}
	if _, err := disabled.svc.AdminListTenants(ctx, "anything", "proj", 0, ""); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("AdminListTenants disabled: err = %v, want ErrUnimplemented", err)
	}

	f := newAdminFixture(testAdminSecret)
	seedTenants(f, "proj", 1)
	for _, presented := range []string{"", "wrong", testAdminSecret + "x"} {
		if _, err := f.svc.AdminGetTenant(ctx, presented, "proj", "t-000"); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("AdminGetTenant(secret=%q): err = %v, want ErrPermissionDenied", presented, err)
		}
		if _, err := f.svc.AdminListTenants(ctx, presented, "proj", 0, ""); !errors.Is(err, ErrPermissionDenied) {
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

	got, err := f.svc.AdminGetTenant(ctx, testAdminSecret, " proj ", " t-1 ")
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

	if _, err := f.svc.AdminGetTenant(ctx, testAdminSecret, "proj", "t-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown tenant: err = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.AdminGetTenant(ctx, testAdminSecret, "other-proj", "t-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another project's tenant: err = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.AdminGetTenant(ctx, testAdminSecret, "  ", "t-1"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank project: err = %v, want ErrInvalidArgument", err)
	}
	if _, err := f.svc.AdminGetTenant(ctx, testAdminSecret, "proj", "  "); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank tenant: err = %v, want ErrInvalidArgument", err)
	}

	boom := errors.New("boom")
	f.tenants.getErr = boom
	if _, err := f.svc.AdminGetTenant(ctx, testAdminSecret, "proj", "t-1"); !errors.Is(err, boom) {
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
		page, err := f.svc.AdminListTenants(ctx, testAdminSecret, "proj", 2, cursor)
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

	page, err := f.svc.AdminListTenants(context.Background(), testAdminSecret, "proj", 3, "")
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

	page, err := f.svc.AdminListTenants(context.Background(), testAdminSecret, "no-tenants", 0, "")
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
		page, err := f.svc.AdminListTenants(ctx, testAdminSecret, "proj", tc.limit, "")
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

	if _, err := f.svc.AdminListTenants(ctx, testAdminSecret, " ", 0, ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank project: err = %v, want ErrInvalidArgument", err)
	}
	for _, cursor := range []string{
		"not base64!",
		base64.RawURLEncoding.EncodeToString([]byte("no-dot")),
		base64.RawURLEncoding.EncodeToString([]byte("abc.t-1")),
		base64.RawURLEncoding.EncodeToString([]byte("-1.t-1")),
		base64.RawURLEncoding.EncodeToString([]byte("12.")),
	} {
		if _, err := f.svc.AdminListTenants(ctx, testAdminSecret, "proj", 0, cursor); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("cursor %q: err = %v, want ErrInvalidArgument", cursor, err)
		}
	}

	boom := errors.New("boom")
	f.tenants.getErr = boom
	if _, err := f.svc.AdminListTenants(ctx, testAdminSecret, "proj", 0, ""); !errors.Is(err, boom) {
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
