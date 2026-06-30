package scim

import (
	"context"
	"net/http"
	"testing"
)

// errStore is a Store whose ListUsers fails, to exercise the provider's
// store-error path on the collection endpoint.
type errStore struct{ memStore }

func newErrStore() *errStore { return &errStore{memStore{rows: map[string]User{}}} }

func (s *errStore) ListUsers(context.Context, ListFilter) ([]User, int, error) {
	return nil, 0, context.DeadlineExceeded
}

func TestProvider_NotFoundPaths(t *testing.T) {
	h := NewProvider(newMemStore()).Handler()

	cases := []struct{ method, path, body string }{
		{http.MethodGet, "/scim/v2/Users/missing", ""},
		{http.MethodPut, "/scim/v2/Users/missing", `{"schemas":["` + SchemaUser + `"],"userName":"a@b.com","active":true}`},
		{http.MethodPatch, "/scim/v2/Users/missing", `{"schemas":["` + SchemaPatchOp + `"],"Operations":[{"op":"replace","path":"active","value":false}]}`},
		{http.MethodDelete, "/scim/v2/Users/missing", ""},
	}
	for _, c := range cases {
		rec := do(t, h, c.method, c.path, c.body)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s = %d, want 404 (body=%s)", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
}

func TestProvider_UserItemEmptyIDOrSubpath(t *testing.T) {
	h := NewProvider(newMemStore()).Handler()
	// A trailing-slash collection with no id, and a nested subpath, are 404s.
	if rec := do(t, h, http.MethodGet, "/scim/v2/Users/a/b", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("nested subpath = %d, want 404", rec.Code)
	}
}

func TestProvider_MethodNotAllowed(t *testing.T) {
	h := NewProvider(newMemStore()).Handler()
	if rec := do(t, h, http.MethodDelete, "/scim/v2/Users", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE collection = %d, want 405", rec.Code)
	}
	u, _ := newMemStore().CreateUser(context.Background(), User{UserName: "x@example.com", Active: true})
	_ = u
	if rec := do(t, h, http.MethodPost, "/scim/v2/Users/anything", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST item = %d, want 405", rec.Code)
	}
}

func TestProvider_DiscoveryNonGETIs405(t *testing.T) {
	h := NewProvider(newMemStore()).Handler()
	for _, p := range []string{
		"/scim/v2/ServiceProviderConfig",
		"/scim/v2/Schemas",
		"/scim/v2/ResourceTypes",
	} {
		if rec := do(t, h, http.MethodPost, p, "{}"); rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s = %d, want 405", p, rec.Code)
		}
	}
}

func TestProvider_MalformedJSON(t *testing.T) {
	h := NewProvider(newMemStore()).Handler()
	if rec := do(t, h, http.MethodPost, "/scim/v2/Users", `{not json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed create = %d, want 400", rec.Code)
	}
	u, _ := newMemStore().CreateUser(context.Background(), User{UserName: "z@example.com", Active: true})
	_ = u
	if rec := do(t, h, http.MethodPut, "/scim/v2/Users/whatever", `{not json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed put = %d, want 400", rec.Code)
	}
	if rec := do(t, h, http.MethodPatch, "/scim/v2/Users/whatever", `{not json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed patch = %d, want 400", rec.Code)
	}
}

func TestProvider_ListStoreError(t *testing.T) {
	h := NewProvider(newErrStore()).Handler()
	if rec := do(t, h, http.MethodGet, "/scim/v2/Users", ""); rec.Code != http.StatusInternalServerError {
		t.Fatalf("list store error = %d, want 500", rec.Code)
	}
}

func TestProvider_ListPaginationParams(t *testing.T) {
	st := newMemStore()
	ctx := context.Background()
	for _, e := range []string{"a@x.com", "b@x.com", "c@x.com"} {
		if _, err := st.CreateUser(ctx, User{UserName: e, Email: e, Active: true}); err != nil {
			t.Fatalf("seed %s: %v", e, err)
		}
	}
	h := NewProvider(st).Handler()

	// startIndex=2&count=1 returns one row, total still 3.
	rec := do(t, h, http.MethodGet, "/scim/v2/Users?startIndex=2&count=1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d body=%s", rec.Code, rec.Body.String())
	}
	var list ListResponse
	mustJSON(t, rec, &list)
	if list.TotalResults != 3 || len(list.Resources) != 1 || list.StartIndex != 2 {
		t.Fatalf("pagination: total=%d items=%d start=%d", list.TotalResults, len(list.Resources), list.StartIndex)
	}

	// externalId + email filters parse.
	if rec := do(t, h, http.MethodGet, `/scim/v2/Users?filter=externalId+eq+%22nope%22`, ""); rec.Code != http.StatusOK {
		t.Fatalf("externalId filter = %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, `/scim/v2/Users?filter=email+eq+%22a@x.com%22`, ""); rec.Code != http.StatusOK {
		t.Fatalf("email filter = %d", rec.Code)
	}
}

func TestProvider_ListInvalidParams(t *testing.T) {
	h := NewProvider(newMemStore()).Handler()
	for _, q := range []string{
		"?startIndex=0",
		"?startIndex=abc",
		"?count=-1",
		"?count=xyz",
		`?filter=foo+eq+%22bar%22`,      // unsupported attribute
		`?filter=userName+co+%22bar%22`, // unsupported operator
	} {
		rec := do(t, h, http.MethodGet, "/scim/v2/Users"+q, "")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("list %s = %d, want 400 (body=%s)", q, rec.Code, rec.Body.String())
		}
	}
}

func TestProvider_CountParsing(t *testing.T) {
	// count above the cap clamps to maxPageSize.
	if f, err := parseListFilterQuery(t, "?count=99999"); err != nil || f.Count != maxPageSize {
		t.Fatalf("count=99999 → %d err=%v, want %d", f.Count, err, maxPageSize)
	}
	// count=0 is preserved (RFC 7644 §3.4.2.4 "totalResults only"), NOT clamped.
	if f, err := parseListFilterQuery(t, "?count=0"); err != nil || f.Count != 0 {
		t.Fatalf("count=0 → %d err=%v, want 0", f.Count, err)
	}
	// Absent count uses the default page size.
	if f, err := parseListFilterQuery(t, ""); err != nil || f.Count != defaultPageSize {
		t.Fatalf("no count → %d err=%v, want %d", f.Count, err, defaultPageSize)
	}
}

func TestProvider_CountZeroReturnsTotalsOnly(t *testing.T) {
	st := newMemStore()
	ctx := context.Background()
	for _, e := range []string{"a@x.com", "b@x.com", "c@x.com"} {
		if _, err := st.CreateUser(ctx, User{UserName: e, Email: e, Active: true}); err != nil {
			t.Fatalf("seed %s: %v", e, err)
		}
	}
	h := NewProvider(st).Handler()
	rec := do(t, h, http.MethodGet, "/scim/v2/Users?count=0", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("count=0 list = %d body=%s", rec.Code, rec.Body.String())
	}
	var list ListResponse
	mustJSON(t, rec, &list)
	if list.TotalResults != 3 {
		t.Fatalf("count=0 totalResults = %d, want 3", list.TotalResults)
	}
	if list.ItemsPerPage != 0 || len(list.Resources) != 0 {
		t.Fatalf("count=0 must return zero resources: itemsPerPage=%d len=%d", list.ItemsPerPage, len(list.Resources))
	}
}

func parseListFilterQuery(t *testing.T, rawQuery string) (ListFilter, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/scim/v2/Users"+rawQuery, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return parseListFilter(req)
}

func TestToUserPatch(t *testing.T) {
	// Path-form active replace, accepting a JSON bool.
	if p, err := (PatchRequest{Operations: []Operation{{Op: "replace", Path: "active", Value: []byte("false")}}}).toUserPatch(); err != nil || p.Active == nil || *p.Active {
		t.Fatalf("active false: %+v err=%v", p, err)
	}
	// Entra sometimes sends active as a quoted string.
	if p, err := (PatchRequest{Operations: []Operation{{Op: "Replace", Path: "active", Value: []byte(`"True"`)}}}).toUserPatch(); err != nil || p.Active == nil || !*p.Active {
		t.Fatalf("active string True: %+v err=%v", p, err)
	}
	// No-path value-object touching several attributes.
	if p, err := (PatchRequest{Operations: []Operation{{Op: "replace", Value: []byte(`{"active":false,"externalId":"e1","name":{"givenName":"A","familyName":"B"}}`)}}}).toUserPatch(); err != nil ||
		p.Active == nil || *p.Active || p.ExternalID == nil || *p.ExternalID != "e1" || p.GivenName == nil || *p.GivenName != "A" || p.FamilyName == nil || *p.FamilyName != "B" {
		t.Fatalf("value-object: %+v err=%v", p, err)
	}
	// emails array → primary value.
	if p, err := (PatchRequest{Operations: []Operation{{Op: "replace", Path: "emails", Value: []byte(`[{"value":"x@y.com","primary":true}]`)}}}).toUserPatch(); err != nil || p.Email == nil || *p.Email != "x@y.com" {
		t.Fatalf("emails array: %+v err=%v", p, err)
	}
	// displayName splits into given/family.
	if p, err := (PatchRequest{Operations: []Operation{{Op: "replace", Path: "displayName", Value: []byte(`"Ada Lovelace"`)}}}).toUserPatch(); err != nil || p.GivenName == nil || *p.GivenName != "Ada" || p.FamilyName == nil || *p.FamilyName != "Lovelace" {
		t.Fatalf("displayName: %+v err=%v", p, err)
	}
	// remove externalId clears it.
	if p, err := (PatchRequest{Operations: []Operation{{Op: "remove", Path: "externalId"}}}).toUserPatch(); err != nil || p.ExternalID == nil || *p.ExternalID != "" {
		t.Fatalf("remove externalId: %+v err=%v", p, err)
	}
	// Invalid active boolean → error.
	if _, err := (PatchRequest{Operations: []Operation{{Op: "replace", Path: "active", Value: []byte(`"nope"`)}}}).toUserPatch(); err == nil {
		t.Fatal("invalid active bool must error")
	}
	// remove active is rejected.
	if _, err := (PatchRequest{Operations: []Operation{{Op: "remove", Path: "active"}}}).toUserPatch(); err == nil {
		t.Fatal("remove active must error")
	}
	// Unmodelled attribute → error.
	if _, err := (PatchRequest{Operations: []Operation{{Op: "replace", Path: "title", Value: []byte(`"Dr"`)}}}).toUserPatch(); err == nil {
		t.Fatal("unmodelled attribute must error")
	}
	// Empty patch → errNoSupportedPatch.
	if _, err := (PatchRequest{}).toUserPatch(); err == nil {
		t.Fatal("empty patch must error")
	}
}

func TestPatch_InvalidActiveValueIs400(t *testing.T) {
	st := newMemStore()
	u, _ := st.CreateUser(context.Background(), User{UserName: "p@example.com", Active: true})
	h := NewProvider(st).Handler()
	rec := do(t, h, http.MethodPatch, "/scim/v2/Users/"+u.ID, `{
		"schemas":["`+SchemaPatchOp+`"],
		"Operations":[{"op":"replace","path":"active","value":"notabool"}]
	}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid active value = %d, want 400", rec.Code)
	}
}

func TestFromResource_SplitsFormattedName(t *testing.T) {
	// name.formatted only (no given/family) exercises splitName via create.
	st := newMemStore()
	h := NewProvider(st).Handler()
	rec := do(t, h, http.MethodPost, "/scim/v2/Users", `{
		"schemas":["`+SchemaUser+`"],
		"userName":"split@example.com",
		"name":{"formatted":"Ada Lovelace"},
		"active":true
	}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d body=%s", rec.Code, rec.Body.String())
	}
	var created Resource
	mustJSON(t, rec, &created)
	if created.Name == nil || created.Name.GivenName != "Ada" || created.Name.FamilyName != "Lovelace" {
		t.Fatalf("splitName via formatted: %+v", created.Name)
	}
}

func TestSplitNameAndFullName(t *testing.T) {
	if g, f := splitName(""); g != "" || f != "" {
		t.Fatalf("empty: %q %q", g, f)
	}
	if g, f := splitName("Mononym"); g != "Mononym" || f != "" {
		t.Fatalf("single: %q %q", g, f)
	}
	if g, f := splitName("  Grace   Hopper  "); g != "Grace" || f != "Hopper" {
		t.Fatalf("trim: %q %q", g, f)
	}
	if got := fullName("", ""); got != "" {
		t.Fatalf("fullName empty = %q", got)
	}
}
