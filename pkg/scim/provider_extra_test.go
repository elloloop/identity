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

func TestProvider_CountClampedToMax(t *testing.T) {
	// count=0 and count>max both clamp to maxPageSize without error.
	for _, q := range []string{"?count=0", "?count=99999"} {
		f, err := parseListFilterQuery(t, q)
		if err != nil {
			t.Fatalf("parse %s: %v", q, err)
		}
		if f.Count != maxPageSize {
			t.Fatalf("count for %s = %d, want %d", q, f.Count, maxPageSize)
		}
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

func TestPatch_ActiveValueShapes(t *testing.T) {
	// Path-form replace.
	if a, ok, err := (PatchRequest{Operations: []Operation{{Op: "replace", Path: "active", Value: []byte("false")}}}).activeValue(); err != nil || !ok || a {
		t.Fatalf("path-form: a=%v ok=%v err=%v", a, ok, err)
	}
	// add op with value object {"active":true}.
	if a, ok, err := (PatchRequest{Operations: []Operation{{Op: "add", Value: []byte(`{"active":true}`)}}}).activeValue(); err != nil || !ok || !a {
		t.Fatalf("value-object: a=%v ok=%v err=%v", a, ok, err)
	}
	// Non-active op → ok=false.
	if _, ok, err := (PatchRequest{Operations: []Operation{{Op: "replace", Path: "displayName", Value: []byte(`"x"`)}}}).activeValue(); ok || err != nil {
		t.Fatalf("non-active: ok=%v err=%v", ok, err)
	}
	// Invalid boolean in path-form → error.
	if _, _, err := (PatchRequest{Operations: []Operation{{Op: "replace", Path: "active", Value: []byte(`"nope"`)}}}).activeValue(); err == nil {
		t.Fatal("invalid bool path-form must error")
	}
	// Invalid boolean in value-object form → error.
	if _, _, err := (PatchRequest{Operations: []Operation{{Op: "add", Value: []byte(`{"active":"nope"}`)}}}).activeValue(); err == nil {
		t.Fatal("invalid bool value-object must error")
	}
	// Non-replace/add op is skipped.
	if _, ok, _ := (PatchRequest{Operations: []Operation{{Op: "remove", Path: "active"}}}).activeValue(); ok {
		t.Fatal("remove op must not yield an active value")
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
