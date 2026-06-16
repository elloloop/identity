package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// memStore is an in-memory Store for exercising the provider end-to-end.
type memStore struct {
	mu   sync.Mutex
	seq  int
	rows map[string]User
}

func newMemStore() *memStore { return &memStore{rows: map[string]User{}} }

func (m *memStore) CreateUser(_ context.Context, u User) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if strings.EqualFold(r.UserName, u.UserName) {
			return User{}, ErrConflict
		}
		if u.ExternalID != "" && r.ExternalID == u.ExternalID {
			return User{}, ErrConflict
		}
	}
	m.seq++
	u.ID = "u-" + itoa(m.seq)
	u.CreatedAt = time.UnixMilli(int64(m.seq))
	u.UpdatedAt = u.CreatedAt
	m.rows[u.ID] = u
	return u, nil
}

func (m *memStore) GetUser(_ context.Context, id string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.rows[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (m *memStore) ReplaceUser(_ context.Context, id string, u User) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.rows[id]
	if !ok {
		return User{}, ErrNotFound
	}
	u.ID = id
	u.CreatedAt = existing.CreatedAt
	u.UpdatedAt = time.UnixMilli(time.Now().UnixMilli())
	m.rows[id] = u
	return u, nil
}

func (m *memStore) SetActive(_ context.Context, id string, active bool) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.rows[id]
	if !ok {
		return User{}, ErrNotFound
	}
	u.Active = active
	m.rows[id] = u
	return u, nil
}

func (m *memStore) DeleteUser(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[id]; !ok {
		return ErrNotFound
	}
	delete(m.rows, id)
	return nil
}

func (m *memStore) ListUsers(_ context.Context, f ListFilter) ([]User, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []User
	for _, u := range m.rows {
		if f.UserName != "" && !strings.EqualFold(u.UserName, f.UserName) {
			continue
		}
		if f.Email != "" && !strings.EqualFold(u.Email, f.Email) {
			continue
		}
		if f.ExternalID != "" && u.ExternalID != f.ExternalID {
			continue
		}
		all = append(all, u)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	total := len(all)
	start := f.StartIndex - 1
	if start < 0 {
		start = 0
	}
	if start > len(all) {
		start = len(all)
	}
	end := start + f.Count
	if f.Count <= 0 || end > len(all) {
		end = len(all)
	}
	return all[start:end], total, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestProvider_UserLifecycle(t *testing.T) {
	h := NewProvider(newMemStore()).Handler()

	// Create
	rec := do(t, h, http.MethodPost, "/scim/v2/Users", `{
		"schemas":["`+SchemaUser+`"],
		"userName":"alice@example.com",
		"externalId":"okta-123",
		"name":{"givenName":"Alice","familyName":"Smith"},
		"emails":[{"value":"alice@example.com","primary":true}],
		"active":true
	}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var created Resource
	mustJSON(t, rec, &created)
	if created.ID == "" || created.ExternalID != "okta-123" || created.UserName != "alice@example.com" {
		t.Fatalf("create resource: %+v", created)
	}
	if !created.Active {
		t.Fatal("created user should be active")
	}
	id := created.ID

	// Get
	rec = do(t, h, http.MethodGet, "/scim/v2/Users/"+id, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d", rec.Code)
	}

	// Filter by userName eq
	rec = do(t, h, http.MethodGet, `/scim/v2/Users?filter=userName+eq+%22alice@example.com%22`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var list ListResponse
	mustJSON(t, rec, &list)
	if list.TotalResults != 1 || len(list.Resources) != 1 {
		t.Fatalf("filter result: %+v", list)
	}

	// PATCH active:false
	rec = do(t, h, http.MethodPatch, "/scim/v2/Users/"+id, `{
		"schemas":["`+SchemaPatchOp+`"],
		"Operations":[{"op":"replace","path":"active","value":false}]
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d body=%s", rec.Code, rec.Body.String())
	}
	var patched Resource
	mustJSON(t, rec, &patched)
	if patched.Active {
		t.Fatal("patch active:false did not deactivate")
	}

	// PUT replace
	rec = do(t, h, http.MethodPut, "/scim/v2/Users/"+id, `{
		"schemas":["`+SchemaUser+`"],
		"userName":"alice@example.com",
		"name":{"givenName":"Alicia","familyName":"Smith"},
		"active":true
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("put status = %d body=%s", rec.Code, rec.Body.String())
	}
	var replaced Resource
	mustJSON(t, rec, &replaced)
	if replaced.Name == nil || replaced.Name.GivenName != "Alicia" {
		t.Fatalf("replace name: %+v", replaced.Name)
	}

	// Delete
	rec = do(t, h, http.MethodDelete, "/scim/v2/Users/"+id, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/scim/v2/Users/"+id, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete = %d, want 404", rec.Code)
	}
}

func TestProvider_DuplicateUserNameConflict(t *testing.T) {
	h := NewProvider(newMemStore()).Handler()
	body := `{"schemas":["` + SchemaUser + `"],"userName":"dup@example.com","active":true}`
	if rec := do(t, h, http.MethodPost, "/scim/v2/Users", body); rec.Code != http.StatusCreated {
		t.Fatalf("first create = %d", rec.Code)
	}
	rec := do(t, h, http.MethodPost, "/scim/v2/Users", body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create = %d, want 409", rec.Code)
	}
}

func TestProvider_CreateRequiresUserName(t *testing.T) {
	h := NewProvider(newMemStore()).Handler()
	rec := do(t, h, http.MethodPost, "/scim/v2/Users", `{"schemas":["`+SchemaUser+`"],"active":true}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create without userName = %d, want 400", rec.Code)
	}
}

func TestProvider_PatchUnsupportedAttributeRejected(t *testing.T) {
	st := newMemStore()
	u, _ := st.CreateUser(context.Background(), User{UserName: "x@example.com", Email: "x@example.com", Active: true})
	h := NewProvider(st).Handler()
	rec := do(t, h, http.MethodPatch, "/scim/v2/Users/"+u.ID, `{
		"schemas":["`+SchemaPatchOp+`"],
		"Operations":[{"op":"replace","path":"userName","value":"y@example.com"}]
	}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("patch userName = %d, want 400", rec.Code)
	}
}

func TestProvider_Discovery(t *testing.T) {
	h := NewProvider(newMemStore()).Handler()
	for _, path := range []string{
		"/scim/v2/ServiceProviderConfig",
		"/scim/v2/Schemas",
		"/scim/v2/ResourceTypes",
	} {
		rec := do(t, h, http.MethodGet, path, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d", path, rec.Code)
		}
		var m map[string]any
		mustJSON(t, rec, &m)
		if len(m) == 0 {
			t.Fatalf("%s returned empty body", path)
		}
		if ct := rec.Header().Get("Content-Type"); ct != scimContentType {
			t.Fatalf("%s content-type = %q", path, ct)
		}
	}
}

func TestParseEqFilter(t *testing.T) {
	attr, val, err := parseEqFilter(`userName eq "bob@example.com"`)
	if err != nil || attr != "userName" || val != "bob@example.com" {
		t.Fatalf("parseEqFilter = %q,%q,%v", attr, val, err)
	}
	if _, _, err := parseEqFilter(`userName co "bob"`); err == nil {
		t.Fatal("non-eq operator should error")
	}
	if _, _, err := parseEqFilter(`userName eq bob`); err == nil {
		t.Fatal("unquoted value should error")
	}
}

func mustJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
}
