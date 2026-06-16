package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
)

const testSCIMToken = "test-bearer-token-123"

func newSCIMTestHandler(t *testing.T, enabled bool) (http.Handler, service.Repository) {
	t.Helper()
	repo := memory.New()
	mux := http.NewServeMux()
	(&scimHandler{
		repo:        repo,
		defaultProj: "default",
		bearerToken: testSCIMToken,
		logger:      zap.NewNop(),
	}).register(mux, enabled)
	// Return the project-scoped repository the handler writes through, so test
	// assertions read the same partition the SCIM store mutates (no request
	// ProjectScope ⇒ the default project, identical to ScopedRepository).
	scoped := service.ScopedRepository(context.Background(), repo, "default")
	return mux, scoped
}

func scimReq(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSCIM_GateOff_404(t *testing.T) {
	h, _ := newSCIMTestHandler(t, false)
	rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users", testSCIMToken, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("gate off: status = %d, want 404", rec.Code)
	}
}

func TestSCIM_RequiresBearerToken(t *testing.T) {
	h, _ := newSCIMTestHandler(t, true)

	if rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", rec.Code)
	}
	if rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users", "wrong", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", rec.Code)
	}
}

func TestSCIM_CreatePatchListThroughRepo(t *testing.T) {
	h, repo := newSCIMTestHandler(t, true)

	// POST create
	rec := scimReq(t, h, http.MethodPost, "/scim/v2/Users", testSCIMToken, `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"bob@example.com",
		"externalId":"entra-77",
		"name":{"givenName":"Bob","familyName":"Jones"},
		"active":true
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

	// external_id round-trips into the repository.
	u, err := repo.FindUserByExternalID(context.Background(), "entra-77")
	if err != nil || u == nil {
		t.Fatalf("FindUserByExternalID: %v %#v", err, u)
	}
	if u.Email != "bob@example.com" || u.Status != "active" {
		t.Fatalf("created user: %+v", u)
	}

	// GET filter eq email.
	rec = scimReq(t, h, http.MethodGet,
		`/scim/v2/Users?filter=`+strings.ReplaceAll(`userName eq "bob@example.com"`, " ", "+"),
		testSCIMToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var list map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if tr, _ := list["totalResults"].(float64); tr != 1 {
		t.Fatalf("filter totalResults = %v, want 1 (body=%s)", list["totalResults"], rec.Body.String())
	}

	// PATCH active:false → status deactivated in the repo.
	rec = scimReq(t, h, http.MethodPatch, "/scim/v2/Users/"+id, testSCIMToken, `{
		"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"active","value":false}]
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d body=%s", rec.Code, rec.Body.String())
	}
	u, _ = repo.GetUser(context.Background(), id)
	if u == nil || u.Status != "deactivated" {
		t.Fatalf("after patch: %+v", u)
	}

	// PUT replace.
	rec = scimReq(t, h, http.MethodPut, "/scim/v2/Users/"+id, testSCIMToken, `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"bob@example.com",
		"name":{"givenName":"Robert","familyName":"Jones"},
		"active":true
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("put status = %d body=%s", rec.Code, rec.Body.String())
	}
	u, _ = repo.GetUser(context.Background(), id)
	if u == nil || u.Name != "Robert Jones" || u.Status != "active" {
		t.Fatalf("after put: %+v", u)
	}

	// DELETE.
	rec = scimReq(t, h, http.MethodDelete, "/scim/v2/Users/"+id, testSCIMToken, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", rec.Code)
	}
	if u, _ := repo.GetUser(context.Background(), id); u != nil {
		t.Fatalf("user still present after delete: %+v", u)
	}
}

func TestSCIM_DiscoveryEndpoints(t *testing.T) {
	h, _ := newSCIMTestHandler(t, true)
	for _, p := range []string{
		"/scim/v2/ServiceProviderConfig",
		"/scim/v2/Schemas",
		"/scim/v2/ResourceTypes",
	} {
		rec := scimReq(t, h, http.MethodGet, p, testSCIMToken, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d", p, rec.Code)
		}
	}
}
