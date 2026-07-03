package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
)

const (
	testSCIMToken     = "test-bearer-token-123"
	testSCIMProjectID = "scim-project"
)

func newSCIMTestHandler(t *testing.T, enabled bool) (http.Handler, service.Repository) {
	t.Helper()
	repo := memory.New()
	mux := http.NewServeMux()
	(&scimHandler{
		repo:        repo,
		projectID:   testSCIMProjectID,
		bearerToken: testSCIMToken,
		logger:      zap.NewNop(),
	}).register(mux, enabled)
	// Return the repository bound to the SAME fixed project the handler writes
	// through, so test assertions read the partition the SCIM store mutates.
	scoped := service.ProjectBoundRepository(repo, testSCIMProjectID)
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

	// external_id round-trips into the repository — resolved via the
	// production correlation path (ListUsers with an ExternalID filter).
	matches, err := repo.ListUsers(context.Background(), service.UserListFilter{ExternalID: "entra-77"})
	if err != nil || len(matches) != 1 {
		t.Fatalf("ListUsers(ExternalID): %v %#v", err, matches)
	}
	u := matches[0]
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

// TestSCIM_IgnoresRequestProjectScope is the regression for the cross-project
// provisioning hole: the SCIM credential is bound to ONE configured project, so
// a request that resolves (via Host/auth-domain) to a DIFFERENT project must
// still operate on the configured project's users only — never the resolved
// one. The handler OVERWRITES the request scope with its own fixed project
// (so audit + events also attribute to it); here we forge a foreign
// ProjectScope on the request context and assert the created user lands in the
// configured project and is absent from the forged one.
func TestSCIM_IgnoresRequestProjectScope(t *testing.T) {
	repo := memory.New()
	mux := http.NewServeMux()
	(&scimHandler{
		repo:        repo,
		projectID:   testSCIMProjectID,
		bearerToken: testSCIMToken,
		logger:      zap.NewNop(),
	}).register(mux, true)

	const foreignProject = "attacker-project"
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"victim@example.com","active":true}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testSCIMToken)
	// Forge a resolved scope for a different project — what a malicious Host /
	// auth-domain would inject through the project-resolution middleware.
	req = req.WithContext(service.WithProjectScope(req.Context(),
		&service.ProjectScope{ProjectID: foreignProject}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", rec.Code, rec.Body.String())
	}

	ctx := context.Background()
	// The user must exist in the CONFIGURED project...
	if u, err := service.ProjectBoundRepository(repo, testSCIMProjectID).
		FindUserByEmail(ctx, "victim@example.com"); err != nil || u == nil {
		t.Fatalf("user must land in configured project %q: %v %#v", testSCIMProjectID, err, u)
	}
	// ...and must NOT have leaked into the forged project.
	if u, err := service.ProjectBoundRepository(repo, foreignProject).
		FindUserByEmail(ctx, "victim@example.com"); err != nil || u != nil {
		t.Fatalf("cross-project leak: user reachable from forged project %q: %#v (err=%v)", foreignProject, u, err)
	}
}

// TestSCIM_DuplicateUserName_Returns409 asserts a duplicate userName/email
// create maps to HTTP 409 Conflict (SCIM uniqueness error), not 500.
func TestSCIM_DuplicateUserName_Returns409(t *testing.T) {
	h, _ := newSCIMTestHandler(t, true)
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"dup@example.com","active":true}`

	if rec := scimReq(t, h, http.MethodPost, "/scim/v2/Users", testSCIMToken, body); rec.Code != http.StatusCreated {
		t.Fatalf("first create status = %d body=%s", rec.Code, rec.Body.String())
	}
	rec := scimReq(t, h, http.MethodPost, "/scim/v2/Users", testSCIMToken, body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create status = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
	}
	var errBody map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &errBody)
	if errBody["scimType"] != "uniqueness" {
		t.Fatalf("409 scimType = %v, want uniqueness (body=%s)", errBody["scimType"], rec.Body.String())
	}
}

// TestSCIM_ListPaginationBeyond500 asserts totalResults reflects the whole
// matching set (not the page size or the 500-row cap) and that startIndex/count
// page against the DB with a real offset — so a large project never silently
// truncates at 500.
func TestSCIM_ListPaginationBeyond500(t *testing.T) {
	h, repo := newSCIMTestHandler(t, true)
	ctx := context.Background()

	const total = 620
	base := time.UnixMilli(1_700_000_000_000)
	for i := 0; i < total; i++ {
		if _, err := repo.CreateUser(ctx, &service.User{
			Email:     fmt.Sprintf("u%04d@example.com", i),
			Status:    "active",
			CreatedAt: base.Add(time.Duration(i) * time.Millisecond),
			UpdatedAt: base.Add(time.Duration(i) * time.Millisecond),
		}); err != nil {
			t.Fatalf("seed user %d: %v", i, err)
		}
	}

	// Page near the end (startIndex=551, count=100) must return rows beyond the
	// 500-row cap the old adapter truncated at, and report the true total.
	rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users?startIndex=551&count=100", testSCIMToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var list struct {
		TotalResults int `json:"totalResults"`
		StartIndex   int `json:"startIndex"`
		ItemsPerPage int `json:"itemsPerPage"`
		Resources    []struct {
			UserName string `json:"userName"`
		} `json:"Resources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v body=%s", err, rec.Body.String())
	}
	if list.TotalResults != total {
		t.Fatalf("totalResults = %d, want %d (must be the full match count, not the page size)", list.TotalResults, total)
	}
	// startIndex 551 → offset 550; 620 total ⇒ 70 rows remain.
	if list.ItemsPerPage != 70 || len(list.Resources) != 70 {
		t.Fatalf("itemsPerPage = %d / len = %d, want 70", list.ItemsPerPage, len(list.Resources))
	}
	// The window must start at the 551st row (created_at asc): u0550.
	if list.Resources[0].UserName != "u0550@example.com" {
		t.Fatalf("first row = %q, want u0550@example.com (real DB offset)", list.Resources[0].UserName)
	}
}

// TestSCIM_PutDeactivationRevokesTokens asserts a PUT (ReplaceUser) that flips
// the user inactive revokes refresh tokens immediately — the same as a PATCH
// active:false — so a deprovisioned account cannot keep using a live token.
func TestSCIM_PutDeactivationRevokesTokens(t *testing.T) {
	h, repo := newSCIMTestHandler(t, true)
	ctx := context.Background()

	id, err := repo.CreateUser(ctx, &service.User{Email: "rev@example.com", Status: "active", Role: "member"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := repo.CreateRefreshToken(ctx, &service.RefreshTokenRecord{UserID: id, TokenHash: "live-hash"}); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	counter, ok := repo.(interface {
		CountRefreshTokensForUser(string) int
	})
	if !ok {
		t.Fatal("memory repo must expose CountRefreshTokensForUser")
	}
	if n := counter.CountRefreshTokensForUser(id); n != 1 {
		t.Fatalf("precondition: refresh tokens = %d, want 1", n)
	}

	rec := scimReq(t, h, http.MethodPut, "/scim/v2/Users/"+id, testSCIMToken, `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"rev@example.com",
		"active":false
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("put status = %d body=%s", rec.Code, rec.Body.String())
	}
	if u, _ := repo.GetUser(ctx, id); u == nil || u.Status != "deactivated" {
		t.Fatalf("after put: %+v", u)
	}
	if n := counter.CountRefreshTokensForUser(id); n != 0 {
		t.Fatalf("PUT active:false must revoke refresh tokens: got %d, want 0", n)
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
