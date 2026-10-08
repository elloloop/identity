package app

import (
	"context"
	"net/http"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
)

// A SCIM email change, through the real handler chain (bearer check and the
// project scope it pins), re-derives an email account's account address.
func TestSCIM_EmailChangeFollowsTheAccountAddress(t *testing.T) {
	repo := memory.New()
	mux := http.NewServeMux()
	(&scimHandler{
		repo:             repo,
		projectID:        testSCIMProjectID,
		bearerToken:      testSCIMToken,
		logger:           zap.NewNop(),
		defaultProjectID: testSCIMProjectID,
		defaultAccounts:  service.ProjectAccountsConfig{Domain: "accounts.example.test"},
	}).register(mux, true)
	scoped := repo.WithProject(testSCIMProjectID)

	id, err := scoped.CreateUser(context.Background(), &service.User{
		Email: "old@mail.example.test", EmailVerified: true, Status: "active",
		AccountAddress: "old-at-mail.example.test@accounts.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := scimReq(t, mux, http.MethodPatch, "/scim/v2/Users/"+id, testSCIMToken, `{
		"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"userName","value":"new@mail.example.test"}]
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d body=%s", rec.Code, rec.Body.String())
	}
	u, err := scoped.GetUser(context.Background(), id)
	if err != nil || u == nil {
		t.Fatalf("GetUser: %v %v", u, err)
	}
	if u.AccountAddress != "new-at-mail.example.test@accounts.example.test" {
		t.Fatalf("address after a SCIM email change: %q", u.AccountAddress)
	}
}

// A project other than the default is read from the control plane; a failed
// read refuses the request rather than provisioning without the policy.
func TestSCIM_ProjectPolicyUnavailableIs503(t *testing.T) {
	mux := http.NewServeMux()
	(&scimHandler{
		repo:             memory.New(),
		projectID:        testSCIMProjectID,
		bearerToken:      testSCIMToken,
		logger:           zap.NewNop(),
		projects:         &fakeNativeProjects{},
		defaultProjectID: "another-project",
	}).register(mux, true)
	rec := scimReq(t, mux, http.MethodGet, "/scim/v2/Users", testSCIMToken, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// A merged account is absent from SCIM: no PUT or PATCH can reactivate it.
func TestSCIM_MergedAccountIsNotAddressable(t *testing.T) {
	h, repo := newSCIMTestHandler(t, true)
	id, err := repo.CreateUser(context.Background(), &service.User{
		Email: "gone@mail.example.test", Status: "deactivated", MergedIntoUserID: "survivor",
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := scimReq(t, h, http.MethodPatch, "/scim/v2/Users/"+id, testSCIMToken, `{
		"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"active","value":true}]
	}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("patch on a merged account: status = %d, want 404", rec.Code)
	}
}
