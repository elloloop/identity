package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/elloloop/identity/pkg/passwords"
)

const (
	scimLoginPath  = "/identity.v1.IdentityService/PasswordLogin"
	scimSignupPath = "/identity.v1.IdentityService/PasswordSignup"
)

// newSCIMLoginApp serves the full chain with SCIM provisioning into the
// project sign-in resolves to, and returns the repository bound to it.
func newSCIMLoginApp(t *testing.T) (http.Handler, service.Repository, string) {
	t.Helper()
	cfg := newTestConfig()
	cfg.DefaultProjectID = config.DefaultProjectIDFallback
	cfg.SCIMEnabled = true
	cfg.SCIMBearerToken = strings.Repeat("s", config.MinSCIMBearerTokenLength)
	cfg.SCIMProjectID = cfg.DefaultProjectID
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Identity Test", Origin: "http://localhost:9002"})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	repo := memory.New()
	built, err := New(Deps{
		Config:             cfg,
		Logger:             zap.NewNop(),
		Signer:             jwttest.NewSigner(t, "scim-login"),
		Repo:               repo,
		DB:                 repo,
		Passkeys:           pk,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	built.Start()
	t.Cleanup(built.Stop)
	return built.Handler, repo.WithProject(cfg.SCIMProjectID), cfg.SCIMBearerToken
}

// An identity provider sends userName as the directory spells it. SCIM stores
// it in the canonical form sign-up stores, so the provisioned account is the
// one sign-in resolves — however the user types the address — and a later
// self-sign-up with the same mailbox is a duplicate rather than a second,
// unprovisioned account outside SCIM deprovisioning.
func TestSCIM_ProvisionedAccountIsTheOneSignInResolves(t *testing.T) {
	h, repo, token := newSCIMLoginApp(t)
	ctx := context.Background()

	create := scimReq(t, h, http.MethodPost, "/scim/v2/Users", token,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Élodie.Martin+HR@Example.com","active":true}`)
	if create.Code != http.StatusCreated {
		t.Fatalf("create: status = %d body=%s, want 201", create.Code, create.Body.String())
	}
	const canonical = "élodie.martin@example.com"
	stored, err := repo.FindUserByEmail(ctx, canonical)
	if err != nil || stored == nil {
		t.Fatalf("FindUserByEmail(%q) = %+v, %v; want the provisioned account", canonical, stored, err)
	}
	if stored.Email != canonical {
		t.Fatalf("stored email = %q, want the canonical %q", stored.Email, canonical)
	}

	// The SCIM filter finds it by the address as the directory spells it.
	list := scimReq(t, h, http.MethodGet,
		`/scim/v2/Users?filter=userName%20eq%20%22%C3%89lodie.Martin%2BHR@Example.com%22`, token, "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"totalResults":1`) {
		t.Fatalf("filtered list: status = %d body=%s, want one result", list.Code, list.Body.String())
	}

	const password = "correct horse battery staple 42"
	hash, err := passwords.Hash(password)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := repo.UpdateUser(ctx, stored.ID, map[string]any{"password_hash": hash}); err != nil {
		t.Fatalf("set password: %v", err)
	}
	for _, typed := range []string{"ÉLODIE.MARTIN@EXAMPLE.COM", "élodie.martin+hr@example.com"} {
		login := postRPC(t, h, scimLoginPath, `{"email":"`+typed+`","password":"`+password+`"}`, nil)
		if login.Code != http.StatusOK {
			t.Fatalf("PasswordLogin(%q): status = %d body=%s, want 200", typed, login.Code, login.Body.String())
		}
		if !strings.Contains(login.Body.String(), stored.ID) {
			t.Fatalf("PasswordLogin(%q) signed in as someone else: %s", typed, login.Body.String())
		}
	}

	dup := postRPC(t, h, scimSignupPath, `{"email":"ÉLODIE.MARTIN+x@example.com","password":"`+password+`"}`, nil)
	if dup.Code == http.StatusOK {
		t.Fatalf("self-sign-up duplicated the provisioned mailbox: %s", dup.Body.String())
	}
	users, err := repo.ListUsers(ctx, service.UserListFilter{Email: canonical})
	if err != nil || len(users) != 1 || users[0].ID != stored.ID {
		t.Fatalf("accounts for %q = %+v, %v; want only the provisioned one", canonical, users, err)
	}
}

// An account provisioned before SCIM canonicalized carries the address as the
// IdP spelled it. An IdP re-sync filters by that spelling before it decides to
// create, so the filter must still find the account, and the re-sync's PUT
// then stores the canonical form sign-in resolves.
func TestSCIM_FilterFindsAccountStoredBeforeCanonicalization(t *testing.T) {
	h, repo, token := newSCIMLoginApp(t)
	ctx := context.Background()
	const asProvisioned = "Élodie.Martin+HR@Example.com"
	id, err := repo.CreateUser(ctx, &service.User{Email: asProvisioned, Status: service.StatusActive, Role: "member"})
	if err != nil {
		t.Fatalf("seed legacy account: %v", err)
	}

	list := scimReq(t, h, http.MethodGet,
		`/scim/v2/Users?filter=userName%20eq%20%22%C3%89lodie.Martin%2BHR@Example.com%22`, token, "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"totalResults":1`) || !strings.Contains(list.Body.String(), id) {
		t.Fatalf("filter by the provisioned spelling: status = %d body=%s, want the legacy account", list.Code, list.Body.String())
	}

	put := scimReq(t, h, http.MethodPut, "/scim/v2/Users/"+id, token,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"`+asProvisioned+`","active":true}`)
	if put.Code != http.StatusOK {
		t.Fatalf("re-sync PUT: status = %d body=%s", put.Code, put.Body.String())
	}
	if u, err := repo.FindUserByEmail(ctx, "élodie.martin@example.com"); err != nil || u == nil || u.ID != id {
		t.Fatalf("after re-sync FindUserByEmail(canonical) = %+v, %v; want %s", u, err, id)
	}
	// Once canonical, the same filter resolves by the canonical form.
	list = scimReq(t, h, http.MethodGet,
		`/scim/v2/Users?filter=userName%20eq%20%22%C3%89lodie.Martin%2BHR@Example.com%22`, token, "")
	if !strings.Contains(list.Body.String(), `"totalResults":1`) || !strings.Contains(list.Body.String(), id) {
		t.Fatalf("filter after re-sync: body=%s, want the account", list.Body.String())
	}
}

// A userName filter on a blank address names nobody: it must return an empty
// page, not fall through to an unfiltered list of every user.
func TestSCIM_BlankUserNameFilterMatchesNobody(t *testing.T) {
	h, repo, token := newSCIMLoginApp(t)
	if _, err := repo.CreateUser(context.Background(), &service.User{Email: "someone@example.com", Status: service.StatusActive, Role: "member"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	for _, value := range []string{"%20", "%20%20%20"} {
		list := scimReq(t, h, http.MethodGet, `/scim/v2/Users?filter=userName%20eq%20%22`+value+`%22`, token, "")
		if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"totalResults":0`) {
			t.Fatalf("filter userName eq %q: status = %d body=%s, want an empty page", value, list.Code, list.Body.String())
		}
	}
}

// A PATCH of userName stores the canonical form, like create and replace, and
// a value with no mailbox left once canonical is refused as an invalid value
// instead of being stored as "@example.com".
func TestSCIM_PatchStoresCanonicalAndRefusesUnusableAddresses(t *testing.T) {
	h, repo, token := newSCIMLoginApp(t)
	create := scimReq(t, h, http.MethodPost, "/scim/v2/Users", token,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"first@example.com","active":true}`)
	if create.Code != http.StatusCreated {
		t.Fatalf("create: status = %d body=%s", create.Code, create.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("decode create: %v %s", err, create.Body.String())
	}

	patch := scimReq(t, h, http.MethodPatch, "/scim/v2/Users/"+created.ID, token,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"userName","value":"New.Name+HR@Example.com"}]}`)
	if patch.Code != http.StatusOK {
		t.Fatalf("patch: status = %d body=%s", patch.Code, patch.Body.String())
	}
	if u, err := repo.GetUser(context.Background(), created.ID); err != nil || u == nil || u.Email != "new.name@example.com" {
		t.Fatalf("after patch stored user = %+v, %v; want email new.name@example.com", u, err)
	}

	for _, req := range []struct {
		method, path, body string
	}{
		{http.MethodPost, "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"+x@example.com","active":true}`},
		{http.MethodPut, "/scim/v2/Users/" + created.ID, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"+x@example.com","active":true}`},
		{http.MethodPatch, "/scim/v2/Users/" + created.ID, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"userName","value":"+x@example.com"}]}`},
	} {
		rec := scimReq(t, h, req.method, req.path, token, req.body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"invalidValue"`) {
			t.Fatalf("%s %s with +x@example.com: status = %d body=%s, want 400 invalidValue", req.method, req.path, rec.Code, rec.Body.String())
		}
	}
	if u, _ := repo.GetUser(context.Background(), created.ID); u == nil || u.Email != "new.name@example.com" {
		t.Fatalf("a refused write changed the stored user: %+v", u)
	}
}

// When a PATCH sets both userName and an explicit email, the email is what is
// stored, so only the email must be a usable address: an IdP whose userName
// is not an address still provisions the user.
func TestSCIM_PatchValidatesOnlyTheValueThatBecomesTheEmail(t *testing.T) {
	h, repo, token := newSCIMLoginApp(t)
	create := scimReq(t, h, http.MethodPost, "/scim/v2/Users", token,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"first@example.com","active":true}`)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("create: status = %d body=%s", create.Code, create.Body.String())
	}

	patch := scimReq(t, h, http.MethodPatch, "/scim/v2/Users/"+created.ID, token,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[`+
			`{"op":"replace","path":"userName","value":"jdoe"},`+
			`{"op":"replace","path":"emails[type eq \"work\"].value","value":"J.Doe@Example.com"}]}`)
	if patch.Code != http.StatusOK {
		t.Fatalf("patch: status = %d body=%s, want 200", patch.Code, patch.Body.String())
	}
	if u, err := repo.GetUser(context.Background(), created.ID); err != nil || u == nil || u.Email != "j.doe@example.com" {
		t.Fatalf("stored user = %+v, %v; want the explicit email, canonical", u, err)
	}
}
