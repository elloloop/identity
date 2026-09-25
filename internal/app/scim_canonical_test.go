package app

import (
	"context"
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
