package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

const (
	chainDirectoryProject = "directory-project"
	chainDirectoryPublic  = "dk_chaintest"
	chainDirectorySecret  = "chain-directory-secret"
	chainDirectoryKey     = chainDirectoryPublic + "." + chainDirectorySecret
	lookupUsersPath       = "/identity.v1.IdentityService/LookupUsers"
)

// chainCredentials is a one-credential DirectoryCredentialStore standing in
// for the postgres control plane, so the served chain can be driven on the
// memory driver.
type chainCredentials struct {
	cred *service.AdminProjectCredential
}

func (c chainCredentials) ProjectCredentialByPublicID(_ context.Context, publicID string) (*service.AdminProjectCredential, error) {
	if publicID != c.cred.PublicID {
		return nil, nil
	}
	cp := *c.cred
	return &cp, nil
}

func newDirectoryChainApp(t *testing.T) (http.Handler, service.Repository) {
	t.Helper()
	sum := sha256.Sum256([]byte(chainDirectorySecret))
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Identity Test", Origin: "http://localhost:9002"})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	repo := memory.New()
	built, err := New(Deps{
		Config:             newTestConfig(),
		Logger:             zap.NewNop(),
		Signer:             jwttest.NewSigner(t, "directory-chain"),
		Repo:               repo,
		DB:                 repo,
		Passkeys:           pk,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		DirectoryCredentials: chainCredentials{cred: &service.AdminProjectCredential{
			ID:         "cred-chain",
			ProjectID:  chainDirectoryProject,
			Kind:       service.CredentialKindDirectoryReader,
			PublicID:   chainDirectoryPublic,
			SecretHash: hex.EncodeToString(sum[:]),
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	built.Start()
	t.Cleanup(built.Stop)
	return built.Handler, repo
}

// postRPC issues a Connect unary JSON call through the served chain.
func postRPC(t *testing.T, h http.Handler, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestDirectoryLookup_ServedThroughFullChain proves the JWT-exempt LookupUsers
// reaches its handler with only a directory key, resolves the credential's
// project (not the Host-resolved default one), and discloses the minimal
// profile.
func TestDirectoryLookup_ServedThroughFullChain(t *testing.T) {
	h, repo := newDirectoryChainApp(t)
	ctx := context.Background()
	inProject, err := service.ProjectBoundRepository(repo, chainDirectoryProject).CreateUser(ctx, &service.User{
		Email: "staff@corp.test", Name: "Staff", Status: service.StatusActive, PhoneNumber: "+15550100",
	})
	if err != nil {
		t.Fatalf("seed directory project: %v", err)
	}
	// Same address in the default project the request's Host resolves to.
	if _, err := repo.CreateUser(ctx, &service.User{Email: "staff@corp.test", Name: "Other", Status: service.StatusActive}); err != nil {
		t.Fatalf("seed default project: %v", err)
	}

	rec := postRPC(t, h, lookupUsersPath, `{"emails":["staff@corp.test"]}`,
		map[string]string{middleware.DirectoryKeyHeader: chainDirectoryKey})
	if rec.Code != http.StatusOK {
		t.Fatalf("LookupUsers: status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Users []map[string]any `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Users) != 1 || resp.Users[0]["id"] != inProject {
		t.Fatalf("users = %v, want only the credential project's account %q", resp.Users, inProject)
	}
	for field := range resp.Users[0] {
		switch field {
		case "id", "email", "name", "avatarUrl":
		default:
			t.Fatalf("directory entry discloses %q: %v", field, resp.Users[0])
		}
	}

	// Without the key, or with a wrong one, the RPC is refused.
	for name, hdr := range map[string]map[string]string{
		"no key":       nil,
		"wrong secret": {middleware.DirectoryKeyHeader: chainDirectoryPublic + ".nope"},
		"as bearer":    {"Authorization": "Bearer " + chainDirectoryKey},
	} {
		if rec := postRPC(t, h, lookupUsersPath, `{"emails":["staff@corp.test"]}`, hdr); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d body=%s, want 401", name, rec.Code, rec.Body.String())
		}
	}
}

// TestDirectoryKey_GrantsNothingElse walks EVERY IdentityService RPC and
// asserts presenting the directory key — in its own header and as a Bearer
// token — changes nothing: each RPC answers exactly as it does for a caller
// holding no credential at all. That is the read-only, single-RPC guarantee,
// held for RPCs added later too, since the list comes from the descriptor.
// The user-management RPCs are additionally pinned to 401.
func TestDirectoryKey_GrantsNothingElse(t *testing.T) {
	h, repo := newDirectoryChainApp(t)
	target, err := service.ProjectBoundRepository(repo, chainDirectoryProject).CreateUser(context.Background(),
		&service.User{Email: "victim@corp.test", Status: service.StatusActive})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	withKey := map[string]string{
		middleware.DirectoryKeyHeader: chainDirectoryKey,
		"Authorization":               "Bearer " + chainDirectoryKey,
	}

	methods := identitypb.File_identity_v1_identity_proto.Services().ByName("IdentityService").Methods()
	for i := 0; i < methods.Len(); i++ {
		name := string(methods.Get(i).Name())
		if name == "LookupUsers" {
			continue
		}
		path := "/identity.v1.IdentityService/" + name
		body := `{"userId":"` + target + `","email":"victim@corp.test"}`
		anonymous := postRPC(t, h, path, body, nil)
		keyed := postRPC(t, h, path, body, withKey)
		if keyed.Code == http.StatusOK && anonymous.Code != http.StatusOK {
			t.Errorf("%s: the directory key unlocked it (status %d, anonymous %d)", name, keyed.Code, anonymous.Code)
		}
		if keyed.Code != anonymous.Code {
			t.Errorf("%s: status with directory key = %d, without = %d — the key must change nothing", name, keyed.Code, anonymous.Code)
		}
	}

	for _, name := range []string{"ListUsers", "GetUser", "CreateUser", "UpdateUser", "DeleteUser", "DeactivateUser", "InviteUser", "ResetUserPassword"} {
		if rec := postRPC(t, h, "/identity.v1.IdentityService/"+name, `{"userId":"`+target+`"}`, withKey); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with the directory key: status = %d body=%s, want 401", name, rec.Code, rec.Body.String())
		}
	}

	u, err := service.ProjectBoundRepository(repo, chainDirectoryProject).GetUser(context.Background(), target)
	if err != nil || u == nil || u.Status != service.StatusActive || u.Email != "victim@corp.test" {
		t.Fatalf("target account changed under the directory key: %+v %v", u, err)
	}
}
