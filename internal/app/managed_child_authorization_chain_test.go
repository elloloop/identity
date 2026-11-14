package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
	identityconnect "github.com/elloloop/identity/internal/connect"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
	"go.uber.org/zap"
)

type managedChildChainResolver struct{}

func (managedChildChainResolver) ResolveByCredential(context.Context, string) (*service.ResolvedProject, error) {
	return nil, nil
}

func (managedChildChainResolver) ResolveByHostname(context.Context, string) (*service.ResolvedProject, error) {
	return &service.ResolvedProject{ID: chainDirectoryProject}, nil
}

func newManagedChildChainApp(t *testing.T, cfg *config.Config, resolver service.ProjectResolver) (http.Handler, service.Repository) {
	t.Helper()
	sum := sha256.Sum256([]byte(chainDirectorySecret))
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Identity Test", Origin: "http://localhost:9002"})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	repo := memory.New()
	built, err := New(Deps{
		Config:             cfg,
		ProjectResolver:    resolver,
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
			Kind:       service.CredentialKindManagedChildReader,
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

func TestManagedChildAuthorization_ServedChain(t *testing.T) {
	cfg := newTestConfig()
	cfg.DefaultProjectID = chainDirectoryProject
	cfg.AgeGateEnabled = true
	cfg.AgeGateChildMaxAge = 12
	cfg.AgeGateAdultAge = 18
	h, repo := newManagedChildChainApp(t, cfg, managedChildChainResolver{})
	ctx := context.Background()
	scoped := repo.WithProject(chainDirectoryProject)
	child, err := scoped.CreateUser(ctx, &service.User{Username: "child", Kind: service.UserKindPerson, Status: service.StatusActive, DateOfBirthMs: time.Now().AddDate(-8, 0, 0).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	guardian, err := scoped.CreateUser(ctx, &service.User{Email: "parent@example.test", Kind: service.UserKindPerson, Status: service.StatusActive, DateOfBirthMs: time.Now().AddDate(-35, 0, 0).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	if err := scoped.UpsertGuardianEdge(ctx, &service.GuardianEdge{ChildUserID: child, GuardianUserID: guardian}); err != nil {
		t.Fatal(err)
	}
	path := "/identity.v1.IdentityService/GetManagedChildAuthorization"
	body := `{"childUserId":"` + child + `","guardianUserId":"` + guardian + `"}`
	headers := map[string]string{identityconnect.ManagedChildKeyHeader: chainDirectoryKey}
	rec := postRPC(t, h, path, body, headers)
	if rec.Code != http.StatusOK {
		t.Fatalf("proof: %d %s", rec.Code, rec.Body.String())
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 || string(fields["authorized"]) != "true" {
		t.Fatalf("unsafe or denied response: %s", rec.Body.String())
	}
	if rec := postRPC(t, h, path, body, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key: %d", rec.Code)
	}
	headers["X-Project-Key"] = "pk_invalid"
	if rec := postRPC(t, h, path, body, headers); rec.Code == http.StatusOK {
		t.Fatal("invalid explicit project fell back")
	}
	delete(headers, "X-Project-Key")
	if err := scoped.DeleteGuardianEdge(ctx, guardian, child); err != nil {
		t.Fatal(err)
	}
	rec = postRPC(t, h, path, body, headers)
	fields = nil
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &fields) != nil || string(fields["authorized"]) == "true" {
		t.Fatalf("revocation: %d %s", rec.Code, rec.Body.String())
	}
}

func TestManagedChildKey_GrantsNoOtherRPC(t *testing.T) {
	cfg := newTestConfig()
	cfg.DefaultProjectID = chainDirectoryProject
	h, _ := newManagedChildChainApp(t, cfg, managedChildChainResolver{})
	headers := map[string]string{identityconnect.ManagedChildKeyHeader: chainDirectoryKey, "Authorization": "Bearer " + chainDirectoryKey}
	methods := identitypb.File_identity_v1_identity_proto.Services().ByName("IdentityService").Methods()
	for i := 0; i < methods.Len(); i++ {
		name := string(methods.Get(i).Name())
		if name == "GetManagedChildAuthorization" {
			continue
		}
		path := "/identity.v1.IdentityService/" + name
		without := postRPC(t, h, path, `{}`, nil)
		with := postRPC(t, h, path, `{}`, headers)
		if with.Code != without.Code {
			t.Errorf("%s: machine credential changed authorization %d -> %d", name, without.Code, with.Code)
		}
	}
}

func TestManagedChildAuthorization_NoProjectResolverIsUnavailable(t *testing.T) {
	cfg := newTestConfig()
	cfg.DefaultProjectID = chainDirectoryProject
	h, _ := newManagedChildChainApp(t, cfg, nil)
	rec := postRPC(t, h, "/identity.v1.IdentityService/GetManagedChildAuthorization", `{"childUserId":"child","guardianUserId":"guardian"}`, map[string]string{identityconnect.ManagedChildKeyHeader: chainDirectoryKey, "X-Project-Key": "pk_invalid"})
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("credential store without project policy resolver: %d %s", rec.Code, rec.Body.String())
	}
}
