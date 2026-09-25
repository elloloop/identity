package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/service"
)

// startDirectoryServer mounts a handler wired with the control-plane admin
// service (to mint and revoke credentials) and, unless disabled, the directory
// service reading repo through the same credential store.
func startDirectoryServer(t *testing.T, repo *fakeRepo, withDirectory bool) identityconnectgen.IdentityServiceClient {
	t.Helper()
	admin, store, _ := newAdminControlSvc(handlerAdminSecret)
	var directory *service.DirectoryService
	if withDirectory {
		directory = service.NewDirectoryService(store, repo, true, nil)
	}
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, nil, admin, directory, testConfig())
	mux := http.NewServeMux()
	path, handler := identityconnectgen.NewIdentityServiceHandler(h)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return identityconnectgen.NewIdentityServiceClient(srv.Client(), srv.URL)
}

func withDirectoryKey(msg *identitypb.LookupUsersRequest, key string) *connect.Request[identitypb.LookupUsersRequest] {
	req := connect.NewRequest(msg)
	req.Header().Set(DirectoryKeyHeader, key)
	return req
}

func TestLookupUsers_NoControlPlane_Unimplemented(t *testing.T) {
	t.Parallel()
	client := startDirectoryServer(t, newFakeRepo(), false)
	_, err := client.LookupUsers(context.Background(),
		withDirectoryKey(&identitypb.LookupUsersRequest{Emails: []string{"a@corp.test"}}, "dk_x.y"))
	requireCode(t, err, connect.CodeUnimplemented)
}

// TestLookupUsers_MintLookupRevoke drives the operator flow end to end over
// Connect: mint a directory_reader credential, resolve addresses with it,
// revoke it, and watch the next lookup be refused.
func TestLookupUsers_MintLookupRevoke(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := newFakeRepo()
	alice, err := repo.CreateUser(ctx, &service.User{
		Email: "alice@corp.test", Name: "Alice", AvatarURL: "https://cdn.test/a.png",
		Status: service.StatusActive, PhoneNumber: "+15550100", Role: "admin", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := repo.CreateUser(ctx, &service.User{Email: "gone@corp.test", Status: service.StatusDeactivated, EmailVerified: true}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	client := startDirectoryServer(t, repo, true)

	minted, err := client.AdminCreateProjectCredential(ctx, withAdminSecret(&identitypb.AdminCreateProjectCredentialRequest{
		ProjectId: "proj-1", Kind: service.CredentialKindDirectoryReader,
	}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	key := minted.Msg.GetRawKey()

	resp, err := client.LookupUsers(ctx, withDirectoryKey(&identitypb.LookupUsersRequest{
		Emails: []string{"gone@corp.test", "Alice@Corp.Test", "nobody@corp.test"},
	}, key))
	if err != nil {
		t.Fatalf("LookupUsers: %v", err)
	}
	users := resp.Msg.GetUsers()
	if len(users) != 1 {
		t.Fatalf("users = %v, want only the active account", users)
	}
	want := &identitypb.DirectoryUser{
		Id: alice, Email: "alice@corp.test", Name: "Alice", AvatarUrl: "https://cdn.test/a.png", EmailVerified: true,
		RequestedEmails: []string{"Alice@Corp.Test"},
	}
	if users[0].String() != want.String() {
		t.Fatalf("user = %v, want %v", users[0], want)
	}

	// The key is read from X-Directory-Key only: as a Bearer token it is
	// nothing to this RPC.
	bearer := connect.NewRequest(&identitypb.LookupUsersRequest{Emails: []string{"alice@corp.test"}})
	bearer.Header().Set("Authorization", "Bearer "+key)
	_, err = client.LookupUsers(ctx, bearer)
	requireCode(t, err, connect.CodeUnauthenticated)

	_, err = client.LookupUsers(ctx, withDirectoryKey(&identitypb.LookupUsersRequest{}, key))
	requireCode(t, err, connect.CodeInvalidArgument)

	if _, err := client.AdminRevokeProjectCredential(ctx, withAdminSecret(&identitypb.AdminRevokeProjectCredentialRequest{
		ProjectId: "proj-1", CredentialId: minted.Msg.GetCredentialId(),
	}, handlerAdminSecret)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err = client.LookupUsers(ctx, withDirectoryKey(&identitypb.LookupUsersRequest{Emails: []string{"alice@corp.test"}}, key))
	requireCode(t, err, connect.CodeUnauthenticated)

	_, err = client.AdminRevokeProjectCredential(ctx, withAdminSecret(&identitypb.AdminRevokeProjectCredentialRequest{
		ProjectId: "proj-2", CredentialId: minted.Msg.GetCredentialId(),
	}, handlerAdminSecret))
	requireCode(t, err, connect.CodeNotFound)
}
