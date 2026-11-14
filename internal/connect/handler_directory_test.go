package connect

import (
	"context"
	"crypto/sha256"
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

func TestMatchTenantMemberPhones_NoControlPlane_Unimplemented(t *testing.T) {
	t.Parallel()
	client := startDirectoryServer(t, newFakeRepo(), false)
	req := connect.NewRequest(&identitypb.MatchTenantMemberPhonesRequest{TenantId: "t-acme", PhoneNumberHashes: [][]byte{make([]byte, 32)}})
	req.Header().Set(DirectoryKeyHeader, "dk_x.y")
	_, err := client.MatchTenantMemberPhones(context.Background(), req)
	requireCode(t, err, connect.CodeUnimplemented)
}

// TestMatchTenantMemberPhones_OverConnect drives the match with a minted
// directory_reader credential: the members the store found come back, a
// tenant outside the credential's project is PERMISSION_DENIED, a batch over
// the cap is INVALID_ARGUMENT, a spent budget is RESOURCE_EXHAUSTED, and the
// credential is read from X-Directory-Key alone, never from a bearer token.
func TestMatchTenantMemberPhones_OverConnect(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	admin, store, _ := newAdminControlSvc(handlerAdminSecret)
	members := &connectMembershipStore{phoneTenant: "t-acme", phoneMatches: []string{"user-1", "user-2"}}
	directory := service.NewDirectoryService(store, newFakeRepo(), true, nil).WithTenantMemberPhones(members, 2, 60_000)
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, nil, admin, directory, testConfig())
	mux := http.NewServeMux()
	path, handler := identityconnectgen.NewIdentityServiceHandler(h)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := identityconnectgen.NewIdentityServiceClient(srv.Client(), srv.URL)

	minted, err := client.AdminCreateProjectCredential(ctx, withAdminSecret(&identitypb.AdminCreateProjectCredentialRequest{
		ProjectId: "proj-1", Kind: service.CredentialKindDirectoryReader,
	}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	key := minted.Msg.GetRawKey()
	hash := sha256.Sum256([]byte("+14155550123"))
	match := func(tenantID string, hashes [][]byte, header, value string) (*connect.Response[identitypb.MatchTenantMemberPhonesResponse], error) {
		req := connect.NewRequest(&identitypb.MatchTenantMemberPhonesRequest{TenantId: tenantID, PhoneNumberHashes: hashes})
		req.Header().Set(header, value)
		return client.MatchTenantMemberPhones(ctx, req)
	}

	resp, err := match("t-acme", [][]byte{hash[:]}, DirectoryKeyHeader, key)
	if err != nil {
		t.Fatalf("MatchTenantMemberPhones: %v", err)
	}
	if got := resp.Msg.GetUserIds(); len(got) != 2 || got[0] != "user-1" || got[1] != "user-2" {
		t.Fatalf("user_ids = %v, want the store's matches", got)
	}

	_, err = match("t-acme", [][]byte{hash[:]}, "Authorization", "Bearer "+key)
	requireCode(t, err, connect.CodeUnauthenticated)

	overCap := make([][]byte, service.MaxPhoneMatchHashes+1)
	for i := range overCap {
		overCap[i] = hash[:]
	}
	_, err = match("t-acme", overCap, DirectoryKeyHeader, key)
	requireCode(t, err, connect.CodeInvalidArgument)

	_, err = match("t-elsewhere", [][]byte{hash[:]}, DirectoryKeyHeader, key)
	requireCode(t, err, connect.CodePermissionDenied)

	if _, err := match("t-acme", [][]byte{hash[:]}, DirectoryKeyHeader, key); err != nil {
		t.Fatalf("second match within the budget: %v", err)
	}
	_, err = match("t-acme", [][]byte{hash[:]}, DirectoryKeyHeader, key)
	requireCode(t, err, connect.CodeResourceExhausted)
}
