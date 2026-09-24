//go:build integration && realpostgres

package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
)

// directoryClient returns a Connect client presenting a directory credential
// in X-Directory-Key and nothing else.
func (h *RedesignHarness) directoryClient(rawKey string) identityconnectgen.IdentityServiceClient {
	return h.ClientWithHost("", map[string]string{middleware.DirectoryKeyHeader: rawKey})
}

func mintDirectoryKey(t *testing.T, h *RedesignHarness, projectID string) *identitypb.AdminCreateProjectCredentialResponse {
	t.Helper()
	resp, err := h.adminClient(harnessAdminSecret).AdminCreateProjectCredential(context.Background(),
		connect.NewRequest(&identitypb.AdminCreateProjectCredentialRequest{
			ProjectId: projectID,
			Kind:      service.CredentialKindDirectoryReader,
		}))
	if err != nil {
		t.Fatalf("AdminCreateProjectCredential(directory_reader): %v", err)
	}
	return resp.Msg
}

func requireConnectCode(t *testing.T, what string, err error, want connect.Code) {
	t.Helper()
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr.Code() != want {
		t.Fatalf("%s: err = %v, want %v", what, err, want)
	}
}

// TestRedesign_DirectoryLookup_Flow drives the directory credential through
// the composition root against a real Postgres: an operator mints a
// directory_reader key, a service resolves addresses with it (active accounts
// only, exact match, its own project only), the key opens no other RPC, and
// revocation takes effect on the next call.
func TestRedesign_DirectoryLookup_Flow(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	unique := time.Now().UnixNano()
	addr := func(local string) string { return fmt.Sprintf("%s-%d@corp-example.com", local, unique) }

	// Two members of the default project; one is then deactivated.
	alice := signupMembershipUser(t, h, addr("alice"))
	bob := signupMembershipUser(t, h, addr("bob"))
	if err := h.Stores.users.UpdateUser(ctx, bob.userID, map[string]any{"status": service.StatusDeactivated}); err != nil {
		t.Fatalf("deactivate bob: %v", err)
	}

	// A second project holding an account at alice's address.
	admin := h.adminClient(harnessAdminSecret)
	other, err := admin.AdminCreateProject(ctx, connect.NewRequest(&identitypb.AdminCreateProjectRequest{
		Name: "Other", StorageScopeId: fmt.Sprintf("dir-other-%d", unique),
	}))
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	otherProject := other.Msg.GetProjectId()
	otherAlice, err := service.ProjectBoundRepository(h.Stores.users, otherProject).CreateUser(ctx, &service.User{
		Email: addr("alice"), Status: service.StatusActive, Role: "member",
	})
	if err != nil {
		t.Fatalf("seed other project: %v", err)
	}

	minted := mintDirectoryKey(t, h, h.ProjectID)
	directory := h.directoryClient(minted.GetRawKey())

	resp, err := directory.LookupUsers(ctx, connect.NewRequest(&identitypb.LookupUsersRequest{
		Emails: []string{addr("bob"), addr("ALICE"), addr("nobody"), "alice", "corp-example.com"},
	}))
	if err != nil {
		t.Fatalf("LookupUsers: %v", err)
	}
	users := resp.Msg.GetUsers()
	if len(users) != 1 || users[0].GetId() != alice.userID || users[0].GetEmail() != addr("alice") {
		t.Fatalf("LookupUsers = %v, want only alice (%s) from the default project", users, alice.userID)
	}

	// The other project's key sees the other project's alice, never ours.
	otherKey := mintDirectoryKey(t, h, otherProject)
	resp, err = h.directoryClient(otherKey.GetRawKey()).LookupUsers(ctx, connect.NewRequest(&identitypb.LookupUsersRequest{
		Emails: []string{addr("alice")},
	}))
	if err != nil {
		t.Fatalf("LookupUsers (other project): %v", err)
	}
	if got := resp.Msg.GetUsers(); len(got) != 1 || got[0].GetId() != otherAlice {
		t.Fatalf("other project's key saw %v, want only %s", got, otherAlice)
	}

	// The key opens nothing else — neither as X-Directory-Key nor as Bearer.
	asBearer := h.AuthedClient(minted.GetRawKey())
	_, err = directory.ListUsers(ctx, connect.NewRequest(&identitypb.ListUsersRequest{}))
	requireConnectCode(t, "ListUsers with the directory key", err, connect.CodeUnauthenticated)
	_, err = asBearer.ListUsers(ctx, connect.NewRequest(&identitypb.ListUsersRequest{}))
	requireConnectCode(t, "ListUsers with the directory key as Bearer", err, connect.CodeUnauthenticated)
	_, err = asBearer.UpdateUser(ctx, connect.NewRequest(&identitypb.UpdateUserRequest{UserId: alice.userID, Name: "pwned"}))
	requireConnectCode(t, "UpdateUser with the directory key", err, connect.CodeUnauthenticated)
	_, err = asBearer.DeleteUser(ctx, connect.NewRequest(&identitypb.DeleteUserRequest{UserId: alice.userID}))
	requireConnectCode(t, "DeleteUser with the directory key", err, connect.CodeUnauthenticated)
	_, err = h.ClientWithHost("", map[string]string{middleware.AdminAPISecretHeader: minted.GetRawKey()}).
		AdminRevokeProjectCredential(ctx, connect.NewRequest(&identitypb.AdminRevokeProjectCredentialRequest{
			ProjectId: h.ProjectID, CredentialId: minted.GetCredentialId(),
		}))
	requireConnectCode(t, "admin RPC with the directory key", err, connect.CodePermissionDenied)

	// Revocation is immediate.
	if _, err := admin.AdminRevokeProjectCredential(ctx, connect.NewRequest(&identitypb.AdminRevokeProjectCredentialRequest{
		ProjectId: h.ProjectID, CredentialId: minted.GetCredentialId(),
	})); err != nil {
		t.Fatalf("AdminRevokeProjectCredential: %v", err)
	}
	_, err = directory.LookupUsers(ctx, connect.NewRequest(&identitypb.LookupUsersRequest{Emails: []string{addr("alice")}}))
	requireConnectCode(t, "LookupUsers after revocation", err, connect.CodeUnauthenticated)

	// A credential id that is not the project's is NotFound, not a silent success.
	_, err = admin.AdminRevokeProjectCredential(ctx, connect.NewRequest(&identitypb.AdminRevokeProjectCredentialRequest{
		ProjectId: h.ProjectID, CredentialId: otherKey.GetCredentialId(),
	}))
	requireConnectCode(t, "revoke another project's credential", err, connect.CodeNotFound)
}
