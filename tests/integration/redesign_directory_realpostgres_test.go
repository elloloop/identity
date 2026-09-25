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
	"github.com/elloloop/identity/internal/config"
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
// revocation takes effect on the next call — under both revocation modes,
// since session mode decorates the repository the lookup binds to the
// credential's project.
func TestRedesign_DirectoryLookup_Flow(t *testing.T) {
	for name, mode := range map[string]config.RevocationMode{
		"ttl":     config.RevocationModeTTL,
		"session": config.RevocationModeSession,
	} {
		t.Run(name, func(t *testing.T) {
			directoryLookupFlow(t, startRedesignHarnessWith(t, func(cfg *config.Config) { cfg.RevocationMode = mode }))
		})
	}
}

// otherAliceName tells the second project's account apart from the default
// project's one at the same address.
const otherAliceName = "Other Project Alice"

func directoryLookupFlow(t *testing.T, h *RedesignHarness) {
	t.Helper()
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
	otherAlice, err := h.Stores.users.WithProject(otherProject).CreateUser(ctx, &service.User{
		Email: addr("alice"), Name: otherAliceName, Status: service.StatusActive, Role: "member",
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
	if len(users) != 1 || users[0].GetId() != alice.userID || users[0].GetEmail() != addr("alice") || users[0].GetName() == otherAliceName ||
		users[0].GetEmailVerified() {
		t.Fatalf("LookupUsers = %v, want only alice (%s, unverified password signup) from the default project", users, alice.userID)
	}

	// The other project's key sees the other project's alice, never ours.
	otherKey := mintDirectoryKey(t, h, otherProject)
	resp, err = h.directoryClient(otherKey.GetRawKey()).LookupUsers(ctx, connect.NewRequest(&identitypb.LookupUsersRequest{
		Emails: []string{addr("alice")},
	}))
	if err != nil {
		t.Fatalf("LookupUsers (other project): %v", err)
	}
	if got := resp.Msg.GetUsers(); len(got) != 1 || got[0].GetId() != otherAlice || got[0].GetName() != otherAliceName {
		t.Fatalf("other project's key saw %v, want only %s (%s)", got, otherAlice, otherAliceName)
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

// TestRedesign_DirectoryLookup_VerifiedEmail drives GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL
// through the directory lookup on an open-signup project. Anyone can sign up
// with an address they do not own; while verified email is required that
// account is not returned, and it is once the owner confirms the mailed link.
// With the requirement off it is returned throughout, flagged unverified until
// then.
func TestRedesign_DirectoryLookup_VerifiedEmail(t *testing.T) {
	for _, required := range []bool{true, false} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			h := startRedesignHarnessWith(t, func(cfg *config.Config) { cfg.AuthRequireVerifiedEmail = required })
			ctx := context.Background()
			addr := fmt.Sprintf("claimed-%d@corp-example.com", time.Now().UnixNano())

			signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
				Email: addr, Password: validPassword,
			}))
			if err != nil {
				t.Fatalf("PasswordSignup: %v", err)
			}
			userID := signup.Msg.GetUser().GetId()

			directory := h.directoryClient(mintDirectoryKey(t, h, h.ProjectID).GetRawKey())
			lookup := func() []*identitypb.DirectoryUser {
				t.Helper()
				resp, err := directory.LookupUsers(ctx, connect.NewRequest(&identitypb.LookupUsersRequest{Emails: []string{addr}}))
				if err != nil {
					t.Fatalf("LookupUsers: %v", err)
				}
				return resp.Msg.GetUsers()
			}

			got := lookup()
			switch {
			case required && len(got) != 0:
				t.Fatalf("unverified sign-up returned while verified email is required: %v", got)
			case !required && (len(got) != 1 || got[0].GetId() != userID || got[0].GetEmailVerified()):
				t.Fatalf("LookupUsers = %v, want %s flagged unverified", got, userID)
			}

			if _, err := h.Client.VerifyEmail(ctx, connect.NewRequest(&identitypb.VerifyEmailRequest{
				Token: extractMailedToken(t, h, addr),
			})); err != nil {
				t.Fatalf("VerifyEmail: %v", err)
			}
			if got := lookup(); len(got) != 1 || got[0].GetId() != userID || !got[0].GetEmailVerified() {
				t.Fatalf("after verification LookupUsers = %v, want %s verified", got, userID)
			}
		})
	}
}
