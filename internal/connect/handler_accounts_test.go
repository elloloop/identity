package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// With no project policy choosing them, username accounts are off: neither a
// person nor an admin can create one.
func TestUsernameAccounts_OffByDefault(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.addUser("admin-1", "admin@e.com", "Admin", "admin", "active")

	_, err := h.client.UsernameSignup(ctx, withClientHeaders(connect.NewRequest(&identitypb.UsernameSignupRequest{
		Username: "bob", Password: strongPW,
	})))
	if connectCodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("UsernameSignup: want FailedPrecondition, got %v: %v", connectCodeOf(err), err)
	}

	_, err = h.client.CreateUser(ctx, authedReq(connect.NewRequest(&identitypb.CreateUserRequest{
		Username: "bob",
	}), "admin-1"))
	if connectCodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("CreateUser(username): want FailedPrecondition, got %v: %v", connectCodeOf(err), err)
	}
}

func TestCreateUser_EmailAndUsernameIsInvalid(t *testing.T) {
	h := newHarness(t)
	h.db.addUser("admin-1", "admin@e.com", "Admin", "admin", "active")
	_, err := h.client.CreateUser(context.Background(), authedReq(connect.NewRequest(&identitypb.CreateUserRequest{
		Email: "bob@e.com", Username: "bob",
	}), "admin-1"))
	if connectCodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want InvalidArgument, got %v: %v", connectCodeOf(err), err)
	}
}

func TestUsernameSignup_SignupDisabled(t *testing.T) {
	h := newHarness(t)
	h.cfg.PasswordSignupEnabled = false
	_, err := h.client.UsernameSignup(context.Background(), connect.NewRequest(&identitypb.UsernameSignupRequest{
		Username: "bob", Password: strongPW,
	}))
	if connectCodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want FailedPrecondition, got %v: %v", connectCodeOf(err), err)
	}
}

func TestToConnectError_SignupThrottledIsResourceExhausted(t *testing.T) {
	if got := connectCodeOf(toConnectError(service.ErrSignupThrottled)); got != connect.CodeResourceExhausted {
		t.Fatalf("code = %v, want ResourceExhausted", got)
	}
	if got := connectCodeOf(toConnectError(service.ErrAccountKindOff)); got != connect.CodeFailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", got)
	}
}
