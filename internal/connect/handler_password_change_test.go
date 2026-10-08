package connect

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/passwords"
)

// An administrator-issued password signs in only to be replaced: the
// refusal carries the ticket, and the completion RPC — reached without a
// session — sets the user's own password and opens one.
func TestCompleteRequiredPasswordChange_OverTheWire(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	hash, err := passwords.Hash("Issu3d!Temp0rary")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := h.repo.CreateUser(ctx, &service.User{
		Email: "issued@example.com", Status: service.StatusActive, Role: "member",
		PasswordHash: hash, PasswordChangeRequired: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	_, err = h.client.PasswordLogin(ctx, withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: "issued@example.com", Password: "Issu3d!Temp0rary",
	})))
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr.Code() != connect.CodeFailedPrecondition {
		t.Fatalf("login with an issued password: want FailedPrecondition, got %v", err)
	}
	var ticket string
	for _, d := range cerr.Details() {
		if msg, derr := d.Value(); derr == nil {
			if pc, ok := msg.(*identitypb.PasswordChangeRequiredDetails); ok {
				ticket = pc.CompletionToken
			}
		}
	}
	if ticket == "" {
		t.Fatal("the refusal carries no PasswordChangeRequiredDetails ticket")
	}

	res, err := h.client.CompleteRequiredPasswordChange(ctx, withClientHeaders(connect.NewRequest(&identitypb.CompleteRequiredPasswordChangeRequest{
		CompletionToken: ticket, NewPassword: "My0wn!Passw0rd",
	})))
	if err != nil {
		t.Fatalf("CompleteRequiredPasswordChange: %v", err)
	}
	if res.Msg.AccessToken == "" || res.Msg.User.GetPasswordChangeRequired() {
		t.Fatalf("want a session and the flag cleared, got %+v", res.Msg)
	}

	if _, err := h.client.PasswordLogin(ctx, withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: "issued@example.com", Password: "My0wn!Passw0rd",
	}))); err != nil {
		t.Fatalf("login with the new password: %v", err)
	}
}
