package connect

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/passwords"
)

// The kept account's session must come from a recent sign-in; the handler
// reads it from the auth_time the auth middleware verified.
func TestMergeAccounts_Handler_RequiresARecentSignIn(t *testing.T) {
	h := newHarnessWith(t, nil, nil, func(c *config.Config) {
		c.AccountMergeEnabled = true
	})
	ctx := context.Background()
	now := time.Now()
	survivorID, err := h.repo.CreateUser(ctx, &service.User{
		Email: "kept@example.com", EmailVerified: true, Status: service.StatusActive, Role: "member",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := passwords.Hash(strongPW)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.repo.CreateUser(ctx, &service.User{
		Username: "bob", Status: service.StatusActive, Role: "member", PasswordHash: hash,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	merge := func(authTime int64) error {
		req := authedReq(withClientHeaders(connect.NewRequest(&identitypb.MergeAccountsRequest{
			OtherIdentifier: "bob", OtherPassword: strongPW,
		})), survivorID)
		if authTime != 0 {
			req.Header().Set(middleware.AuthenticatedAuthTimeHeader, strconv.FormatInt(authTime, 10))
		}
		_, err := h.client.MergeAccounts(ctx, req)
		return err
	}

	for name, authTime := range map[string]int64{
		"no sign-in time": 0,
		"an hour ago":     now.Add(-time.Hour).Unix(),
	} {
		err := merge(authTime)
		if connectCodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "reauthentication_required") {
			t.Fatalf("%s: want FailedPrecondition reauthentication_required, got %v", name, err)
		}
	}
	if err := merge(now.Unix()); err != nil {
		t.Fatalf("a fresh sign-in: %v", err)
	}
	kept, _ := h.repo.GetUser(ctx, survivorID)
	if kept.Username != "bob" {
		t.Fatalf("the kept account did not take the username: %+v", kept)
	}
}
