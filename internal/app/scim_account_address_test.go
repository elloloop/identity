package app

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/scim"
)

// A SCIM write that changes an email account's email re-derives its account
// address, as a confirmed self-service change does; one that leaves the email
// alone, or touches a username account, keeps the address.
func TestSCIM_EmailChangeFollowsTheAccountAddress(t *testing.T) {
	cfg, err := service.ParseProjectConfig(`{"access":{"mode":"open"},"accounts":{"domain":"accounts.example.test"}}`)
	if err != nil {
		t.Fatal(err)
	}
	ctx := service.WithProjectScope(context.Background(), &service.ProjectScope{ProjectID: "p", Access: cfg.Access, Accounts: cfg.Accounts})
	repo := memory.New()
	s := &repoSCIMStore{repo: repo, logger: zap.NewNop()}

	id, err := repo.CreateUser(ctx, &service.User{
		Email: "old@mail.example.test", EmailVerified: true, Status: "active",
		AccountAddress: "old-at-mail.example.test@accounts.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceUser(ctx, id, scim.User{Email: "old@mail.example.test", GivenName: "Renamed", Active: true}); err != nil {
		t.Fatal(err)
	}
	if u, _ := repo.GetUser(ctx, id); u.AccountAddress != "old-at-mail.example.test@accounts.example.test" {
		t.Fatalf("unchanged email kept the address: got %q", u.AccountAddress)
	}

	newEmail := "new@mail.example.test"
	if _, err := s.PatchUser(ctx, id, scim.UserPatch{Email: &newEmail}); err != nil {
		t.Fatal(err)
	}
	// SCIM is the identity provider's word for the email, and it leaves the
	// verified flag as it was, so the address follows straight away.
	u, _ := repo.GetUser(ctx, id)
	if u.AccountAddress != "new-at-mail.example.test@accounts.example.test" {
		t.Fatalf("address after a SCIM email change: %q", u.AccountAddress)
	}
}
