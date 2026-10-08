package connect

import (
	"testing"

	"github.com/elloloop/identity/internal/service"
)

func TestUserToProto_CarriesAccountAddress(t *testing.T) {
	got := userToProto(&service.User{ID: "u1", Username: "bob", AccountAddress: "bob@accounts.example.test"})
	if got.AccountAddress != "bob@accounts.example.test" {
		t.Fatalf("AccountAddress = %q", got.AccountAddress)
	}
}
