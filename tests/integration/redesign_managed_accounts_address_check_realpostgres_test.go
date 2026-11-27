//go:build integration && realpostgres

package integration

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/service"
)

// checkAddresses asks caller's client about username@domain pairs for
// tenantID, returning the statuses in order.
func checkAddresses(client identityconnectgen.IdentityServiceClient, tenantID string, pairs ...[2]string) ([]identitypb.ManagedAddressStatus, error) {
	req := &identitypb.CheckManagedAddressesRequest{TenantId: tenantID}
	for _, p := range pairs {
		req.Addresses = append(req.Addresses, &identitypb.ManagedAddress{Username: p[0], Domain: p[1]})
	}
	resp, err := client.CheckManagedAddresses(context.Background(), connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	out := make([]identitypb.ManagedAddressStatus, 0, len(resp.Msg.GetResults()))
	for _, r := range resp.Msg.GetResults() {
		out = append(out, r.GetStatus())
	}
	return out, nil
}

// TestRedesign_ManagedAccounts_CheckAddresses drives the address check
// against a real Postgres: an owner or admin learns, for addresses on the
// tenant's verified domain, which are free, already the tenant's, or held
// outside it, and nothing about any other domain, another tenant's
// included; a member, and another tenant's owner, learn nothing; and with
// managed accounts dark the check is refused with POLICY.
func TestRedesign_ManagedAccounts_CheckAddresses(t *testing.T) {
	h := startRedesignHarnessWith(t, enableManagedAccounts)
	setProjectConfig(t, h, managedAccountsConfig)
	ctx := context.Background()
	mt := newManagedTenant(t, h, "managed-check")
	other := newManagedTenant(t, h, "managed-check-other")
	if _, err := createManaged(mt.owner, "ann", mt.domain, "Ann", "ann@example.net", service.RoleMember); err != nil {
		t.Fatalf("create: %v", err)
	}
	signupBranded(t, h, "bob@"+mt.domain)
	if _, err := createManaged(other.owner, "cat", other.domain, "Cat", "cat@example.net", service.RoleMember); err != nil {
		t.Fatalf("create in the other tenant: %v", err)
	}

	pairs := [][2]string{
		{"new", mt.domain},
		{"ann", mt.domain},
		{"bob", mt.domain},
		{"cat", other.domain},
		{"x..y", mt.domain},
	}
	want := []identitypb.ManagedAddressStatus{
		identitypb.ManagedAddressStatus_MANAGED_ADDRESS_STATUS_FREE,
		identitypb.ManagedAddressStatus_MANAGED_ADDRESS_STATUS_MANAGED_BY_THIS_TENANT,
		identitypb.ManagedAddressStatus_MANAGED_ADDRESS_STATUS_ADDRESS_UNAVAILABLE,
		identitypb.ManagedAddressStatus_MANAGED_ADDRESS_STATUS_DOMAIN_UNVERIFIED,
		identitypb.ManagedAddressStatus_MANAGED_ADDRESS_STATUS_INVALID,
	}
	for name, caller := range map[string]ownerCaller{"owner": mt.owner, "admin": mt.admin} {
		got, err := checkAddresses(caller.client, mt.tenantID, pairs...)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: statuses = %v, want %v", name, got, want)
			}
		}
	}

	if _, err := checkAddresses(other.owner.client, mt.tenantID, pairs[0]); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("another tenant's owner checking this tenant = %v, want PermissionDenied", err)
	}
	got, err := checkAddresses(other.owner.client, other.tenantID, [2]string{"ann", mt.domain})
	if err != nil || got[0] != identitypb.ManagedAddressStatus_MANAGED_ADDRESS_STATUS_DOMAIN_UNVERIFIED {
		t.Fatalf("probing another tenant's domain = %v %v, want DOMAIN_UNVERIFIED", got, err)
	}

	setUpToken := extractMailedToken(t, h, "ann@example.net")
	done, err := setUp(h, setUpToken, validPassword)
	if err != nil {
		t.Fatalf("set up: %v", err)
	}
	if _, err := checkAddresses(brandedClient(h, done.GetAccessToken()), mt.tenantID, pairs[0]); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("a member checking = %v, want PermissionDenied", err)
	}

	if _, err := mt.owner.client.CheckManagedAddresses(ctx, connect.NewRequest(&identitypb.CheckManagedAddressesRequest{TenantId: mt.tenantID})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("no addresses = %v, want InvalidArgument", err)
	}

	setProjectConfig(t, h, `{"access":{"mode":"open"}}`)
	_, err = checkAddresses(mt.owner.client, mt.tenantID, pairs[0])
	requireManagedRefusal(t, "checking while the project is not opted in", err,
		connect.CodeFailedPrecondition, identitypb.ManagedAccountRefusal_MANAGED_ACCOUNT_REFUSAL_POLICY)
}
