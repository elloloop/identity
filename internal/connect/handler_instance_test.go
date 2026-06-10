package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	"github.com/elloloop/identity/internal/config"
)

// bootstrapAdminPassword satisfies the strength policy (upper+lower+
// digit+special, not common) so the bootstrap itself isn't what fails.
const bootstrapAdminPassword = "Bootstrap1!"

// TestInstanceSignup_BootstrapsFirstAdmin drives the unauthenticated
// bootstrap end to end: the first call mints a role=admin session, and
// a second call is permanently refused with FailedPrecondition.
func TestInstanceSignup_BootstrapsFirstAdmin(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	resp, err := h.client.InstanceSignup(ctx, connect.NewRequest(&identitypb.InstanceSignupRequest{
		AdminEmail:    "owner@example.com",
		AdminPassword: bootstrapAdminPassword,
		AdminName:     "Owner",
	}))
	if err != nil {
		t.Fatalf("InstanceSignup: %v", err)
	}
	if resp.Msg.AdminUser == nil || resp.Msg.AdminUser.Role != "admin" {
		t.Fatalf("want role=admin user, got %#v", resp.Msg.AdminUser)
	}
	if resp.Msg.AccessToken == "" || resp.Msg.RefreshToken == "" {
		t.Fatal("want non-empty access + refresh tokens")
	}

	// Self-disabling: a second bootstrap (different email) must fail now
	// that an admin exists.
	_, err = h.client.InstanceSignup(ctx, connect.NewRequest(&identitypb.InstanceSignupRequest{
		AdminEmail:    "other@example.com",
		AdminPassword: bootstrapAdminPassword,
	}))
	if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("second InstanceSignup code = %v, want FailedPrecondition (err=%v)", got, err)
	}
}

// TestInstanceSignup_MultiMode_ReturnsUnimplemented confirms the RPC is
// single-mode only; in mode=multi OrganizationSignup is the entry point.
func TestInstanceSignup_MultiMode_ReturnsUnimplemented(t *testing.T) {
	h := newHarnessWith(t, nil, nil, func(cfg *config.Config) {
		cfg.IdentityMode = config.IdentityModeMulti
	})

	_, err := h.client.InstanceSignup(context.Background(), connect.NewRequest(&identitypb.InstanceSignupRequest{
		AdminEmail:    "owner@example.com",
		AdminPassword: bootstrapAdminPassword,
	}))
	if got := connect.CodeOf(err); got != connect.CodeUnimplemented {
		t.Fatalf("multi-mode InstanceSignup code = %v, want Unimplemented (err=%v)", got, err)
	}
}
