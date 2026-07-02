//go:build integration

package integration

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
)

// TestOAuthAdmin_Unimplemented_WithoutControlPlane asserts the per-project OAuth
// provider admin RPCs are control-plane-only: on a driver with no control plane
// (memory/sqlite — the bare app the standard harness wires) they return
// UNIMPLEMENTED, exactly like every other operator RPC. The full authoring loop
// is exercised against a real control plane in the realpostgres suite.
func TestOAuthAdmin_Unimplemented_WithoutControlPlane(t *testing.T) {
	h := StartServer(t)
	ctx := context.Background()

	_, err := h.Client.AdminSetProjectOAuthProvider(ctx, connect.NewRequest(&identitypb.AdminSetProjectOAuthProviderRequest{
		ProjectId: "p",
		Config:    &identitypb.ProjectOAuthProviderConfig{Provider: "google", ClientId: "g", ClientSecret: "s"},
	}))
	if got := connect.CodeOf(err); got != connect.CodeUnimplemented {
		t.Fatalf("AdminSetProjectOAuthProvider code = %v, want Unimplemented", got)
	}

	_, err = h.Client.AdminDeleteProjectOAuthProvider(ctx, connect.NewRequest(&identitypb.AdminDeleteProjectOAuthProviderRequest{
		ProjectId: "p", Provider: "google",
	}))
	if got := connect.CodeOf(err); got != connect.CodeUnimplemented {
		t.Fatalf("AdminDeleteProjectOAuthProvider code = %v, want Unimplemented", got)
	}

	_, err = h.Client.AdminListProjectOAuthProviders(ctx, connect.NewRequest(&identitypb.AdminListProjectOAuthProvidersRequest{
		ProjectId: "p",
	}))
	if got := connect.CodeOf(err); got != connect.CodeUnimplemented {
		t.Fatalf("AdminListProjectOAuthProviders code = %v, want Unimplemented", got)
	}
}
