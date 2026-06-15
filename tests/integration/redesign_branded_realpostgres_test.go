//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
)

// TestRedesign_BrandedResolution_ProjectToken asserts that a request whose
// Host is the seeded branded auth domain resolves to the default project, and
// that the access token a login mints under it carries the `project` claim.
func TestRedesign_BrandedResolution_ProjectToken(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()

	email := fmt.Sprintf("brand-%d@example-corp.com", time.Now().UnixNano())

	// Sign up via the BRANDED host so the request resolves to the default
	// project by Host→auth-domain (not the zero-config default pin). If
	// branded resolution were broken the token would carry no/other project.
	branded := h.ClientWithHost(h.BrandedAuthDomain, nil)
	signup, err := branded.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    email,
		Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup via branded host: %v", err)
	}
	if got := decodeTokenProjectClaim(t, signup.Msg.GetAccessToken()); got != h.ProjectID {
		t.Fatalf("signup access-token project claim = %q, want %q", got, h.ProjectID)
	}

	// A password login over the branded host carries the same project claim.
	login, err := branded.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    email,
		Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordLogin via branded host: %v", err)
	}
	if got := decodeTokenProjectClaim(t, login.Msg.GetAccessToken()); got != h.ProjectID {
		t.Fatalf("login access-token project claim = %q, want %q", got, h.ProjectID)
	}

	// The token resolved/minted under the default project authenticates a
	// request that also resolves to the default project (here, the default
	// host pin): GetCurrentUser succeeds, proving the project scope guard
	// does not reject a matching token.
	authed := h.AuthedClient(login.Msg.GetAccessToken())
	if _, err := authed.GetCurrentUser(ctx, connect.NewRequest(&identitypb.GetCurrentUserRequest{})); err != nil {
		t.Fatalf("GetCurrentUser with project token on matching project: %v", err)
	}
}

// TestRedesign_InvalidProjectKey_Unauthenticated asserts that an explicit but
// unknown X-Project-Key is rejected (Unauthenticated) rather than silently
// downgraded to the default project.
func TestRedesign_InvalidProjectKey_Unauthenticated(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()

	bad := h.ClientWithHost("", map[string]string{
		projectKeyHeader: "pk_does_not_exist",
	})
	_, err := bad.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    fmt.Sprintf("nokey-%d@example-corp.com", time.Now().UnixNano()),
		Password: validPassword,
	}))
	if err == nil {
		t.Fatal("PasswordSignup with invalid X-Project-Key: want error, got nil")
	}
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("invalid project key error code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}
