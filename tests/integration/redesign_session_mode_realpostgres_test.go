//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
)

// TestRedesign_SessionMode_NonDefaultProject drives GATEWAY_REVOCATION_MODE=
// session on a project other than the boot default, over the wire against a
// real Postgres. The session row is written in the request's project, so the
// auth middleware must read it there (not in the default project), and a
// logout through the project-bound repository must still invalidate the
// session cache — the TTL here is long enough that only an invalidation can
// make the very next request fail.
func TestRedesign_SessionMode_NonDefaultProject(t *testing.T) {
	h := startRedesignHarnessWith(t, func(cfg *config.Config) {
		cfg.RevocationMode = config.RevocationModeSession
		cfg.SessionCacheTTLSeconds = 3600
	})
	ctx := context.Background()
	admin := h.adminClient(harnessAdminSecret)
	unique := time.Now().UnixNano()

	project, err := admin.AdminCreateProject(ctx, connect.NewRequest(&identitypb.AdminCreateProjectRequest{
		Name: "Session Mode", StorageScopeId: fmt.Sprintf("session-mode-%d", unique),
	}))
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	projectID := project.Msg.GetProjectId()
	host := fmt.Sprintf("session-mode-%d.acme.test", unique)
	if _, err := admin.AdminAddProjectAuthDomain(ctx, connect.NewRequest(&identitypb.AdminAddProjectAuthDomainRequest{
		ProjectId: projectID, Hostname: host, IsPrimary: true,
	})); err != nil {
		t.Fatalf("AdminAddProjectAuthDomain: %v", err)
	}
	openProjectAccess(t, h.Stores.controlPlane, projectID)

	signup, err := h.ClientWithHost(host, nil).PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: fmt.Sprintf("member-%d@corp-example.com", unique), Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup on %s: %v", host, err)
	}
	if got := decodeTokenProjectClaim(t, signup.Msg.GetAccessToken()); got != projectID {
		t.Fatalf("token project = %q, want %q", got, projectID)
	}
	authed := h.ClientWithHost(host, map[string]string{"Authorization": "Bearer " + signup.Msg.GetAccessToken()})

	sessions, err := authed.ListMySessions(ctx, connect.NewRequest(&identitypb.ListMySessionsRequest{}))
	if err != nil {
		t.Fatalf("ListMySessions with a fresh session: %v", err)
	}
	if len(sessions.Msg.GetSessions()) != 1 {
		t.Fatalf("sessions = %v, want the one just opened", sessions.Msg.GetSessions())
	}

	if _, err := h.ClientWithHost(host, nil).Logout(ctx, connect.NewRequest(&identitypb.LogoutRequest{
		RefreshToken: signup.Msg.GetRefreshToken(),
	})); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	_, err = authed.ListMySessions(ctx, connect.NewRequest(&identitypb.ListMySessionsRequest{}))
	requireConnectCode(t, "ListMySessions after logout", err, connect.CodeUnauthenticated)
}
