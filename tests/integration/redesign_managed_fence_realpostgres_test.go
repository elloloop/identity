//go:build integration && realpostgres

package integration

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

// managedReplica boots a second server on h's project with the same managed
// configuration and a minute-long session cache, standing for another replica
// whose cache no write on h reaches. Its boot opens the project's access
// again, so the project is made to admit managed accounts once more.
func managedReplica(t *testing.T, h *RedesignHarness) *RedesignHarness {
	t.Helper()
	defer setProjectConfig(t, h, managedAccountsConfig)
	return bootRedesignHarnessOn(t, h.ProjectID, h.TenantID, h.BrandedAuthDomain, func(c *config.Config) {
		enableManagedAccounts(c)
		c.SessionCacheTTLSeconds = 60
		c.AgentsEnabled = true
	}, NewRecordingMailer())
}

// TestRedesign_ManagedFence_AnotherReplicasCacheAttachesNothing: a managed
// admin's token whose session another replica still caches as live keeps
// passing that replica's session check after a reset or a suspension on the
// first, but attaches no credential and administers nothing there: the fence
// reads the account and the session from the store.
func TestRedesign_ManagedFence_AnotherReplicasCacheAttachesNothing(t *testing.T) {
	h := startManagedHarness(t, func(c *config.Config) { c.AgentsEnabled = true })
	m := newManagedMember(t, h, "managed-fence")
	ctx := context.Background()
	if _, err := m.owner.SetTenantMemberRole(ctx, connect.NewRequest(&identitypb.SetTenantMemberRoleRequest{
		TenantId: m.tenantID, UserId: m.userID, Role: service.RoleAdmin,
	})); err != nil {
		t.Fatalf("SetTenantMemberRole: %v", err)
	}
	b := managedReplica(t, h)
	login, err := brandedClient(b, "").PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{Email: m.address, Password: m.password}))
	if err != nil {
		t.Fatalf("PasswordLogin on the second replica: %v", err)
	}
	ann := brandedClient(b, login.Msg.GetAccessToken())
	if _, err := ann.ListTenantMembers(ctx, connect.NewRequest(&identitypb.ListTenantMembersRequest{TenantId: m.tenantID})); err != nil {
		t.Fatalf("ListTenantMembers while live: %v", err)
	}

	if _, err := m.owner.ResetManagedAccount(ctx, connect.NewRequest(&identitypb.ResetManagedAccountRequest{
		TenantId: m.tenantID, UserId: m.userID, DeliveryAddress: "ann.fence@example.net",
	})); err != nil {
		t.Fatalf("ResetManagedAccount: %v", err)
	}
	if _, err := ann.ListMySessions(ctx, connect.NewRequest(&identitypb.ListMySessionsRequest{})); err != nil {
		t.Fatalf("the second replica's cache no longer serves the session, so this test proves nothing: %v", err)
	}
	_, err = ann.ListTenantMembers(ctx, connect.NewRequest(&identitypb.ListTenantMembersRequest{TenantId: m.tenantID}))
	requireConnectCode(t, "a reset admin administering", err, connect.CodeFailedPrecondition)
	_, err = ann.BeginTotpSetup(ctx, connect.NewRequest(&identitypb.BeginTotpSetupRequest{}))
	requireConnectCode(t, "a reset account enrolling two-step", err, connect.CodeFailedPrecondition)
	_, err = ann.CreateAgent(ctx, connect.NewRequest(&identitypb.CreateAgentRequest{Name: "Helper"}))
	requireConnectCode(t, "a reset account creating an agent", err, connect.CodeFailedPrecondition)
}

// TestRedesign_ManagedFence_EndedSessionAttachesNothing: a member's session
// a suspension ended attaches nothing through another replica that still
// caches it.
func TestRedesign_ManagedFence_EndedSessionAttachesNothing(t *testing.T) {
	h := startManagedHarness(t, func(c *config.Config) { c.AgentsEnabled = true })
	m := newManagedMember(t, h, "managed-fence-ended")
	ctx := context.Background()
	b := managedReplica(t, h)
	login, err := brandedClient(b, "").PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{Email: m.address, Password: m.password}))
	if err != nil {
		t.Fatalf("PasswordLogin on the second replica: %v", err)
	}
	ann := brandedClient(b, login.Msg.GetAccessToken())
	if _, err := ann.ListMySessions(ctx, connect.NewRequest(&identitypb.ListMySessionsRequest{})); err != nil {
		t.Fatalf("ListMySessions while live: %v", err)
	}
	if _, err := m.owner.SuspendTenantMember(ctx, connect.NewRequest(&identitypb.SuspendTenantMemberRequest{
		TenantId: m.tenantID, UserId: m.userID,
	})); err != nil {
		t.Fatalf("SuspendTenantMember: %v", err)
	}
	_, err = ann.BeginTotpSetup(ctx, connect.NewRequest(&identitypb.BeginTotpSetupRequest{}))
	requireConnectCode(t, "an ended session enrolling two-step", err, connect.CodeUnauthenticated)
	_, err = ann.BeginPasskeyRegistration(ctx, connect.NewRequest(&identitypb.BeginPasskeyRegistrationRequest{DeviceName: "laptop"}))
	requireConnectCode(t, "an ended session adding a passkey", err, connect.CodeUnauthenticated)
	_, err = ann.CreateAgent(ctx, connect.NewRequest(&identitypb.CreateAgentRequest{Name: "Helper"}))
	requireConnectCode(t, "an ended session creating an agent", err, connect.CodeUnauthenticated)
}

// TestRedesign_ManagedAgents_LiveWithTheirOwnersStanding: a managed account
// creates an agent while it stands in its tenant; suspending the account
// deactivates the agent with it, and a restored account creates a new one.
func TestRedesign_ManagedAgents_LiveWithTheirOwnersStanding(t *testing.T) {
	h := startManagedHarness(t, func(c *config.Config) { c.AgentsEnabled = true })
	m := newManagedMember(t, h, "managed-agents")
	ctx := context.Background()
	createAgent := func(name string) (*identitypb.User, error) {
		login := m.mustSignIn(t)
		resp, err := brandedClient(h, login.GetAccessToken()).CreateAgent(ctx, connect.NewRequest(&identitypb.CreateAgentRequest{Name: name}))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetAgent(), nil
	}
	agent, err := createAgent("Helper")
	if err != nil {
		t.Fatalf("a managed account creating an agent: %v", err)
	}

	if _, err := m.owner.SuspendTenantMember(ctx, connect.NewRequest(&identitypb.SuspendTenantMemberRequest{
		TenantId: m.tenantID, UserId: m.userID,
	})); err != nil {
		t.Fatalf("SuspendTenantMember: %v", err)
	}
	stored, err := h.Stores.users.WithProject(h.ProjectID).GetUser(ctx, agent.GetId())
	if err != nil || stored == nil || stored.Status != service.StatusDeactivated {
		t.Fatalf("agent after the owner's suspension = %+v %v, want it deactivated", stored, err)
	}

	if _, err := m.owner.RestoreTenantMember(ctx, connect.NewRequest(&identitypb.RestoreTenantMemberRequest{
		TenantId: m.tenantID, UserId: m.userID,
	})); err != nil {
		t.Fatalf("RestoreTenantMember: %v", err)
	}
	if _, err := createAgent("Second"); err != nil {
		t.Fatalf("a restored managed account creating an agent: %v", err)
	}
}

// TestRedesign_ManagedFence_PersonalAdminsUnchanged: with managed accounts
// off, a personal owner administers and enrolls as before.
func TestRedesign_ManagedFence_PersonalAdminsUnchanged(t *testing.T) {
	h := startRedesignHarnessWith(t, func(c *config.Config) { c.RevocationMode = config.RevocationModeSession })
	owner, _, _ := operatorTenantWithDomain(t, h, "personal-fence")
	ctx := context.Background()
	if _, err := owner.client.ListTenantMembers(ctx, connect.NewRequest(&identitypb.ListTenantMembersRequest{TenantId: owner.tenantID})); err != nil {
		t.Fatalf("ListTenantMembers: %v", err)
	}
	if _, err := owner.client.ListTenantDomains(ctx, connect.NewRequest(&identitypb.ListTenantDomainsRequest{TenantId: owner.tenantID})); err != nil {
		t.Fatalf("ListTenantDomains: %v", err)
	}
	if _, err := owner.client.BeginTotpSetup(ctx, connect.NewRequest(&identitypb.BeginTotpSetupRequest{})); err != nil {
		t.Fatalf("BeginTotpSetup: %v", err)
	}
}

// TestRedesign_ManagedFence_ShortAccessTokens: a managed account's access
// token carries managed: true and lasts a minute at most, while a personal
// account's lasts the server's access-token expiry, as before.
func TestRedesign_ManagedFence_ShortAccessTokens(t *testing.T) {
	h := startManagedHarness(t, func(c *config.Config) { c.JWTExpirySeconds = 900 })
	m := newManagedMember(t, h, "managed-short-token")
	lifetime := func(accessToken string) float64 {
		claims := decodeTokenClaims(t, accessToken)
		return claims["exp"].(float64) - claims["iat"].(float64)
	}
	login := m.mustSignIn(t)
	if got := lifetime(login.GetAccessToken()); got > 60 {
		t.Fatalf("managed access token lasts %vs, want at most 60s", got)
	}
	if login.GetExpiresIn() != 60 || decodeTokenClaims(t, login.GetAccessToken())["managed"] != true {
		t.Fatalf("managed sign-in = expires_in %d, claims %v; want 60 and managed", login.GetExpiresIn(), decodeTokenClaims(t, login.GetAccessToken()))
	}
	personal, err := brandedClient(h, "").PasswordLogin(context.Background(), connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: ownerAddress(t, h, m.ownerID), Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("owner PasswordLogin: %v", err)
	}
	if got := lifetime(personal.Msg.GetAccessToken()); got != 900 || personal.Msg.GetExpiresIn() != 900 {
		t.Fatalf("personal access token lasts %vs (expires_in %d), want 900s", got, personal.Msg.GetExpiresIn())
	}
}
