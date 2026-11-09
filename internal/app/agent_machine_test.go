package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/graph"
	"github.com/elloloop/identity/internal/repo/memory"

	"github.com/elloloop/identity/pkg/audit"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/stretchr/testify/require"
)

// observedDB records every audit write the app makes while forwarding nothing:
// the memory store's ExecuteAtomic keeps no graph state.
type observedDB struct {
	service.DB
	writes *captureNodeWriter
}

func (d *observedDB) ExecuteAtomic(ctx context.Context, projectID, tenant string, ops []graph.Operation) (*graph.CommitResult, error) {
	return d.writes.ExecuteAtomic(ctx, projectID, tenant, ops)
}

func newAgentMachineFixture(t *testing.T) *agentOAuthHTTPFixture {
	t.Helper()
	f := newAgentOAuthHTTPFixture(t)
	enableMachineClient(t, f)
	return f
}

// newAgentMachineFixtureObserved is newAgentMachineFixture with the audit writes captured.
func newAgentMachineFixtureObserved(t *testing.T) (*agentOAuthHTTPFixture, *captureNodeWriter) {
	t.Helper()
	writes := &captureNodeWriter{}
	f := newAgentOAuthHTTPFixtureWithDB(t, func(repo *memory.Repo) service.DB { return &observedDB{DB: repo, writes: writes} })
	enableMachineClient(t, f)
	return f, writes
}

func enableMachineClient(t *testing.T, f *agentOAuthHTTPFixture) {
	t.Helper()
	f.cfg.AgentMachineEnabled = true
	client, err := f.repo.GetOAuthClient(t.Context(), f.clientID)
	require.NoError(t, err)
	client.Registration.GrantTypes = append(client.Registration.GrantTypes, service.OAuthGrantAgentMachine)
	_, err = f.repo.UpdateOAuthClient(t.Context(), client.ID, client.Revision, &client.Registration, time.Now().UnixMilli())
	require.NoError(t, err)
}

func TestMachineHTTPUnattendedExchangeAfterHumanSessionEnds(t *testing.T) {
	f := newAgentMachineFixture(t)
	_, machine, raw := registerTestMachine(t, f)
	first := exchangeTestMachine(t, f, machine.MachineId, raw, f.agent)
	claims, err := jwt.VerifyDelegatedAccessToken(first.AccessToken, f.signer, f.cfg.JWTIssuer, f.cfg.DefaultProjectID, testAgentResource)
	require.NoError(t, err)
	require.Equal(t, f.agent, claims.Sub)
	require.Equal(t, f.owner, claims.Actor.Sub)
	_, err = jwt.VerifyAccessToken(first.AccessToken, f.signer, "", "", false)
	require.Error(t, err)
	human, err := jwt.VerifyAccessToken(f.token, f.signer, "", "", false)
	require.NoError(t, err)
	require.NoError(t, f.repo.RevokeSession(t.Context(), human.SID, time.Now().UnixMilli()))
	f.cfg.RefreshExpirySeconds = 1
	second := exchangeTestMachine(t, f, machine.MachineId, raw, f.agent)
	next, err := jwt.VerifyDelegatedAccessToken(second.AccessToken, f.signer, f.cfg.JWTIssuer, f.cfg.DefaultProjectID, testAgentResource)
	require.NoError(t, err)
	require.Equal(t, claims.GrantID, next.GrantID)
	require.Equal(t, claims.SID, next.SID)
	require.NotEqual(t, claims.JWTID, next.JWTID)
	status, active := f.post(t, agentOAuthIntrospectPath, url.Values{"token": {second.AccessToken}}, true)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, true, active["active"])
	page, err := f.client.ListAgentMachineAgents(t.Context(), connect.NewRequest(&identitypb.ListAgentMachineAgentsRequest{MachineId: machine.MachineId, Proof: machineControlProof(t, f, machine.MachineId, raw, identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_LIST_AGENTS)}))
	require.NoError(t, err)
	require.Len(t, page.Msg.Agents, 1)
	require.Equal(t, f.agent, page.Msg.Agents[0].Id)
}

func TestMachineHTTPSelectionRevokeAndNoAutomaticResurrection(t *testing.T) {
	f := newAgentMachineFixture(t)
	_, machine, raw := registerTestMachine(t, f)
	token := exchangeTestMachine(t, f, machine.MachineId, raw, f.agent)
	req := connect.NewRequest(&identitypb.SelectAgentMachineAgentsRequest{MachineId: machine.MachineId, ExpectedRevision: machine.Revision, Selection: &identitypb.AgentMachineSelection{AllAgents: true, ExcludedAgentUserIds: []string{f.agent}}})
	req.Header().Set("Authorization", "Bearer "+f.token)
	changed, err := f.client.SelectAgentMachineAgents(t.Context(), req)
	require.NoError(t, err)
	_, inactive := f.post(t, agentOAuthIntrospectPath, url.Values{"token": {token.AccessToken}}, true)
	require.Equal(t, false, inactive["active"])
	_, err = f.client.SelectAgentMachineAgents(t.Context(), req)
	require.Equal(t, connect.CodeAborted, connect.CodeOf(err))
	req.Msg.ExpectedRevision = changed.Msg.Machine.Revision
	req.Msg.Selection = &identitypb.AgentMachineSelection{AllAgents: true}
	_, err = f.client.SelectAgentMachineAgents(t.Context(), req)
	require.NoError(t, err)
	_, err = f.client.ExchangeAgentMachineCredential(t.Context(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: machine.MachineId, AgentUserId: f.agent}))
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	revoke := connect.NewRequest(&identitypb.RevokeAgentMachineRequest{MachineId: machine.MachineId})
	revoke.Header().Set("Authorization", "Bearer "+f.token)
	_, err = f.client.RevokeAgentMachine(t.Context(), revoke)
	require.NoError(t, err)
	_, err = f.client.ListAgentMachineAgents(t.Context(), connect.NewRequest(&identitypb.ListAgentMachineAgentsRequest{MachineId: machine.MachineId}))
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

// A revoked machine registers again under its installation id with a new engine
// key, enrols its agents again under fresh agent keys, and exchanges; what the
// revocation ended stays ended, and the audit log tells the renewal apart.
func TestMachineHTTPRevokedMachineRegistersAgainWithNewKeysAndExchanges(t *testing.T) {
	f, writes := newAgentMachineFixtureObserved(t)
	first, machine, keys := registerTestMachine(t, f)
	before := exchangeTestMachine(t, f, machine.MachineId, keys, f.agent)
	revoke := connect.NewRequest(&identitypb.RevokeAgentMachineRequest{MachineId: machine.MachineId})
	revoke.Header().Set("Authorization", "Bearer "+f.token)
	_, err := f.client.RevokeAgentMachine(t.Context(), revoke)
	require.NoError(t, err)
	// The retired engine key never registers again, whatever else the request says.
	retired := connect.NewRequest(&identitypb.RegisterAgentMachineRequest{
		MachineId: first.MachineId, ClientId: first.ClientId, Resource: first.Resource, Scopes: first.Scopes,
		DisplayName: "Renamed desktop", EnginePublicKey: first.EnginePublicKey,
	})
	retired.Header().Set("Authorization", "Bearer "+f.token)
	_, err = f.client.RegisterAgentMachine(t.Context(), retired)
	require.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))
	// The same owner registers the installation again with a new engine key.
	_, renewed, fresh := registerTestMachine(t, f)
	require.Equal(t, machine.MachineId, renewed.MachineId)
	require.Greater(t, renewed.Revision, machine.Revision)
	// The agent's old key, which the revocation ended, is refused; a fresh one enrols,
	// and the delegation exchanges again.
	oldAgentKey := keys.agents[f.agent]
	oldProof := machineHTTPProof(t, f, &identitypb.CreateAgentMachineChallengeRequest{MachineId: machine.MachineId, AgentUserId: f.agent, AgentPublicKey: hex.EncodeToString(oldAgentKey.Public().(ed25519.PublicKey)), Operation: identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_ENROLL_AGENT}, fresh.engine)
	_, err = f.client.RegisterAgentMachineAgentKey(t.Context(), connect.NewRequest(&identitypb.RegisterAgentMachineAgentKeyRequest{MachineId: machine.MachineId, AgentUserId: f.agent, AgentPublicKey: hex.EncodeToString(oldAgentKey.Public().(ed25519.PublicKey)), Proof: oldProof}))
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	after := exchangeTestMachine(t, f, machine.MachineId, fresh, f.agent)
	_, inactive := f.post(t, agentOAuthIntrospectPath, url.Values{"token": {before.AccessToken}}, true)
	require.Equal(t, false, inactive["active"])
	_, active := f.post(t, agentOAuthIntrospectPath, url.Values{"token": {after.AccessToken}}, true)
	require.Equal(t, true, active["active"])
	// The first registration's audit event carries no renewal details; the renewal's
	// names the revocation it recovered from and its revision. The log is written
	// asynchronously.
	registeredDetails := func() []map[string]any {
		out := make([]map[string]any, 0, 2)
		for _, write := range writes.all() {
			if write.eventType != string(audit.EventAgentMachineRegistered) {
				continue
			}
			details := map[string]any{}
			if raw, _ := write.data["7"].(string); raw != "" {
				require.NoError(t, json.Unmarshal([]byte(raw), &details))
			}
			out = append(out, details)
		}
		return out
	}
	require.Eventually(t, func() bool { return len(registeredDetails()) == 2 }, 5*time.Second, 20*time.Millisecond)
	var plain, renewal map[string]any
	for _, details := range registeredDetails() {
		if _, ok := details["renewed_after_revoked_at_ms"]; ok {
			renewal = details
		} else {
			plain = details
		}
	}
	require.NotNil(t, plain)
	require.NotNil(t, renewal)
	require.NotZero(t, renewal["renewed_after_revoked_at_ms"])
	require.EqualValues(t, renewed.Revision, renewal["revision"])
}

func TestMachineHTTPRegistrationRecoveryAndBounds(t *testing.T) {
	f := newAgentMachineFixture(t)
	input, machine, raw := registerTestMachine(t, f)
	req := connect.NewRequest(input)
	req.Header().Set("Authorization", "Bearer "+f.token)
	repeated, err := f.client.RegisterAgentMachine(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, machine.CreatedAtMs, repeated.Msg.Machine.CreatedAtMs)
	input.EnginePublicKey = strings.Repeat("a", 64)
	_, err = f.client.RegisterAgentMachine(t.Context(), req)
	require.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))
	enrollTestAgent(t, f, machine.MachineId, f.agent, raw)
	for _, proof := range [][]byte{nil, []byte("invalid"), make([]byte, 63), make([]byte, 64), make([]byte, 65)} {
		_, err = f.client.ExchangeAgentMachineCredential(t.Context(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: machine.MachineId, Proof: &identitypb.AgentMachineProof{ChallengeId: "unknown-challenge", Signature: proof}, AgentUserId: f.agent}))
		require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	}
	_, err = f.client.ExchangeAgentMachineCredential(t.Context(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: machine.MachineId, AgentUserId: f.owner}))
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	for _, offset := range []int32{-1, 2147483647} {
		_, err = f.client.ListAgentMachineAgents(t.Context(), connect.NewRequest(&identitypb.ListAgentMachineAgentsRequest{MachineId: machine.MachineId, Offset: offset}))
		require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	}
}

func TestMachineHTTPManagementNeverUsesAgentTokensOrForeignOwners(t *testing.T) {
	f := newAgentMachineFixture(t)
	_, machine, raw := registerTestMachine(t, f)
	agentToken := exchangeTestMachine(t, f, machine.MachineId, raw, f.agent)
	foreign, err := f.client.PasswordSignup(t.Context(), connect.NewRequest(&identitypb.PasswordSignupRequest{Email: "other@example.com", Password: "Offline-test-Password123!"}))
	require.NoError(t, err)
	for _, token := range []string{"", agentToken.AccessToken, foreign.Msg.AccessToken} {
		revoke := connect.NewRequest(&identitypb.RevokeAgentMachineRequest{MachineId: machine.MachineId})
		revoke.Header().Set("Authorization", "Bearer "+token)
		_, err = f.client.RevokeAgentMachine(t.Context(), revoke)
		require.Contains(t, []connect.Code{connect.CodeUnauthenticated, connect.CodePermissionDenied}, connect.CodeOf(err))
	}
	list := connect.NewRequest(&identitypb.ListAgentMachinesRequest{})
	list.Header().Set("Authorization", "Bearer "+foreign.Msg.AccessToken)
	result, err := f.client.ListAgentMachines(t.Context(), list)
	require.NoError(t, err)
	require.Empty(t, result.Msg.Machines)
	// A human bearer does not replace a missing machine proof on exchange.
	exchange := connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: machine.MachineId, AgentUserId: f.agent})
	exchange.Header().Set("Authorization", "Bearer "+f.token)
	_, err = f.client.ExchangeAgentMachineCredential(t.Context(), exchange)
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestMachineHTTPFeatureRequiresBothOperatorAndClientOptIn(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	f.cfg.AgentMachineEnabled = true
	req := connect.NewRequest(&identitypb.RegisterAgentMachineRequest{MachineId: "test-desktop", ClientId: f.clientID, Resource: testAgentResource, Scopes: []string{"files:read"}, DisplayName: "Example desktop", EnginePublicKey: strings.Repeat("a", 64)})
	req.Header().Set("Authorization", "Bearer "+f.token)
	_, err := f.client.RegisterAgentMachine(t.Context(), req)
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	f.cfg.AgentMachineEnabled = false
	_, err = f.client.RegisterAgentMachine(context.Background(), req)
	require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestMachineHTTPRejectsOversizedCredentialBeforeService(t *testing.T) {
	f := newAgentMachineFixture(t)
	_, err := f.client.ExchangeAgentMachineCredential(t.Context(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: "test-desktop", Proof: &identitypb.AgentMachineProof{Signature: make([]byte, maxAgentOAuthFormBytes+1)}, AgentUserId: f.agent}))
	require.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
}

func TestMachineHTTPObservedOwnerPolicyLossRevokesWholeMachine(t *testing.T) {
	f := newAgentMachineFixture(t)
	_, machine, raw := registerTestMachine(t, f)
	request := connect.NewRequest(&identitypb.CreateAgentRequest{Name: "Second example assistant"})
	request.Header().Set("Authorization", "Bearer "+f.token)
	second, err := f.client.CreateAgent(t.Context(), request)
	require.NoError(t, err)
	token := exchangeTestMachine(t, f, machine.MachineId, raw, f.agent)
	f.cfg.IDVRequired = true
	_, inactive := f.post(t, agentOAuthIntrospectPath, url.Values{"token": {token.AccessToken}}, true)
	require.Equal(t, false, inactive["active"])
	stored, err := f.repo.(service.AgentMachineRepository).GetAgentMachine(t.Context(), machine.MachineId)
	require.NoError(t, err)
	require.Positive(t, stored.RevokedAtMs)
	f.cfg.IDVRequired = false
	_, err = f.client.ExchangeAgentMachineCredential(t.Context(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: machine.MachineId, AgentUserId: second.Msg.Agent.Id}))
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestMachineHTTPResourceVerificationRequiresDedicatedCredential(t *testing.T) {
	f := newAgentMachineFixture(t)
	_, machine, raw := registerTestMachine(t, f)
	input := &identitypb.IntrospectAgentMachineRequest{MachineId: machine.MachineId, Proof: machineControlProof(t, f, machine.MachineId, raw, identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_INSPECT_MACHINE)}
	for _, authorization := range []string{"", "Bearer " + f.token, "Basic " + base64.StdEncoding.EncodeToString([]byte("files-resource:wrong"))} {
		req := connect.NewRequest(input)
		req.Header().Set("Authorization", authorization)
		_, err := f.client.IntrospectAgentMachine(t.Context(), req)
		require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	}
	req := connect.NewRequest(input)
	req.Header().Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("files-resource:"+testResourceSecret)))
	response, err := f.client.IntrospectAgentMachine(t.Context(), req)
	require.NoError(t, err)
	require.True(t, response.Msg.Active)
	require.Equal(t, f.owner, response.Msg.Machine.OwnerUserId)
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	req.Msg.Proof = &identitypb.AgentMachineProof{ChallengeId: "invalid"}
	response, err = f.client.IntrospectAgentMachine(t.Context(), req)
	require.NoError(t, err)
	require.False(t, response.Msg.Active)
	require.Nil(t, response.Msg.Machine)
	req.Msg.Proof = machineControlProof(t, f, machine.MachineId, raw, identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_INSPECT_MACHINE)
	revoke := connect.NewRequest(&identitypb.RevokeAgentMachineRequest{MachineId: machine.MachineId})
	revoke.Header().Set("Authorization", "Bearer "+f.token)
	_, err = f.client.RevokeAgentMachine(t.Context(), revoke)
	require.NoError(t, err)
	response, err = f.client.IntrospectAgentMachine(t.Context(), req)
	require.NoError(t, err)
	require.False(t, response.Msg.Active)
	require.Nil(t, response.Msg.Machine)
}
