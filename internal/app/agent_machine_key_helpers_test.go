package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/stretchr/testify/require"
)

type machineTestKeys struct {
	engine ed25519.PrivateKey
	agents map[string]ed25519.PrivateKey
}

func registerTestMachine(t *testing.T, f *agentOAuthHTTPFixture) (*identitypb.RegisterAgentMachineRequest, *identitypb.AgentMachine, *machineTestKeys) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	input := &identitypb.RegisterAgentMachineRequest{MachineId: "test-desktop", ClientId: f.clientID, Resource: testAgentResource, Scopes: []string{"files:read"}, DisplayName: "Example desktop", EnginePublicKey: hex.EncodeToString(public)}
	req := connect.NewRequest(input)
	req.Header().Set("Authorization", "Bearer "+f.token)
	result, err := f.client.RegisterAgentMachine(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, "no-store", result.Header().Get("Cache-Control"))
	require.True(t, result.Msg.Machine.Selection.AllAgents)
	return input, result.Msg.Machine, &machineTestKeys{engine: private, agents: make(map[string]ed25519.PrivateKey)}
}

func machineHTTPProof(t *testing.T, f *agentOAuthHTTPFixture, request *identitypb.CreateAgentMachineChallengeRequest, key ed25519.PrivateKey) *identitypb.AgentMachineProof {
	t.Helper()
	response, err := f.client.CreateAgentMachineChallenge(t.Context(), connect.NewRequest(request))
	require.NoError(t, err)
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	require.Greater(t, response.Msg.ExpiresAtMs, time.Now().UnixMilli())
	require.Contains(t, string(response.Msg.Message), f.cfg.JWTIssuer)
	require.Contains(t, string(response.Msg.Message), f.cfg.DefaultProjectID)
	return &identitypb.AgentMachineProof{ChallengeId: response.Msg.ChallengeId, Signature: ed25519.Sign(key, response.Msg.Message)}
}

func machineControlProof(t *testing.T, f *agentOAuthHTTPFixture, id string, keys *machineTestKeys, operation identitypb.AgentMachineOperation) *identitypb.AgentMachineProof {
	t.Helper()
	return machineHTTPProof(t, f, &identitypb.CreateAgentMachineChallengeRequest{MachineId: id, Operation: operation}, keys.engine)
}

func enrollTestAgent(t *testing.T, f *agentOAuthHTTPFixture, id, agent string, keys *machineTestKeys) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key := hex.EncodeToString(public)
	proof := machineHTTPProof(t, f, &identitypb.CreateAgentMachineChallengeRequest{MachineId: id, AgentUserId: agent, AgentPublicKey: key, Operation: identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_ENROLL_AGENT}, keys.engine)
	response, err := f.client.RegisterAgentMachineAgentKey(t.Context(), connect.NewRequest(&identitypb.RegisterAgentMachineAgentKeyRequest{MachineId: id, AgentUserId: agent, AgentPublicKey: key, Proof: proof}))
	require.NoError(t, err)
	require.NotEmpty(t, response.Msg.DelegationId)
	keys.agents[agent] = private
}

func exchangeTestMachine(t *testing.T, f *agentOAuthHTTPFixture, id string, keys *machineTestKeys, agent string) *identitypb.ExchangeAgentMachineCredentialResponse {
	t.Helper()
	if keys.agents[agent] == nil {
		enrollTestAgent(t, f, id, agent, keys)
	}
	proof := machineHTTPProof(t, f, &identitypb.CreateAgentMachineChallengeRequest{MachineId: id, AgentUserId: agent, Operation: identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_EXCHANGE_AGENT}, keys.agents[agent])
	result, err := f.client.ExchangeAgentMachineCredential(t.Context(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: id, AgentUserId: agent, Proof: proof}))
	require.NoError(t, err)
	require.Equal(t, "no-store", result.Header().Get("Cache-Control"))
	require.Equal(t, "Bearer", result.Msg.TokenType)
	require.EqualValues(t, f.cfg.AgentOAuthAccessSeconds, result.Msg.ExpiresIn)
	return result.Msg
}
