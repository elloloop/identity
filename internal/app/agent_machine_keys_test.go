package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/stretchr/testify/require"
)

func TestMachineHTTPKeysSeparateAgentAndOrchestratorAndRejectReplay(t *testing.T) {
	f := newAgentMachineFixture(t)
	input, machine, keys := registerTestMachine(t, f)
	enrollTestAgent(t, f, machine.MachineId, f.agent, keys)
	exchange := &identitypb.CreateAgentMachineChallengeRequest{MachineId: machine.MachineId, AgentUserId: f.agent, Operation: identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_EXCHANGE_AGENT}
	wrong := machineHTTPProof(t, f, exchange, keys.engine)
	_, err := f.client.ExchangeAgentMachineCredential(t.Context(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: machine.MachineId, AgentUserId: f.agent, Proof: wrong}))
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	proof := machineHTTPProof(t, f, exchange, keys.agents[f.agent])
	results := make(chan error, 8)
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			_, err := f.client.ExchangeAgentMachineCredential(t.Context(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: machine.MachineId, AgentUserId: f.agent, Proof: proof}))
			results <- err
		})
	}
	group.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
		}
	}
	require.Equal(t, 1, successes)
	roster := &identitypb.CreateAgentMachineChallengeRequest{MachineId: machine.MachineId, Operation: identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_LIST_AGENTS}
	wrong = machineHTTPProof(t, f, roster, keys.agents[f.agent])
	_, err = f.client.ListAgentMachineAgents(t.Context(), connect.NewRequest(&identitypb.ListAgentMachineAgentsRequest{MachineId: machine.MachineId, Proof: wrong}))
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	proof = machineHTTPProof(t, f, roster, keys.engine)
	_, err = f.client.ListAgentMachineAgents(t.Context(), connect.NewRequest(&identitypb.ListAgentMachineAgentsRequest{MachineId: machine.MachineId, Offset: 1, Proof: proof}))
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.client.ListAgentMachineAgents(t.Context(), connect.NewRequest(&identitypb.ListAgentMachineAgentsRequest{MachineId: machine.MachineId, Proof: proof}))
	require.NoError(t, err)
	input.MachineId = "other-desktop"
	register := connect.NewRequest(input)
	register.Header().Set("Authorization", "Bearer "+f.token)
	_, err = f.client.RegisterAgentMachine(t.Context(), register)
	require.NoError(t, err)
	proof = machineHTTPProof(t, f, roster, keys.engine)
	_, err = f.client.ListAgentMachineAgents(t.Context(), connect.NewRequest(&identitypb.ListAgentMachineAgentsRequest{MachineId: input.MachineId, Proof: proof}))
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestMachineHTTPFutureAgentEnrollsAfterHumanLogoutAndStoresOnlyPublicKeys(t *testing.T) {
	f := newAgentMachineFixture(t)
	_, machine, keys := registerTestMachine(t, f)
	human, err := jwt.VerifyAccessToken(f.token, f.signer, "", "", false)
	require.NoError(t, err)
	require.NoError(t, f.repo.RevokeSession(t.Context(), human.SID, time.Now().UnixMilli()))
	newAgent, err := f.repo.CreateUser(t.Context(), &service.User{Kind: service.UserKindAgent, Status: service.StatusActive, OwnerUserID: f.owner})
	require.NoError(t, err)
	issued := exchangeTestMachine(t, f, machine.MachineId, keys, newAgent)
	claims, err := jwt.VerifyDelegatedAccessToken(issued.AccessToken, f.signer, f.cfg.JWTIssuer, f.cfg.DefaultProjectID, testAgentResource)
	require.NoError(t, err)
	require.Equal(t, newAgent, claims.Sub)
	require.Equal(t, f.owner, claims.Actor.Sub)
	repo := f.repo.(service.AgentMachineRepository)
	stored, err := repo.GetAgentMachine(t.Context(), machine.MachineId)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(keys.engine.Public().(ed25519.PublicKey)), stored.PublicKey)
	grant, err := repo.GetAgentMachineDelegation(t.Context(), machine.MachineId, newAgent)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(keys.agents[newAgent].Public().(ed25519.PublicKey)), grant.MachinePublicKey)
	for _, record := range []any{stored, grant} {
		data, err := json.Marshal(record)
		require.NoError(t, err)
		require.NotContains(t, string(data), hex.EncodeToString(keys.engine))
		require.NotContains(t, string(data), hex.EncodeToString(keys.agents[newAgent]))
	}
}

func TestMachineHTTPAgentKeyRegistrationIsBoundAndCannotReplaceExistingKey(t *testing.T) {
	f := newAgentMachineFixture(t)
	_, machine, keys := registerTestMachine(t, f)
	enrollTestAgent(t, f, machine.MachineId, f.agent, keys)
	public := hex.EncodeToString(keys.agents[f.agent].Public().(ed25519.PublicKey))
	request := &identitypb.CreateAgentMachineChallengeRequest{MachineId: machine.MachineId, AgentUserId: f.agent, AgentPublicKey: public, Operation: identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_ENROLL_AGENT}
	proof := machineHTTPProof(t, f, request, keys.engine)
	input := &identitypb.RegisterAgentMachineAgentKeyRequest{MachineId: machine.MachineId, AgentUserId: f.agent, AgentPublicKey: public, Proof: proof}
	first, err := f.client.RegisterAgentMachineAgentKey(t.Context(), connect.NewRequest(input))
	require.NoError(t, err)
	input.Proof = machineHTTPProof(t, f, request, keys.engine)
	repeated, err := f.client.RegisterAgentMachineAgentKey(t.Context(), connect.NewRequest(input))
	require.NoError(t, err)
	require.Equal(t, first.Msg.DelegationId, repeated.Msg.DelegationId)
	replacement, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	input.Proof = machineHTTPProof(t, f, request, keys.engine)
	input.AgentPublicKey = hex.EncodeToString(replacement)
	_, err = f.client.RegisterAgentMachineAgentKey(t.Context(), connect.NewRequest(input))
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	request.AgentPublicKey = input.AgentPublicKey
	input.Proof = machineHTTPProof(t, f, request, keys.engine)
	_, err = f.client.RegisterAgentMachineAgentKey(t.Context(), connect.NewRequest(input))
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	exchangeTestMachine(t, f, machine.MachineId, keys, f.agent)
}

func TestMachineHTTPBackgroundSweepDropsAbandonedChallengesAfterRevocation(t *testing.T) {
	f := newAgentMachineFixture(t)
	_, machine, keys := registerTestMachine(t, f)
	proof := machineControlProof(t, f, machine.MachineId, keys, identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_LIST_AGENTS)
	repo := f.repo.(service.AgentMachineRepository)
	challenge, err := repo.GetAgentMachineChallenge(t.Context(), proof.ChallengeId)
	require.NoError(t, err)
	require.NotNil(t, challenge)
	_, err = repo.MutateAgentMachine(t.Context(), machine.MachineId, service.AgentMachineMutation{Operation: service.AgentMachineRevoke, OwnerID: f.owner, AtMs: time.Now().UnixMilli()})
	require.NoError(t, err)
	require.NoError(t, sweepAgentOAuth(t.Context(), f.repo, nil, f.cfg.DefaultProjectID, challenge.ExpiresAtMs, 100))
	challenge, err = repo.GetAgentMachineChallenge(t.Context(), proof.ChallengeId)
	require.NoError(t, err)
	require.Nil(t, challenge)
}
