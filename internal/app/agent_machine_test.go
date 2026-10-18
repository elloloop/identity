package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/stretchr/testify/require"
)

func newAgentMachineFixture(t *testing.T) *agentOAuthHTTPFixture {
	t.Helper()
	f := newAgentOAuthHTTPFixture(t)
	f.cfg.AgentMachineEnabled = true
	client, err := f.repo.GetOAuthClient(t.Context(), f.clientID)
	require.NoError(t, err)
	client.Registration.GrantTypes = append(client.Registration.GrantTypes, service.OAuthGrantAgentMachine)
	_, err = f.repo.UpdateOAuthClient(t.Context(), client.ID, client.Revision, &client.Registration, time.Now().UnixMilli())
	require.NoError(t, err)
	return f
}

func registerTestMachine(t *testing.T, f *agentOAuthHTTPFixture) (*identitypb.RegisterAgentMachineRequest, *identitypb.AgentMachine, string) {
	t.Helper()
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	raw := base64.RawURLEncoding.EncodeToString(secret)
	digest := sha256.Sum256([]byte(raw))
	input := &identitypb.RegisterAgentMachineRequest{MachineId: "test-desktop", ClientId: f.clientID, Resource: testAgentResource, Scopes: []string{"files:read"}, DisplayName: "Example desktop", CredentialSha256: hex.EncodeToString(digest[:])}
	req := connect.NewRequest(input)
	req.Header().Set("Authorization", "Bearer "+f.token)
	result, err := f.client.RegisterAgentMachine(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, "no-store", result.Header().Get("Cache-Control"))
	require.True(t, result.Msg.Machine.Selection.AllAgents)
	return input, result.Msg.Machine, raw
}

func exchangeTestMachine(t *testing.T, f *agentOAuthHTTPFixture, id, raw, agent string) *identitypb.ExchangeAgentMachineCredentialResponse {
	t.Helper()
	result, err := f.client.ExchangeAgentMachineCredential(t.Context(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: id, MachineCredential: raw, AgentUserId: agent}))
	require.NoError(t, err)
	require.Equal(t, "no-store", result.Header().Get("Cache-Control"))
	require.Equal(t, "Bearer", result.Msg.TokenType)
	require.EqualValues(t, f.cfg.AgentOAuthAccessSeconds, result.Msg.ExpiresIn)
	return result.Msg
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
	page, err := f.client.ListAgentMachineAgents(t.Context(), connect.NewRequest(&identitypb.ListAgentMachineAgentsRequest{MachineId: machine.MachineId, MachineCredential: raw}))
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
	_, err = f.client.ExchangeAgentMachineCredential(t.Context(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: machine.MachineId, MachineCredential: raw, AgentUserId: f.agent}))
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	revoke := connect.NewRequest(&identitypb.RevokeAgentMachineRequest{MachineId: machine.MachineId})
	revoke.Header().Set("Authorization", "Bearer "+f.token)
	_, err = f.client.RevokeAgentMachine(t.Context(), revoke)
	require.NoError(t, err)
	_, err = f.client.ListAgentMachineAgents(t.Context(), connect.NewRequest(&identitypb.ListAgentMachineAgentsRequest{MachineId: machine.MachineId, MachineCredential: raw}))
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestMachineHTTPRegistrationRecoveryAndBounds(t *testing.T) {
	f := newAgentMachineFixture(t)
	input, machine, raw := registerTestMachine(t, f)
	req := connect.NewRequest(input)
	req.Header().Set("Authorization", "Bearer "+f.token)
	repeated, err := f.client.RegisterAgentMachine(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, machine.CreatedAtMs, repeated.Msg.Machine.CreatedAtMs)
	input.CredentialSha256 = strings.Repeat("a", 64)
	_, err = f.client.RegisterAgentMachine(t.Context(), req)
	require.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))
	for _, proof := range []string{"", raw + "=", base64.RawURLEncoding.EncodeToString(make([]byte, 32))} {
		_, err = f.client.ExchangeAgentMachineCredential(t.Context(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: machine.MachineId, MachineCredential: proof, AgentUserId: f.agent}))
		require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	}
	_, err = f.client.ExchangeAgentMachineCredential(t.Context(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: machine.MachineId, MachineCredential: raw, AgentUserId: f.owner}))
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	for _, offset := range []int32{-1, 2147483647} {
		_, err = f.client.ListAgentMachineAgents(t.Context(), connect.NewRequest(&identitypb.ListAgentMachineAgentsRequest{MachineId: machine.MachineId, MachineCredential: raw, Offset: offset}))
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
	req := connect.NewRequest(&identitypb.RegisterAgentMachineRequest{MachineId: "test-desktop", ClientId: f.clientID, Resource: testAgentResource, Scopes: []string{"files:read"}, DisplayName: "Example desktop", CredentialSha256: strings.Repeat("a", 64)})
	req.Header().Set("Authorization", "Bearer "+f.token)
	_, err := f.client.RegisterAgentMachine(t.Context(), req)
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	f.cfg.AgentMachineEnabled = false
	_, err = f.client.RegisterAgentMachine(context.Background(), req)
	require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestMachineHTTPRejectsOversizedCredentialBeforeService(t *testing.T) {
	f := newAgentMachineFixture(t)
	_, err := f.client.ExchangeAgentMachineCredential(t.Context(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: "test-desktop", MachineCredential: strings.Repeat("x", maxAgentOAuthFormBytes+1), AgentUserId: f.agent}))
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
	_, err = f.client.ExchangeAgentMachineCredential(t.Context(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: machine.MachineId, MachineCredential: raw, AgentUserId: second.Msg.Agent.Id}))
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestMachineHTTPResourceVerificationRequiresDedicatedCredential(t *testing.T) {
	f := newAgentMachineFixture(t)
	_, machine, raw := registerTestMachine(t, f)
	input := &identitypb.IntrospectAgentMachineRequest{MachineId: machine.MachineId, MachineCredential: raw}
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
	req.Msg.MachineCredential = "invalid"
	response, err = f.client.IntrospectAgentMachine(t.Context(), req)
	require.NoError(t, err)
	require.False(t, response.Msg.Active)
	require.Nil(t, response.Msg.Machine)
	req.Msg.MachineCredential = raw
	revoke := connect.NewRequest(&identitypb.RevokeAgentMachineRequest{MachineId: machine.MachineId})
	revoke.Header().Set("Authorization", "Bearer "+f.token)
	_, err = f.client.RevokeAgentMachine(t.Context(), revoke)
	require.NoError(t, err)
	response, err = f.client.IntrospectAgentMachine(t.Context(), req)
	require.NoError(t, err)
	require.False(t, response.Msg.Active)
	require.Nil(t, response.Msg.Machine)
}
