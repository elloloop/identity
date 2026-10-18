package connect

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

func machineToProto(machine *service.AgentMachine) *identitypb.AgentMachine {
	if machine == nil {
		return nil
	}
	return &identitypb.AgentMachine{MachineId: machine.ID, OwnerUserId: machine.OwnerID, ClientId: machine.ClientID, Resource: machine.Resource, Scopes: machine.Scopes, Product: machine.Product, DisplayName: machine.DisplayName, Selection: &identitypb.AgentMachineSelection{AllAgents: machine.AllAgents, AgentUserIds: machine.AgentIDs, ExcludedAgentUserIds: machine.ExcludedAgentIDs}, CreatedAtMs: machine.CreatedAtMs, Revision: machine.Revision, RevokedAtMs: machine.RevokedAtMs}
}

func machineResponse[T any](message *T) *connect.Response[T] {
	response := connect.NewResponse(message)
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	return response
}

func (h *IdentityHandler) machineEnabled() error {
	if h.agentOAuth == nil {
		return connect.NewError(connect.CodeFailedPrecondition, service.ErrAgentOAuthDisabled)
	}
	return nil
}

func (h *IdentityHandler) RegisterAgentMachine(ctx context.Context, req *connect.Request[identitypb.RegisterAgentMachineRequest]) (*connect.Response[identitypb.RegisterAgentMachineResponse], error) {
	if err := h.machineEnabled(); err != nil {
		return nil, err
	}
	all := true
	var agents, excluded []string
	if selection := req.Msg.Selection; selection != nil {
		all = selection.AllAgents
		agents = selection.AgentUserIds
		excluded = selection.ExcludedAgentUserIds
	}
	machine, err := h.agentOAuth.RegisterMachine(ctx, agentOAuthHuman(req.Header()), service.AgentMachineRegistration{ID: req.Msg.MachineId, ClientID: req.Msg.ClientId, Resource: req.Msg.Resource, Scopes: req.Msg.Scopes, DisplayName: req.Msg.DisplayName, CredentialHash: req.Msg.CredentialSha256, AllAgents: all, AgentIDs: agents, ExcludedAgentIDs: excluded})
	if err != nil {
		return nil, toConnectError(err)
	}
	return machineResponse(&identitypb.RegisterAgentMachineResponse{Machine: machineToProto(machine)}), nil
}

func (h *IdentityHandler) ListAgentMachines(ctx context.Context, req *connect.Request[identitypb.ListAgentMachinesRequest]) (*connect.Response[identitypb.ListAgentMachinesResponse], error) {
	if err := h.machineEnabled(); err != nil {
		return nil, err
	}
	machines, err := h.agentOAuth.ListMachines(ctx, agentOAuthHuman(req.Header()), req.Msg.AfterMachineId, int(req.Msg.Limit))
	if err != nil {
		return nil, toConnectError(err)
	}
	out := &identitypb.ListAgentMachinesResponse{}
	for _, machine := range machines {
		out.Machines = append(out.Machines, machineToProto(machine))
		out.NextCursor = machine.ID
	}
	return machineResponse(out), nil
}

func (h *IdentityHandler) SelectAgentMachineAgents(ctx context.Context, req *connect.Request[identitypb.SelectAgentMachineAgentsRequest]) (*connect.Response[identitypb.SelectAgentMachineAgentsResponse], error) {
	if err := h.machineEnabled(); err != nil {
		return nil, err
	}
	if req.Msg.Selection == nil {
		return nil, toConnectError(service.ErrInvalidArgument)
	}
	selection := req.Msg.Selection
	machine, err := h.agentOAuth.SelectMachineAgents(ctx, agentOAuthHuman(req.Header()), req.Msg.MachineId, req.Msg.ExpectedRevision, selection.AllAgents, selection.AgentUserIds, selection.ExcludedAgentUserIds)
	if err != nil {
		return nil, toConnectError(err)
	}
	return machineResponse(&identitypb.SelectAgentMachineAgentsResponse{Machine: machineToProto(machine)}), nil
}

func (h *IdentityHandler) RevokeAgentMachine(ctx context.Context, req *connect.Request[identitypb.RevokeAgentMachineRequest]) (*connect.Response[identitypb.RevokeAgentMachineResponse], error) {
	if err := h.machineEnabled(); err != nil {
		return nil, err
	}
	if err := h.agentOAuth.RevokeMachine(ctx, agentOAuthHuman(req.Header()), req.Msg.MachineId); err != nil {
		return nil, toConnectError(err)
	}
	return machineResponse(&identitypb.RevokeAgentMachineResponse{}), nil
}

func (h *IdentityHandler) ExchangeAgentMachineCredential(ctx context.Context, req *connect.Request[identitypb.ExchangeAgentMachineCredentialRequest]) (*connect.Response[identitypb.ExchangeAgentMachineCredentialResponse], error) {
	if err := h.machineEnabled(); err != nil {
		return nil, err
	}
	tokens, err := h.agentOAuth.ExchangeMachine(ctx, req.Msg.MachineId, req.Msg.MachineCredential, req.Msg.AgentUserId)
	if err != nil {
		return nil, toConnectError(err)
	}
	return machineResponse(&identitypb.ExchangeAgentMachineCredentialResponse{AccessToken: tokens.AccessToken, ExpiresIn: tokens.ExpiresIn, Scope: tokens.Scope, TokenType: "Bearer"}), nil
}

func (h *IdentityHandler) ListAgentMachineAgents(ctx context.Context, req *connect.Request[identitypb.ListAgentMachineAgentsRequest]) (*connect.Response[identitypb.ListAgentMachineAgentsResponse], error) {
	if err := h.machineEnabled(); err != nil {
		return nil, err
	}
	page, err := h.agentOAuth.MachineAgents(ctx, req.Msg.MachineId, req.Msg.MachineCredential, int(req.Msg.Offset))
	if err != nil {
		return nil, toConnectError(err)
	}
	out := &identitypb.ListAgentMachineAgentsResponse{NextOffset: page.NextOffset}
	for _, agent := range page.Agents {
		out.Agents = append(out.Agents, userToProto(agent))
	}
	return machineResponse(out), nil
}

func (h *IdentityHandler) IntrospectAgentMachine(ctx context.Context, req *connect.Request[identitypb.IntrospectAgentMachineRequest]) (*connect.Response[identitypb.IntrospectAgentMachineResponse], error) {
	if err := h.machineEnabled(); err != nil {
		return nil, err
	}
	request := &http.Request{Header: req.Header()}
	id, secret, ok := request.BasicAuth()
	if !ok || len(req.Header().Values("Authorization")) != 1 {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	resource, err := h.agentOAuth.AuthenticateResource(ctx, id, secret)
	if err != nil {
		return nil, toConnectError(err)
	}
	result, err := h.agentOAuth.IntrospectMachine(ctx, resource, req.Msg.MachineId, req.Msg.MachineCredential)
	if err != nil {
		return nil, toConnectError(err)
	}
	return machineResponse(&identitypb.IntrospectAgentMachineResponse{Active: result.Active, Machine: machineToProto(result.Machine)}), nil
}
