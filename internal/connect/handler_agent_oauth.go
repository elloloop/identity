package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
)

func agentOAuthHuman(headers headerReader) service.AgentOAuthHuman {
	return service.AgentOAuthHuman{UserID: authenticatedUserID(headers), SID: headers.Get(middleware.AuthenticatedSessionIDHeader), AuthTime: authenticatedAuthTime(headers)}
}

func (h *IdentityHandler) GetAgentAuthorization(ctx context.Context, req *connect.Request[identitypb.GetAgentAuthorizationRequest]) (*connect.Response[identitypb.GetAgentAuthorizationResponse], error) {
	if h.agentOAuth == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, service.ErrAgentOAuthDisabled)
	}
	view, err := h.agentOAuth.GetConsent(ctx, agentOAuthHuman(req.Header()), req.Msg.GetRequestId(), int(req.Msg.GetAgentOffset()))
	if err != nil {
		return nil, toConnectError(err)
	}
	out := &identitypb.GetAgentAuthorizationResponse{RequestId: view.Request.ID, Revision: view.Request.Revision, ClientId: view.Request.ClientID, ClientName: view.ClientName, Resource: view.Request.Resource, Scopes: view.Request.Scopes, Product: view.Request.Product, RequestExpiresAtMs: view.Request.ExpiresAtMs, GrantExpiresAtMs: view.GrantExpiresAtMs, NextAgentOffset: view.NextAgentOffset}
	for _, agent := range view.Agents {
		out.Agents = append(out.Agents, userToProto(agent))
	}
	return connect.NewResponse(out), nil
}

func (h *IdentityHandler) DecideAgentAuthorization(ctx context.Context, req *connect.Request[identitypb.DecideAgentAuthorizationRequest]) (*connect.Response[identitypb.DecideAgentAuthorizationResponse], error) {
	if h.agentOAuth == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, service.ErrAgentOAuthDisabled)
	}
	if req.Msg.Decision != identitypb.AgentAuthorizationDecision_AGENT_AUTHORIZATION_DECISION_APPROVE && req.Msg.Decision != identitypb.AgentAuthorizationDecision_AGENT_AUTHORIZATION_DECISION_DENY {
		return nil, toConnectError(service.ErrInvalidArgument)
	}
	redirect, err := h.agentOAuth.Decide(ctx, agentOAuthHuman(req.Header()), req.Msg.GetRequestId(), req.Msg.GetExpectedRevision(), req.Msg.Decision == identitypb.AgentAuthorizationDecision_AGENT_AUTHORIZATION_DECISION_APPROVE, req.Msg.GetAgentUserId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.DecideAgentAuthorizationResponse{RedirectUri: redirect}), nil
}

func (h *IdentityHandler) ListAgentDelegations(ctx context.Context, req *connect.Request[identitypb.ListAgentDelegationsRequest]) (*connect.Response[identitypb.ListAgentDelegationsResponse], error) {
	if h.agentOAuth == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, service.ErrAgentOAuthDisabled)
	}
	grants, err := h.agentOAuth.List(ctx, agentOAuthHuman(req.Header()), req.Msg.GetAfterDelegationId(), int(req.Msg.GetLimit()))
	if err != nil {
		return nil, toConnectError(err)
	}
	out := &identitypb.ListAgentDelegationsResponse{}
	for _, grant := range grants {
		out.NextCursor = grant.ID
		if grant.Decision != service.AgentAuthorizationApproved {
			continue
		}
		out.Delegations = append(out.Delegations, &identitypb.AgentDelegation{DelegationId: grant.ID, AgentUserId: grant.AgentID, ClientId: grant.ClientID, Resource: grant.Resource, Scopes: grant.Scopes, Product: grant.Product, ConsentedAtMs: grant.ConsentAtMs, ExpiresAtMs: grant.GrantExpiresAtMs, RevokedAtMs: grant.RevokedAtMs, MachineId: grant.MachineID})
	}
	if len(grants) == 0 {
		out.NextCursor = ""
	}
	return connect.NewResponse(out), nil
}

func (h *IdentityHandler) RevokeAgentDelegation(ctx context.Context, req *connect.Request[identitypb.RevokeAgentDelegationRequest]) (*connect.Response[identitypb.RevokeAgentDelegationResponse], error) {
	if h.agentOAuth == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, service.ErrAgentOAuthDisabled)
	}
	if err := h.agentOAuth.Revoke(ctx, agentOAuthHuman(req.Header()), req.Msg.GetDelegationId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.RevokeAgentDelegationResponse{}), nil
}
