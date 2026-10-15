package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// ─── Agent account RPCs ─────────────────────────────────────────────────────
//
// Management of agent accounts: non-human accounts a person owns. Every
// handler takes the caller from the authenticated session
// (X-Authenticated-User-Id, set by the auth middleware after verifying the
// JWT), never from the request body. The service admits the agent's owner or
// a project admin at one chokepoint and answers everyone else with an
// account-agnostic PERMISSION_DENIED.

// CreateAgent creates an agent account owned by the caller, or by another
// person when a project admin names one.
func (h *IdentityHandler) CreateAgent(
	ctx context.Context,
	req *connect.Request[identitypb.CreateAgentRequest],
) (*connect.Response[identitypb.CreateAgentResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	agent, err := h.auth.CreateAgent(
		ctx, callerID,
		req.Msg.GetName(), req.Msg.GetAvatarUrl(), req.Msg.GetOwnerUserId(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.CreateAgentResponse{Agent: userToProto(agent)}), nil
}

// ListAgents returns the agents the caller owns, or, for a project admin,
// the agents another account owns.
func (h *IdentityHandler) ListAgents(
	ctx context.Context,
	req *connect.Request[identitypb.ListAgentsRequest],
) (*connect.Response[identitypb.ListAgentsResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	agents, err := h.auth.ListAgents(ctx, callerID, req.Msg.GetOwnerUserId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.ListAgentsResponse{Agents: usersToProto(agents)}), nil
}

// UpdateAgent replaces an agent's display name and avatar URL.
func (h *IdentityHandler) UpdateAgent(
	ctx context.Context,
	req *connect.Request[identitypb.UpdateAgentRequest],
) (*connect.Response[identitypb.UpdateAgentResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	agent, err := h.auth.UpdateAgent(
		ctx, callerID,
		req.Msg.GetAgentUserId(), req.Msg.GetName(), req.Msg.GetAvatarUrl(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.UpdateAgentResponse{Agent: userToProto(agent)}), nil
}

// TransferAgent offers an agent to another owner, or reassigns an orphaned
// agent at once when a project admin asks.
func (h *IdentityHandler) TransferAgent(
	ctx context.Context,
	req *connect.Request[identitypb.TransferAgentRequest],
) (*connect.Response[identitypb.TransferAgentResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	agent, err := h.auth.TransferAgent(
		ctx, callerID,
		req.Msg.GetAgentUserId(), req.Msg.GetNewOwnerUserId(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.TransferAgentResponse{Agent: userToProto(agent)}), nil
}

// AcceptAgentTransfer takes ownership of an agent offered to the caller.
func (h *IdentityHandler) AcceptAgentTransfer(
	ctx context.Context,
	req *connect.Request[identitypb.AcceptAgentTransferRequest],
) (*connect.Response[identitypb.AcceptAgentTransferResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	agent, err := h.auth.AcceptAgentTransfer(
		ctx, callerID, req.Msg.GetAgentUserId(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AcceptAgentTransferResponse{Agent: userToProto(agent)}), nil
}

// DeclineAgentTransfer refuses an agent offered to the caller.
func (h *IdentityHandler) DeclineAgentTransfer(
	ctx context.Context,
	req *connect.Request[identitypb.DeclineAgentTransferRequest],
) (*connect.Response[identitypb.DeclineAgentTransferResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	agent, err := h.auth.DeclineAgentTransfer(
		ctx, callerID, req.Msg.GetAgentUserId(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.DeclineAgentTransferResponse{Agent: userToProto(agent)}), nil
}

// CancelAgentTransfer withdraws an agent's pending transfer.
func (h *IdentityHandler) CancelAgentTransfer(
	ctx context.Context,
	req *connect.Request[identitypb.CancelAgentTransferRequest],
) (*connect.Response[identitypb.CancelAgentTransferResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	agent, err := h.auth.CancelAgentTransfer(
		ctx, callerID, req.Msg.GetAgentUserId(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.CancelAgentTransferResponse{Agent: userToProto(agent)}), nil
}

// ListIncomingAgentTransfers returns the agents offered to the caller.
func (h *IdentityHandler) ListIncomingAgentTransfers(
	ctx context.Context,
	req *connect.Request[identitypb.ListIncomingAgentTransfersRequest],
) (*connect.Response[identitypb.ListIncomingAgentTransfersResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	agents, err := h.auth.ListIncomingAgentTransfers(ctx, callerID)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.ListIncomingAgentTransfersResponse{Agents: usersToProto(agents)}), nil
}

// DeactivateAgent suspends an agent and ends its sessions.
func (h *IdentityHandler) DeactivateAgent(
	ctx context.Context,
	req *connect.Request[identitypb.DeactivateAgentRequest],
) (*connect.Response[identitypb.DeactivateAgentResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	if err := h.auth.DeactivateAgent(
		ctx, callerID,
		req.Msg.GetAgentUserId(), req.Msg.GetReason(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.DeactivateAgentResponse{}), nil
}

// ReactivateAgent returns a deactivated agent to active.
func (h *IdentityHandler) ReactivateAgent(
	ctx context.Context,
	req *connect.Request[identitypb.ReactivateAgentRequest],
) (*connect.Response[identitypb.ReactivateAgentResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	if err := h.auth.ReactivateAgent(
		ctx, callerID, req.Msg.GetAgentUserId(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.ReactivateAgentResponse{}), nil
}

// DeleteAgent erases an agent account.
func (h *IdentityHandler) DeleteAgent(
	ctx context.Context,
	req *connect.Request[identitypb.DeleteAgentRequest],
) (*connect.Response[identitypb.DeleteAgentResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}
	if err := h.auth.DeleteAgent(
		ctx, callerID, req.Msg.GetAgentUserId(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.DeleteAgentResponse{}), nil
}
