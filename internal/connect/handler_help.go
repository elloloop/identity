package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	"github.com/elloloop/identity/internal/service"
)

// ─── Admin Help RPCs ───────────────────────────────────────────���────────────

// RequestAdminHelp creates a new admin help request. This is an unauthenticated
// endpoint — the user cannot log in and needs admin assistance.
func (h *IdentityHandler) RequestAdminHelp(
	ctx context.Context,
	req *connect.Request[identitypb.RequestAdminHelpRequest],
) (*connect.Response[identitypb.RequestAdminHelpResponse], error) {
	ipAddr := clientIP(req.Header())
	userAgent := clientUserAgent(req.Header())

	// Best-effort — always returns success to prevent email enumeration.
	_ = h.help.RequestAdminHelp(ctx, req.Msg.Email, req.Msg.Reason, ipAddr, userAgent)

	return connect.NewResponse(&identitypb.RequestAdminHelpResponse{}), nil
}

// ListHelpRequests returns a paginated list of admin help requests. Admin only.
func (h *IdentityHandler) ListHelpRequests(
	ctx context.Context,
	req *connect.Request[identitypb.ListHelpRequestsRequest],
) (*connect.Response[identitypb.ListHelpRequestsResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	statusFilter := protoToHelpRequestStatusString(req.Msg.StatusFilter)

	requests, nextCursor, pendingCount, err := h.help.ListHelpRequests(
		ctx,
		callerID,
		statusFilter,
		req.Msg.Cursor,
		int(req.Msg.Limit),
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.ListHelpRequestsResponse{
		Requests:     helpRequestsToProto(requests),
		NextCursor:   nextCursor,
		PendingCount: intToProtoInt32(pendingCount),
	}
	return connect.NewResponse(resp), nil
}

// ResolveHelpRequest resolves or rejects an admin help request. Admin only.
func (h *IdentityHandler) ResolveHelpRequest(
	ctx context.Context,
	req *connect.Request[identitypb.ResolveHelpRequestRequest],
) (*connect.Response[identitypb.ResolveHelpRequestResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	helpReq, err := h.help.ResolveHelpRequest(
		ctx,
		callerID,
		req.Msg.RequestId,
		req.Msg.Reject,
		req.Msg.ResolutionNotes,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.ResolveHelpRequestResponse{
		Request: helpRequestToProto(helpReq),
	}
	return connect.NewResponse(resp), nil
}

// ─── Audit Log RPCs ─────────────────────────────────────────────────────────

// ListAuditEvents returns a paginated list of audit events. Admin only.
// Delegates to ProfileService.ListAuditEvents which enforces admin role.
func (h *IdentityHandler) ListAuditEvents(
	ctx context.Context,
	req *connect.Request[identitypb.ListAuditEventsRequest],
) (*connect.Response[identitypb.ListAuditEventsResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	events, nextCursor, err := h.profile.ListAuditEvents(
		ctx,
		callerID,
		req.Msg.TargetUserId,
		req.Msg.EventType,
		req.Msg.StartTimeMs,
		req.Msg.EndTimeMs,
		req.Msg.Cursor,
		int(req.Msg.Limit),
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.ListAuditEventsResponse{
		Events:     auditEventsToProto(events),
		NextCursor: nextCursor,
	}
	return connect.NewResponse(resp), nil
}
