package connect

import (
	"context"
	"strings"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// ─── Guardian edge RPCs ─────────────────────────────────────────────────

// ListManagedChildren returns the child accounts the authenticated caller
// holds a guardian edge to. The guardian is ALWAYS the session user
// (X-Authenticated-User-Id, set by the auth middleware after verifying the
// JWT): the request message carries no user id field, so a modified client
// cannot steer the query at another account.
func (h *IdentityHandler) ListManagedChildren(
	ctx context.Context,
	req *connect.Request[identitypb.ListManagedChildrenRequest],
) (*connect.Response[identitypb.ListManagedChildrenResponse], error) {
	guardianUserID := authenticatedUserID(req.Header())
	if guardianUserID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	children, nextCursor, err := h.auth.ListManagedChildren(
		ctx, guardianUserID, req.Msg.GetLimit(), req.Msg.GetCursor(),
	)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.ListManagedChildrenResponse{
		Children:   usersToProto(children),
		NextCursor: nextCursor,
	}), nil
}

// GetGuardians returns the guardians of a child account. The caller must be
// a guardian of the child or carry role=admin (the same check the admin RPCs
// enforce, evaluated here against the caller's own account record). The
// service answers non-guardian non-admin callers identically whether or not
// the child exists — no account-existence disclosure.
func (h *IdentityHandler) GetGuardians(
	ctx context.Context,
	req *connect.Request[identitypb.GetGuardiansRequest],
) (*connect.Response[identitypb.GetGuardiansResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	caller, err := h.auth.GetCurrentUser(ctx, callerID)
	if err != nil {
		return nil, toConnectError(err)
	}
	// Same role check the admin RPCs enforce (requireAdminActor).
	callerIsAdmin := strings.EqualFold(caller.Role, service.RoleAdmin)

	guardians, nextCursor, err := h.auth.GetGuardians(
		ctx, callerID, req.Msg.GetChildUserId(), callerIsAdmin,
		req.Msg.GetLimit(), req.Msg.GetCursor(),
	)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.GetGuardiansResponse{
		Guardians:  usersToProto(guardians),
		NextCursor: nextCursor,
	}), nil
}
