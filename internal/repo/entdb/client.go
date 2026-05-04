package entdb

import (
	"context"
	"errors"
	"fmt"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
)

// GetNode fetches a single node by id. The witness table picks the
// concrete proto T so the SDK can read (entdb.node).type_id from the
// descriptor and decode the wire payload back into T. We then map the
// proto back to a *sdk.Node so legacy callers see the raw shape.
func (s *SDKClient) GetNode(ctx context.Context, tenantID, actor string, typeID int, nodeID string) (*sdk.Node, error) {
	w, ok := witnessByType[typeID]
	if !ok {
		return nil, fmt.Errorf("entdb: GetNode: unknown type_id %d", typeID)
	}
	scope, err := s.scope(tenantID, actor)
	if err != nil {
		return nil, err
	}
	_, node, err := w.get(ctx, scope, nodeID)
	if err != nil {
		var nf *sdk.NotFoundError
		if errors.As(err, &nf) {
			return nil, nil
		}
		return nil, err
	}
	if node != nil {
		node.TypeID = typeID
	}
	return node, nil
}

// QueryNodes runs a filter query for nodes of a given typeID.
func (s *SDKClient) QueryNodes(ctx context.Context, tenantID, actor string, typeID int, filter map[string]any) ([]*sdk.Node, error) {
	w, ok := witnessByType[typeID]
	if !ok {
		return nil, fmt.Errorf("entdb: QueryNodes: unknown type_id %d", typeID)
	}
	scope, err := s.scope(tenantID, actor)
	if err != nil {
		return nil, err
	}
	msgs, err := w.query(ctx, scope, filter)
	if err != nil {
		return nil, err
	}
	out := make([]*sdk.Node, 0, len(msgs))
	for _, m := range msgs {
		n := nodeFromMessage(m, "")
		if n != nil {
			n.TypeID = typeID
		}
		out = append(out, n)
	}
	return out, nil
}

// SearchNodes runs FTS over the type's searchable fields.
func (s *SDKClient) SearchNodes(ctx context.Context, tenantID, actor string, typeID int, query string) ([]*sdk.Node, error) {
	w, ok := witnessByType[typeID]
	if !ok {
		return nil, fmt.Errorf("entdb: SearchNodes: unknown type_id %d", typeID)
	}
	scope, err := s.scope(tenantID, actor)
	if err != nil {
		return nil, err
	}
	msgs, err := w.search(ctx, scope, query)
	if err != nil {
		return nil, err
	}
	out := make([]*sdk.Node, 0, len(msgs))
	for _, m := range msgs {
		n := nodeFromMessage(m, "")
		if n != nil {
			n.TypeID = typeID
		}
		out = append(out, n)
	}
	return out, nil
}

// GetEdgesFrom delegates to the SDK's typed Scope.EdgesFrom.
func (s *SDKClient) GetEdgesFrom(ctx context.Context, tenantID, actor, fromNodeID string, edgeTypeID int) ([]*sdk.Edge, error) {
	scope, err := s.scope(tenantID, actor)
	if err != nil {
		return nil, err
	}
	return scope.EdgesFrom(ctx, fromNodeID, edgeTypeID)
}

// ExecuteAtomic walks the legacy []sdk.Operation list and replays
// each op through the SDK's typed Plan API. CreateNode hydrates a
// concrete proto witness from the field-id-keyed Data map and calls
// Plan.Create(msg). UpdateNode hydrates one for Patch and calls
// Plan.Update(nodeID, msg). DeleteNode/CreateEdge/DeleteEdge call
// the package-level generic helpers via a typeID dispatch.
func (s *SDKClient) ExecuteAtomic(ctx context.Context, tenantID, actor, idempotencyKey string, ops []sdk.Operation) (*sdk.CommitResult, error) {
	var plan *sdk.Plan
	if idempotencyKey == "" {
		plan = s.client.NewPlan(tenantID, actor)
	} else {
		plan = s.client.NewPlanWithKey(tenantID, actor, idempotencyKey)
	}

	for _, op := range ops {
		if err := s.applyOp(plan, op); err != nil {
			return nil, err
		}
	}
	return plan.Commit(ctx)
}

func (s *SDKClient) applyOp(plan *sdk.Plan, op sdk.Operation) error {
	switch op.Type {
	case sdk.OpCreateNode:
		w, ok := witnessByType[op.TypeID]
		if !ok {
			return fmt.Errorf("entdb: ExecuteAtomic: unknown create type_id %d", op.TypeID)
		}
		msg := w.newMsg()
		if err := applyPayloadToMessage(msg, op.Data); err != nil {
			return fmt.Errorf("entdb: ExecuteAtomic: hydrate create payload: %w", err)
		}
		opts := createOptions(op)
		_ = plan.Create(msg, opts...)
	case sdk.OpUpdateNode:
		w, ok := witnessByType[op.TypeID]
		if !ok {
			return fmt.Errorf("entdb: ExecuteAtomic: unknown update type_id %d", op.TypeID)
		}
		msg := w.newMsg()
		if err := applyPayloadToMessage(msg, op.Patch); err != nil {
			return fmt.Errorf("entdb: ExecuteAtomic: hydrate update payload: %w", err)
		}
		plan.Update(op.NodeID, msg)
	case sdk.OpDeleteNode:
		if err := dispatchDelete(plan, op.TypeID, op.NodeID); err != nil {
			return err
		}
	case sdk.OpCreateEdge:
		if err := dispatchEdgeCreate(plan, op.EdgeTypeID, op.FromNodeID, op.ToNodeID); err != nil {
			return err
		}
	case sdk.OpDeleteEdge:
		if err := dispatchEdgeDelete(plan, op.EdgeTypeID, op.FromNodeID, op.ToNodeID); err != nil {
			return err
		}
	default:
		return fmt.Errorf("entdb: ExecuteAtomic: unknown op type %v", op.Type)
	}
	return nil
}

// createOptions translates the legacy Operation fields into SDK
// CreateOption values. ACL, storage mode, alias, and target user are
// the four configurable knobs.
func createOptions(op sdk.Operation) []sdk.CreateOption {
	var opts []sdk.CreateOption
	if len(op.ACL) > 0 {
		opts = append(opts, sdk.WithACL(op.ACL...))
	}
	if op.Alias != "" {
		opts = append(opts, sdk.As(op.Alias))
	}
	switch op.StorageMode {
	case sdk.StorageModeUserMailbox:
		if op.TargetUserID != "" {
			opts = append(opts, sdk.InMailbox(op.TargetUserID))
		}
	case sdk.StorageModePublic:
		opts = append(opts, sdk.InPublic())
	}
	return opts
}

// dispatchDelete dispatches sdk.Delete[T] by numeric type id. Each
// branch is a one-line `sdk.Delete[*schemapb.X](plan, nodeID)` call
// so the SDK reads (entdb.node).type_id from T's descriptor at
// compile time.
func dispatchDelete(plan *sdk.Plan, typeID int, nodeID string) error {
	switch typeID {
	case 1:
		sdk.Delete[*schemapb.User](plan, nodeID)
	case 2:
		sdk.Delete[*schemapb.WorkingGroup](plan, nodeID)
	case 5:
		sdk.Delete[*schemapb.RefreshToken](plan, nodeID)
	case 19:
		sdk.Delete[*schemapb.PasswordResetToken](plan, nodeID)
	case 20:
		sdk.Delete[*schemapb.PasskeyCredential](plan, nodeID)
	case 21:
		sdk.Delete[*schemapb.PasskeyChallenge](plan, nodeID)
	case 22:
		sdk.Delete[*schemapb.QrLoginSession](plan, nodeID)
	case 23:
		sdk.Delete[*schemapb.TotpCredential](plan, nodeID)
	case 24:
		sdk.Delete[*schemapb.RecoveryCode](plan, nodeID)
	case 25:
		sdk.Delete[*schemapb.LoginChallenge](plan, nodeID)
	case 26:
		sdk.Delete[*schemapb.AuditEvent](plan, nodeID)
	case 27:
		sdk.Delete[*schemapb.UserInvitation](plan, nodeID)
	case 28:
		sdk.Delete[*schemapb.AdminHelpRequest](plan, nodeID)
	case 29:
		sdk.Delete[*schemapb.EmailVerificationToken](plan, nodeID)
	case 30:
		sdk.Delete[*schemapb.EmailChangeToken](plan, nodeID)
	case 31:
		sdk.Delete[*schemapb.OAuthIdentity](plan, nodeID)
	default:
		return fmt.Errorf("entdb: ExecuteAtomic: unknown delete type_id %d", typeID)
	}
	return nil
}

func dispatchEdgeCreate(plan *sdk.Plan, edgeTypeID int, from, to string) error {
	switch edgeTypeID {
	case 101:
		sdk.EdgeCreate[*schemapb.MemberOf](plan, from, to)
	case 216:
		sdk.EdgeCreate[*schemapb.UserPasskey](plan, from, to)
	case 217:
		sdk.EdgeCreate[*schemapb.UserTotp](plan, from, to)
	case 218:
		sdk.EdgeCreate[*schemapb.UserRecoveryCode](plan, from, to)
	default:
		return fmt.Errorf("entdb: ExecuteAtomic: unknown edge_type_id %d", edgeTypeID)
	}
	return nil
}

func dispatchEdgeDelete(plan *sdk.Plan, edgeTypeID int, from, to string) error {
	switch edgeTypeID {
	case 101:
		sdk.EdgeDelete[*schemapb.MemberOf](plan, from, to)
	case 216:
		sdk.EdgeDelete[*schemapb.UserPasskey](plan, from, to)
	case 217:
		sdk.EdgeDelete[*schemapb.UserTotp](plan, from, to)
	case 218:
		sdk.EdgeDelete[*schemapb.UserRecoveryCode](plan, from, to)
	default:
		return fmt.Errorf("entdb: ExecuteAtomic: unknown edge_type_id %d", edgeTypeID)
	}
	return nil
}
