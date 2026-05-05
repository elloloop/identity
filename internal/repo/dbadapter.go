package repo

import (
	"context"
	"errors"
	"fmt"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
	"github.com/elloloop/identity/internal/service"
)

// NewDBAdapter wraps a *sdk.DbClient as a service.DB. service.DB is
// the legacy raw-node access path used by the admin / groups / help /
// profile services and the audit logger; those callers speak in
// numeric type ids and field-id-keyed payload maps. The adapter
// translates that legacy shape into the SDK's typed Plan / Get /
// Query API by picking the concrete proto witness for each numeric
// type id at the boundary.
//
// The dispatch is necessary at this layer — service.DB's signatures
// take type_id as int and payload as map[string]any, so the concrete
// proto type only becomes known here. Internal entdb-repo code uses
// the typed messages directly and does not go through this adapter.
//
// The adapter lives in internal/repo (next to driver.go) rather than
// inside internal/repo/entdb so the entdb package itself is purely
// the typed Repository implementation; the legacy raw-node path is
// scoped to the driver-selection layer.
func NewDBAdapter(client *sdk.DbClient) service.DB {
	return &dbAdapter{client: client}
}

type dbAdapter struct {
	client *sdk.DbClient
}

func (a *dbAdapter) scope(tenantID, actor string) (*sdk.Scope, error) {
	parsed, err := sdk.ParseActor(actor)
	if err != nil {
		return nil, fmt.Errorf("entdb: parse actor %q: %w", actor, err)
	}
	return a.client.Tenant(tenantID).Actor(parsed), nil
}

// witness picks a fresh, writable proto message for a numeric type id.
// This is the type-id → proto-type mapping the typed SDK API needs to
// dispatch sdk.Get[T] / sdk.Query[T] / Plan.Create(T) calls — Go does
// not allow generic methods, so the switch is forced.
func witnessForTypeID(typeID int) (proto.Message, error) {
	switch typeID {
	case 1:
		return &schemapb.User{}, nil
	case 2:
		return &schemapb.WorkingGroup{}, nil
	case 5:
		return &schemapb.RefreshToken{}, nil
	case 19:
		return &schemapb.PasswordResetToken{}, nil
	case 20:
		return &schemapb.PasskeyCredential{}, nil
	case 21:
		return &schemapb.PasskeyChallenge{}, nil
	case 22:
		return &schemapb.QrLoginSession{}, nil
	case 23:
		return &schemapb.TotpCredential{}, nil
	case 24:
		return &schemapb.RecoveryCode{}, nil
	case 25:
		return &schemapb.LoginChallenge{}, nil
	case 26:
		return &schemapb.AuditEvent{}, nil
	case 27:
		return &schemapb.UserInvitation{}, nil
	case 28:
		return &schemapb.AdminHelpRequest{}, nil
	case 29:
		return &schemapb.EmailVerificationToken{}, nil
	case 30:
		return &schemapb.EmailChangeToken{}, nil
	case 31:
		return &schemapb.OAuthIdentity{}, nil
	}
	return nil, fmt.Errorf("entdb: unknown type_id %d", typeID)
}

func (a *dbAdapter) GetNode(ctx context.Context, tenantID, actor string, typeID int, nodeID string) (*sdk.Node, error) {
	scope, err := a.scope(tenantID, actor)
	if err != nil {
		return nil, err
	}
	w, err := witnessForTypeID(typeID)
	if err != nil {
		return nil, err
	}
	msg, err := getByWitness(ctx, scope, w, nodeID)
	if err != nil {
		var nf *sdk.NotFoundError
		if errors.As(err, &nf) {
			return nil, nil
		}
		return nil, err
	}
	if msg == nil {
		return nil, nil
	}
	return nodeFromMessage(typeID, nodeID, msg), nil
}

func (a *dbAdapter) QueryNodes(ctx context.Context, tenantID, actor string, typeID int, filter map[string]any) ([]*sdk.Node, error) {
	scope, err := a.scope(tenantID, actor)
	if err != nil {
		return nil, err
	}
	w, err := witnessForTypeID(typeID)
	if err != nil {
		return nil, err
	}
	// Service callers historically passed filter keys as decimal
	// field ids ("1": email). The typed SDK Query expects proto
	// field names; translate at the boundary so the existing
	// service code keeps working unchanged.
	filter = filterFieldIDsToNames(w, filter)
	msgs, err := queryByWitness(ctx, scope, w, filter)
	if err != nil {
		return nil, err
	}
	out := make([]*sdk.Node, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, nodeFromMessage(typeID, "", m))
	}
	return out, nil
}

func (a *dbAdapter) ExecuteAtomic(ctx context.Context, tenantID, actor, idempotencyKey string, ops []sdk.Operation) (*sdk.CommitResult, error) {
	scope, err := a.scope(tenantID, actor)
	if err != nil {
		return nil, err
	}
	var plan *sdk.Plan
	if idempotencyKey == "" {
		plan = scope.Plan()
	} else {
		plan = scope.PlanWithKey(idempotencyKey)
	}
	for _, op := range ops {
		if err := applyOperation(plan, op); err != nil {
			return nil, err
		}
	}
	return plan.Commit(ctx)
}

func (a *dbAdapter) GetEdgesFrom(ctx context.Context, tenantID, actor, fromNodeID string, edgeTypeID int) ([]*sdk.Edge, error) {
	scope, err := a.scope(tenantID, actor)
	if err != nil {
		return nil, err
	}
	return scope.EdgesFrom(ctx, fromNodeID, edgeTypeID)
}

func (a *dbAdapter) GetEdgesTo(ctx context.Context, tenantID, actor, toNodeID string, edgeTypeID int) ([]*sdk.Edge, error) {
	scope, err := a.scope(tenantID, actor)
	if err != nil {
		return nil, err
	}
	return scope.EdgesTo(ctx, toNodeID, edgeTypeID)
}

func (a *dbAdapter) SearchNodes(ctx context.Context, tenantID, actor string, typeID int, query string) ([]*sdk.Node, error) {
	scope, err := a.scope(tenantID, actor)
	if err != nil {
		return nil, err
	}
	w, err := witnessForTypeID(typeID)
	if err != nil {
		return nil, err
	}
	msgs, err := searchByWitness(ctx, scope, w, query)
	if err != nil {
		return nil, err
	}
	out := make([]*sdk.Node, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, nodeFromMessage(typeID, "", m))
	}
	return out, nil
}

// applyOperation translates one legacy entdb.Operation into a typed
// SDK Plan call. CreateNode / UpdateNode hydrate a fresh proto
// witness from the field-id-keyed payload; DeleteNode and edge ops
// dispatch on the numeric type/edge id.
func applyOperation(plan *sdk.Plan, op sdk.Operation) error {
	switch op.Type {
	case sdk.OpCreateNode:
		w, err := witnessForTypeID(op.TypeID)
		if err != nil {
			return err
		}
		if err := applyPayload(w, op.Data); err != nil {
			return fmt.Errorf("entdb: create payload: %w", err)
		}
		opts := createOptionsFromOp(op)
		_ = plan.Create(w, opts...)
	case sdk.OpUpdateNode:
		w, err := witnessForTypeID(op.TypeID)
		if err != nil {
			return err
		}
		patch := op.Patch
		if len(patch) == 0 {
			patch = op.Data
		}
		if err := applyPayload(w, patch); err != nil {
			return fmt.Errorf("entdb: update payload: %w", err)
		}
		plan.Update(op.NodeID, w)
	case sdk.OpDeleteNode:
		return dispatchDeleteByTypeID(plan, op.TypeID, op.NodeID)
	case sdk.OpCreateEdge:
		return dispatchEdgeByID(plan, op.EdgeTypeID, op.FromNodeID, op.ToNodeID, true)
	case sdk.OpDeleteEdge:
		return dispatchEdgeByID(plan, op.EdgeTypeID, op.FromNodeID, op.ToNodeID, false)
	}
	return fmt.Errorf("entdb: unknown op type %v", op.Type)
}

func createOptionsFromOp(op sdk.Operation) []sdk.CreateOption {
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

func dispatchDeleteByTypeID(plan *sdk.Plan, typeID int, nodeID string) error {
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
		return fmt.Errorf("entdb: unknown delete type_id %d", typeID)
	}
	return nil
}

func dispatchEdgeByID(plan *sdk.Plan, edgeTypeID int, from, to string, create bool) error {
	switch edgeTypeID {
	case 101:
		if create {
			sdk.EdgeCreate[*schemapb.MemberOf](plan, from, to)
		} else {
			sdk.EdgeDelete[*schemapb.MemberOf](plan, from, to)
		}
	case 216:
		if create {
			sdk.EdgeCreate[*schemapb.UserPasskey](plan, from, to)
		} else {
			sdk.EdgeDelete[*schemapb.UserPasskey](plan, from, to)
		}
	case 217:
		if create {
			sdk.EdgeCreate[*schemapb.UserTotp](plan, from, to)
		} else {
			sdk.EdgeDelete[*schemapb.UserTotp](plan, from, to)
		}
	case 218:
		if create {
			sdk.EdgeCreate[*schemapb.UserRecoveryCode](plan, from, to)
		} else {
			sdk.EdgeDelete[*schemapb.UserRecoveryCode](plan, from, to)
		}
	default:
		return fmt.Errorf("entdb: unknown edge_type_id %d", edgeTypeID)
	}
	return nil
}

// getByWitness, queryByWitness, searchByWitness are the per-type
// dispatch helpers that pick the right sdk.Get[T] / sdk.Query[T] /
// sdk.Search[T] instantiation. They mirror dispatchDeleteByTypeID
// for read paths.

func getByWitness(ctx context.Context, scope *sdk.Scope, w proto.Message, nodeID string) (proto.Message, error) {
	switch w.(type) {
	case *schemapb.User:
		return getOne[*schemapb.User](ctx, scope, nodeID)
	case *schemapb.WorkingGroup:
		return getOne[*schemapb.WorkingGroup](ctx, scope, nodeID)
	case *schemapb.RefreshToken:
		return getOne[*schemapb.RefreshToken](ctx, scope, nodeID)
	case *schemapb.PasswordResetToken:
		return getOne[*schemapb.PasswordResetToken](ctx, scope, nodeID)
	case *schemapb.PasskeyCredential:
		return getOne[*schemapb.PasskeyCredential](ctx, scope, nodeID)
	case *schemapb.PasskeyChallenge:
		return getOne[*schemapb.PasskeyChallenge](ctx, scope, nodeID)
	case *schemapb.QrLoginSession:
		return getOne[*schemapb.QrLoginSession](ctx, scope, nodeID)
	case *schemapb.TotpCredential:
		return getOne[*schemapb.TotpCredential](ctx, scope, nodeID)
	case *schemapb.RecoveryCode:
		return getOne[*schemapb.RecoveryCode](ctx, scope, nodeID)
	case *schemapb.LoginChallenge:
		return getOne[*schemapb.LoginChallenge](ctx, scope, nodeID)
	case *schemapb.AuditEvent:
		return getOne[*schemapb.AuditEvent](ctx, scope, nodeID)
	case *schemapb.UserInvitation:
		return getOne[*schemapb.UserInvitation](ctx, scope, nodeID)
	case *schemapb.AdminHelpRequest:
		return getOne[*schemapb.AdminHelpRequest](ctx, scope, nodeID)
	case *schemapb.EmailVerificationToken:
		return getOne[*schemapb.EmailVerificationToken](ctx, scope, nodeID)
	case *schemapb.EmailChangeToken:
		return getOne[*schemapb.EmailChangeToken](ctx, scope, nodeID)
	case *schemapb.OAuthIdentity:
		return getOne[*schemapb.OAuthIdentity](ctx, scope, nodeID)
	}
	return nil, fmt.Errorf("entdb: unsupported witness %T", w)
}

func queryByWitness(ctx context.Context, scope *sdk.Scope, w proto.Message, filter map[string]any) ([]proto.Message, error) {
	switch w.(type) {
	case *schemapb.User:
		return queryAll[*schemapb.User](ctx, scope, filter)
	case *schemapb.WorkingGroup:
		return queryAll[*schemapb.WorkingGroup](ctx, scope, filter)
	case *schemapb.RefreshToken:
		return queryAll[*schemapb.RefreshToken](ctx, scope, filter)
	case *schemapb.PasswordResetToken:
		return queryAll[*schemapb.PasswordResetToken](ctx, scope, filter)
	case *schemapb.PasskeyCredential:
		return queryAll[*schemapb.PasskeyCredential](ctx, scope, filter)
	case *schemapb.PasskeyChallenge:
		return queryAll[*schemapb.PasskeyChallenge](ctx, scope, filter)
	case *schemapb.QrLoginSession:
		return queryAll[*schemapb.QrLoginSession](ctx, scope, filter)
	case *schemapb.TotpCredential:
		return queryAll[*schemapb.TotpCredential](ctx, scope, filter)
	case *schemapb.RecoveryCode:
		return queryAll[*schemapb.RecoveryCode](ctx, scope, filter)
	case *schemapb.LoginChallenge:
		return queryAll[*schemapb.LoginChallenge](ctx, scope, filter)
	case *schemapb.AuditEvent:
		return queryAll[*schemapb.AuditEvent](ctx, scope, filter)
	case *schemapb.UserInvitation:
		return queryAll[*schemapb.UserInvitation](ctx, scope, filter)
	case *schemapb.AdminHelpRequest:
		return queryAll[*schemapb.AdminHelpRequest](ctx, scope, filter)
	case *schemapb.EmailVerificationToken:
		return queryAll[*schemapb.EmailVerificationToken](ctx, scope, filter)
	case *schemapb.EmailChangeToken:
		return queryAll[*schemapb.EmailChangeToken](ctx, scope, filter)
	case *schemapb.OAuthIdentity:
		return queryAll[*schemapb.OAuthIdentity](ctx, scope, filter)
	}
	return nil, fmt.Errorf("entdb: unsupported witness %T", w)
}

func searchByWitness(ctx context.Context, scope *sdk.Scope, w proto.Message, q string) ([]proto.Message, error) {
	switch w.(type) {
	case *schemapb.User:
		return searchAll[*schemapb.User](ctx, scope, q)
	case *schemapb.WorkingGroup:
		return searchAll[*schemapb.WorkingGroup](ctx, scope, q)
	case *schemapb.AuditEvent:
		return searchAll[*schemapb.AuditEvent](ctx, scope, q)
	case *schemapb.AdminHelpRequest:
		return searchAll[*schemapb.AdminHelpRequest](ctx, scope, q)
	}
	return nil, fmt.Errorf("entdb: unsupported witness %T", w)
}

func getOne[T proto.Message](ctx context.Context, scope *sdk.Scope, nodeID string) (proto.Message, error) {
	v, err := sdk.Get[T](ctx, scope, nodeID)
	if err != nil {
		return nil, err
	}
	if !v.ProtoReflect().IsValid() {
		return nil, nil
	}
	return v, nil
}

func queryAll[T proto.Message](ctx context.Context, scope *sdk.Scope, filter map[string]any) ([]proto.Message, error) {
	out, err := sdk.Query[T](ctx, scope, filter)
	if err != nil {
		return nil, err
	}
	res := make([]proto.Message, 0, len(out))
	for _, m := range out {
		if !m.ProtoReflect().IsValid() {
			continue
		}
		res = append(res, m)
	}
	return res, nil
}

func searchAll[T proto.Message](ctx context.Context, scope *sdk.Scope, q string) ([]proto.Message, error) {
	out, err := sdk.Search[T](ctx, scope, q)
	if err != nil {
		return nil, err
	}
	res := make([]proto.Message, 0, len(out))
	for _, m := range out {
		if !m.ProtoReflect().IsValid() {
			continue
		}
		res = append(res, m)
	}
	return res, nil
}

// nodeFromMessage converts a typed proto message back into a raw
// *sdk.Node with the same TypeID + field-id-keyed payload that the
// service-layer callers (admin / groups / help / profile / audit)
// were already speaking.
func nodeFromMessage(typeID int, nodeID string, msg proto.Message) *sdk.Node {
	if msg == nil {
		return nil
	}
	return &sdk.Node{
		NodeID:  nodeID,
		TypeID:  typeID,
		Payload: payloadFromMessage(msg),
	}
}

func payloadFromMessage(msg proto.Message) map[string]any {
	out := make(map[string]any)
	msg.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		out[fmt.Sprintf("%d", int(fd.Number()))] = scalarToGo(fd, v)
		return true
	})
	return out
}

func scalarToGo(fd protoreflect.FieldDescriptor, v protoreflect.Value) any {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return v.Bool()
	case protoreflect.StringKind:
		return v.String()
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return v.Int()
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return v.Int()
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return int64(v.Uint())
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return int64(v.Uint())
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		return v.Float()
	default:
		return v.Interface()
	}
}

// applyPayload hydrates a proto message from a field-id-keyed payload
// (the legacy wire shape service.DB callers speak).
func applyPayload(msg proto.Message, payload map[string]any) error {
	if msg == nil {
		return errors.New("entdb: nil message")
	}
	mr := msg.ProtoReflect()
	fields := mr.Descriptor().Fields()
	for k, val := range payload {
		num, err := strconvAtoi(k)
		var fd protoreflect.FieldDescriptor
		if err != nil {
			fd = fields.ByName(protoreflect.Name(k))
		} else {
			fd = fields.ByNumber(protoreflect.FieldNumber(num))
		}
		if fd == nil {
			continue
		}
		pv, err := goToProtoValue(fd, val)
		if err != nil {
			return err
		}
		mr.Set(fd, pv)
	}
	return nil
}

func goToProtoValue(fd protoreflect.FieldDescriptor, val any) (protoreflect.Value, error) {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		if b, ok := val.(bool); ok {
			return protoreflect.ValueOfBool(b), nil
		}
	case protoreflect.StringKind:
		if s, ok := val.(string); ok {
			return protoreflect.ValueOfString(s), nil
		}
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		n, err := toInt64Wire(val)
		if err == nil {
			return protoreflect.ValueOfInt32(int32(n)), nil
		}
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		n, err := toInt64Wire(val)
		if err == nil {
			return protoreflect.ValueOfInt64(n), nil
		}
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		n, err := toInt64Wire(val)
		if err == nil && n >= 0 {
			return protoreflect.ValueOfUint32(uint32(n)), nil
		}
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		n, err := toInt64Wire(val)
		if err == nil && n >= 0 {
			return protoreflect.ValueOfUint64(uint64(n)), nil
		}
	case protoreflect.FloatKind:
		if f, ok := val.(float64); ok {
			return protoreflect.ValueOfFloat32(float32(f)), nil
		}
	case protoreflect.DoubleKind:
		if f, ok := val.(float64); ok {
			return protoreflect.ValueOfFloat64(f), nil
		}
	}
	return protoreflect.Value{}, fmt.Errorf("entdb: field %s kind %v: cannot convert %T", fd.Name(), fd.Kind(), val)
}

func toInt64Wire(v any) (int64, error) {
	switch x := v.(type) {
	case int:
		return int64(x), nil
	case int32:
		return int64(x), nil
	case int64:
		return x, nil
	case uint:
		return int64(x), nil
	case uint32:
		return int64(x), nil
	case uint64:
		return int64(x), nil
	case float32:
		return int64(x), nil
	case float64:
		return int64(x), nil
	}
	return 0, fmt.Errorf("entdb: cannot coerce %T to int64", v)
}

func filterFieldIDsToNames(witness proto.Message, filter map[string]any) map[string]any {
	if witness == nil || len(filter) == 0 {
		return filter
	}
	desc := witness.ProtoReflect().Descriptor()
	fields := desc.Fields()
	out := make(map[string]any, len(filter))
	for k, v := range filter {
		if k == "" || k[0] == '$' {
			out[k] = v
			continue
		}
		num, err := strconvAtoi(k)
		if err != nil {
			out[k] = v
			continue
		}
		fd := fields.ByNumber(protoreflect.FieldNumber(num))
		if fd == nil {
			out[k] = v
			continue
		}
		out[string(fd.Name())] = v
	}
	return out
}

func strconvAtoi(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	neg := false
	i := 0
	if s[0] == '-' {
		neg = true
		i = 1
	}
	n := 0
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}
