// Package entdb is the EntDB-backed implementation of
// service.Repository / service.DB.
//
// It uses the upstream SDK's PUBLIC typed API exclusively — no
// `unsafe`, no reflection on the SDK's private fields. The previous
// implementation used `unsafe` to fish the Transport out of
// *entdb.DbClient because the production code paths needed raw
// `(typeID, fieldID)` access. The new approach goes the opposite
// direction: every read/write goes through the SDK's typed
// `Plan.Create(&schemapb.User{...})` / `entdb.Get[*schemapb.User]` /
// `entdb.Query[*schemapb.User]` / `entdb.GetByKey[T]` surface, with a
// small typeID → witness-message dispatch table for the few code
// paths that have a numeric type id (the legacy service.DB shape).
//
// The dispatch table is the bridge between the legacy raw-node API
// (service.DB.GetNode/QueryNodes/SearchNodes) and the SDK's
// generic-typed API. Every entry in the table is a closure that
// invokes the SDK's package-level generic function with a concrete
// proto witness type from the regenerated schema package — so the
// SDK reads `(entdb.node).type_id` from the descriptor, the wire
// payload is field-id-keyed exactly as the SDK marshals it, and we
// avoid any compile-time type erasure.
package entdb

import (
	"context"
	"errors"
	"fmt"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
)

// Client is the narrow API the entdb-backed Repository / DB adapter
// depends on. It mirrors the legacy `service.DB` shape (raw nodes
// keyed by numeric typeID and field-id payload maps) so the existing
// services that already speak that shape continue to work, but every
// implementation hops through the SDK's PUBLIC typed entry points
// (no unsafe).
type Client interface {
	GetNode(ctx context.Context, tenantID, actor string, typeID int, nodeID string) (*sdk.Node, error)
	QueryNodes(ctx context.Context, tenantID, actor string, typeID int, filter map[string]any) ([]*sdk.Node, error)
	ExecuteAtomic(ctx context.Context, tenantID, actor, idempotencyKey string, ops []sdk.Operation) (*sdk.CommitResult, error)
	GetEdgesFrom(ctx context.Context, tenantID, actor, fromNodeID string, edgeTypeID int) ([]*sdk.Edge, error)
	SearchNodes(ctx context.Context, tenantID, actor string, typeID int, query string) ([]*sdk.Node, error)
}

// SDKClient adapts a *entdb.DbClient to the Client interface.
//
// Reads (GetNode, QueryNodes, SearchNodes) dispatch through a typeID
// → proto-witness factory so we can call the SDK's
// `entdb.Get[*schemapb.X]` / `entdb.Query[*schemapb.X]` /
// `entdb.Search[*schemapb.X]` package-level generics. Writes
// (ExecuteAtomic) go through `client.NewPlan(...).Commit(ctx)`
// using `Plan.Create` / `Plan.Update` / `Delete[T]` /
// `EdgeCreate[T]` / `EdgeDelete[T]` per op kind.
//
// `Plan.Create` only accepts proto messages, but the legacy
// `Operation` shape carries a field-id-keyed `Data` map already
// produced by service-side code. To stay faithful to the SDK's
// "marshal happens once, in the SDK" contract, we walk the map and
// hydrate a concrete *schemapb.X before handing it to Plan.Create.
type SDKClient struct {
	client *sdk.DbClient
}

// NewSDKClient wraps a connected *entdb.DbClient.
func NewSDKClient(c *sdk.DbClient) *SDKClient { return &SDKClient{client: c} }

// scope builds a TenantScope+Actor handle for the given (tenantID, actor)
// pair. The SDK takes (tenantID).Actor(Actor) where Actor is typed.
func (s *SDKClient) scope(tenantID, actor string) (*sdk.Scope, error) {
	a, err := sdk.ParseActor(actor)
	if err != nil {
		return nil, fmt.Errorf("entdb: parse actor %q: %w", actor, err)
	}
	return s.client.Tenant(tenantID).Actor(a), nil
}

// witness is a typed witness factory produced by the proto regen.
// One entry per node typeID we read raw nodes for.
type witness struct {
	get    func(ctx context.Context, scope *sdk.Scope, nodeID string) (proto.Message, *sdk.Node, error)
	query  func(ctx context.Context, scope *sdk.Scope, filter map[string]any) ([]proto.Message, error)
	search func(ctx context.Context, scope *sdk.Scope, query string) ([]proto.Message, error)
	// new returns a fresh empty message of this type; used by
	// ExecuteAtomic to hydrate Plan.Create/Plan.Update calls from
	// the legacy field-id-keyed Operation.Data / Operation.Patch.
	newMsg func() proto.Message
}

// witnessByType is the typeID → witness table. Add a row whenever
// service.DB needs to read or write a new node type. The row has to
// reference the regenerated schemapb concrete type so the SDK can
// pull (entdb.node).type_id from its descriptor.
var witnessByType = map[int]witness{
	1:  witnessFor[*schemapb.User](),
	2:  witnessFor[*schemapb.WorkingGroup](),
	5:  witnessFor[*schemapb.RefreshToken](),
	19: witnessFor[*schemapb.PasswordResetToken](),
	20: witnessFor[*schemapb.PasskeyCredential](),
	21: witnessFor[*schemapb.PasskeyChallenge](),
	22: witnessFor[*schemapb.QrLoginSession](),
	23: witnessFor[*schemapb.TotpCredential](),
	24: witnessFor[*schemapb.RecoveryCode](),
	25: witnessFor[*schemapb.LoginChallenge](),
	26: witnessFor[*schemapb.AuditEvent](),
	27: witnessFor[*schemapb.UserInvitation](),
	28: witnessFor[*schemapb.AdminHelpRequest](),
	29: witnessFor[*schemapb.EmailVerificationToken](),
	30: witnessFor[*schemapb.EmailChangeToken](),
	31: witnessFor[*schemapb.OAuthIdentity](),
}

// witnessFor builds a witness whose closures call the SDK's package-
// level generic functions with a concrete T. Generic methods don't
// exist in Go, so the switch on typeID must compile against a
// concrete type per branch — this helper hides that.
func witnessFor[T proto.Message]() witness {
	return witness{
		get: func(ctx context.Context, scope *sdk.Scope, nodeID string) (proto.Message, *sdk.Node, error) {
			msg, err := sdk.Get[T](ctx, scope, nodeID)
			if err != nil {
				return nil, nil, err
			}
			// `Get[T]` returns the zero T (nil pointer) on
			// not-found; preserve that by returning nil here so
			// the caller can shape it into a `nil *sdk.Node`.
			if !isNonNilMessage(msg) {
				return nil, nil, nil
			}
			node := nodeFromMessage(msg, nodeID)
			return msg, node, nil
		},
		query: func(ctx context.Context, scope *sdk.Scope, filter map[string]any) ([]proto.Message, error) {
			out, err := sdk.Query[T](ctx, scope, filter)
			if err != nil {
				return nil, err
			}
			res := make([]proto.Message, 0, len(out))
			for _, m := range out {
				if !isNonNilMessage(m) {
					continue
				}
				res = append(res, m)
			}
			return res, nil
		},
		search: func(ctx context.Context, scope *sdk.Scope, q string) ([]proto.Message, error) {
			out, err := sdk.Search[T](ctx, scope, q)
			if err != nil {
				return nil, err
			}
			res := make([]proto.Message, 0, len(out))
			for _, m := range out {
				if !isNonNilMessage(m) {
					continue
				}
				res = append(res, m)
			}
			return res, nil
		},
		newMsg: func() proto.Message {
			var zero T
			return zero.ProtoReflect().New().Interface()
		},
	}
}

// isNonNilMessage tells whether a proto.Message wrapped in an
// interface is actually pointing at a value. `var zero *schemapb.User`
// is "non-nil interface, nil pointer" — we want to treat that as nil.
func isNonNilMessage(m proto.Message) bool {
	if m == nil {
		return false
	}
	mr := m.ProtoReflect()
	return mr.IsValid()
}

// nodeFromMessage converts a typed proto message back into a raw
// *sdk.Node (TypeID + field-id-keyed Payload) so legacy callers that
// speak the raw shape see exactly what they expected.
func nodeFromMessage(msg proto.Message, nodeID string) *sdk.Node {
	if msg == nil {
		return nil
	}
	desc := msg.ProtoReflect().Descriptor()
	typeID := readNodeTypeID(desc)
	payload := payloadFromMessage(msg)
	return &sdk.Node{
		NodeID:  nodeID,
		TypeID:  int(typeID),
		Payload: payload,
	}
}

// readNodeTypeID walks the message-options wire format to pull the
// (entdb.node).type_id off the descriptor — the same trick the SDK
// uses internally. Importing the entdb_options package directly would
// pull a transitive dep on every consumer, so we mirror the SDK's
// raw-walk approach.
func readNodeTypeID(desc protoreflect.MessageDescriptor) int32 {
	const extNodeOpts = 50100
	const nodeOptsTypeIDField = 1
	opts := desc.Options()
	if opts == nil {
		return 0
	}
	raw, err := proto.Marshal(opts)
	if err != nil {
		return 0
	}
	inner, ok := findLengthDelimited(raw, uint64(extNodeOpts))
	if !ok {
		return 0
	}
	v, ok := findVarint(inner, uint64(nodeOptsTypeIDField))
	if !ok {
		return 0
	}
	return int32(v)
}

// payloadFromMessage walks a proto message's set fields and returns a
// `field-id (decimal string) → Go scalar` map matching the wire
// shape the SDK marshals on commit.
func payloadFromMessage(msg proto.Message) map[string]any {
	out := make(map[string]any)
	msg.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		out[itoa(int(fd.Number()))] = scalarToGo(fd, v)
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

// translateFilterFieldIDsToNames rewrites a filter map so that any
// keys that look like decimal field ids (the legacy raw-wire shape
// the old repo spoke) are replaced with the proto field name from
// witness's descriptor. Keys that are already proto field names —
// or that begin with `$` (top-level operators like `$or`/`$and`) —
// pass through untouched. Values are not transformed.
func translateFilterFieldIDsToNames(witness proto.Message, filter map[string]any) map[string]any {
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
		num, err := atoi(k)
		if err != nil {
			out[k] = v
			continue
		}
		fd := fields.ByNumber(protoreflect.FieldNumber(num))
		if fd == nil {
			// Unknown field id — pass it through; the server
			// will reject it with a clearer error than we
			// could produce here.
			out[k] = v
			continue
		}
		out[string(fd.Name())] = v
	}
	return out
}

// applyPayloadToMessage hydrates a fresh proto message from a
// field-id-keyed payload. Used by ExecuteAtomic to reconstruct the
// proto witness Plan.Create / Plan.Update expects.
func applyPayloadToMessage(msg proto.Message, payload map[string]any) error {
	if msg == nil {
		return errors.New("entdb: nil message")
	}
	mr := msg.ProtoReflect()
	fields := mr.Descriptor().Fields()
	for k, val := range payload {
		num, err := atoi(k)
		if err != nil {
			fd := fields.ByName(protoreflect.Name(k))
			if fd == nil {
				continue
			}
			pv, err := goToProtoValue(fd, val)
			if err != nil {
				return err
			}
			mr.Set(fd, pv)
			continue
		}
		fd := fields.ByNumber(protoreflect.FieldNumber(num))
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

// ── varint helpers (mirror sdk/marshal.go) ───────────────────────────

func findLengthDelimited(buf []byte, fieldNum uint64) ([]byte, bool) {
	for len(buf) > 0 {
		tag, n := decodeVarint(buf)
		if n == 0 {
			return nil, false
		}
		buf = buf[n:]
		wire := tag & 0x7
		num := tag >> 3
		switch wire {
		case 0:
			_, n = decodeVarint(buf)
			if n == 0 {
				return nil, false
			}
			buf = buf[n:]
		case 1:
			if len(buf) < 8 {
				return nil, false
			}
			buf = buf[8:]
		case 2:
			ln, n := decodeVarint(buf)
			if n == 0 {
				return nil, false
			}
			buf = buf[n:]
			if uint64(len(buf)) < ln {
				return nil, false
			}
			if num == fieldNum {
				return buf[:ln], true
			}
			buf = buf[ln:]
		case 5:
			if len(buf) < 4 {
				return nil, false
			}
			buf = buf[4:]
		default:
			return nil, false
		}
	}
	return nil, false
}

func findVarint(buf []byte, fieldNum uint64) (uint64, bool) {
	for len(buf) > 0 {
		tag, n := decodeVarint(buf)
		if n == 0 {
			return 0, false
		}
		buf = buf[n:]
		wire := tag & 0x7
		num := tag >> 3
		switch wire {
		case 0:
			v, n := decodeVarint(buf)
			if n == 0 {
				return 0, false
			}
			buf = buf[n:]
			if num == fieldNum {
				return v, true
			}
		case 1:
			if len(buf) < 8 {
				return 0, false
			}
			buf = buf[8:]
		case 2:
			ln, n := decodeVarint(buf)
			if n == 0 {
				return 0, false
			}
			buf = buf[n:]
			if uint64(len(buf)) < ln {
				return 0, false
			}
			buf = buf[ln:]
		case 5:
			if len(buf) < 4 {
				return 0, false
			}
			buf = buf[4:]
		default:
			return 0, false
		}
	}
	return 0, false
}

func decodeVarint(buf []byte) (uint64, int) {
	var v uint64
	var shift uint
	for i, b := range buf {
		if i >= 10 {
			return 0, 0
		}
		v |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return v, i + 1
		}
		shift += 7
	}
	return 0, 0
}

// minimalist itoa/atoi to keep dep surface small.

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func atoi(s string) (int, error) {
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
