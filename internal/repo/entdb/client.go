package entdb

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
)

// queriedNode pairs a typed proto message with its node id. The SDK's
// public typed Query[T] returns []T only — it does not expose the
// per-row node id — so find-then-update flows route through this seam
// instead. The in-memory test scope fills the node id from its store;
// the production sdkScope's typed-Query fallback leaves it empty, and
// the raw-transport fast path (queryViaTransport) populates it.
type queriedNode struct {
	NodeID  string
	Message proto.Message
}

// entClient is the small surface the typed Repository depends on. Each
// method takes a typed *schemapb.X message; the implementation calls
// the SDK's package-level generic functions or, for the in-memory
// fake, dispatches over its concrete map store.
//
// It is NOT a re-export of the SDK's RPC shape — the methods reflect
// the operations the Repository actually performs on typed proto
// messages. The only place a witness-style switch appears is inside
// sdkScope, where Go's lack of generic methods forces a per-type
// branch to pick the right sdk.Get[T] / sdk.Query[T] instantiation.
type entClient interface {
	get(ctx context.Context, actor string, dst proto.Message, nodeID string) error
	// findByKey looks up a node by a typed unique-key token and reads
	// the typed payload. Returns the assigned node id. Single logical
	// operation against the SDK's GetByKey + Get pair, the only path
	// that exercises the server's secondary unique-key index. Returns
	// errNotFound when the key has no matching row.
	findByKey(ctx context.Context, actor string, key sdk.UniqueKey[string], value string, dst proto.Message) (nodeID string, err error)
	// query returns nodes matching a non-unique filter. Used for list
	// lookups (e.g. all RefreshTokens for a user). Unique-by-field
	// lookups must go through findByKey, which exercises the secondary
	// index.
	query(ctx context.Context, actor string, witness proto.Message, filter map[string]any) ([]queriedNode, error)
	create(ctx context.Context, actor string, msg proto.Message) (string, error)
	update(ctx context.Context, actor string, nodeID string, msg proto.Message) error
	// updateIf is the compare-and-set variant of update. It applies the
	// patch only when the node's current value of `field` equals
	// `equals`; on mismatch it returns errPreconditionFailed without
	// touching the row. The serialization point for state-machine
	// transitions where two replicas must not both win — e.g. the
	// QR-login approved→consumed transition and the refresh-token
	// unconsumed→consumed transition. Backed by the SDK's Plan.UpdateIf
	// primitive (tenant-shard-db v1.13.1+ for the schemaless-mode fix).
	updateIf(ctx context.Context, actor string, nodeID string, msg proto.Message, field string, equals any) error
	delete(ctx context.Context, actor string, witness proto.Message, nodeID string) error
	// deleteExpired removes up to limit rows of the witness type whose
	// expires_at is strictly less than beforeMs. Used by the GC
	// sweeper; takes the typed witness so per-type field ids and
	// type ids stay resolved inside the dispatch table next to the
	// other typed ops, not at the call site.
	deleteExpired(ctx context.Context, actor string, witness proto.Message, beforeMs int64, limit int) (int, error)
	// ensureUserTenantMember registers userID in the global user
	// registry and adds it as a member of the scope's tenant. Both
	// calls tolerate ALREADY_EXISTS so the helper is idempotent
	// across repeat signups under the same id. Required by
	// tenant-shard-db v1.12+, where actors must be registered users
	// AND tenant members before they can issue writes of their own
	// (e.g. a refresh token write keyed by the user's actor). The
	// in-memory test client implements this as a no-op because it
	// bypasses the EntDB global registry entirely.
	ensureUserTenantMember(ctx context.Context, userID, emailAddr, name, role string) error
}

// errNotFound is returned by entClient.get when the requested node id
// does not exist.
var errNotFound = errors.New("entdb: not found")

// errPreconditionFailed is returned by entClient.updateIf when the
// node's current field value did not match the expected value. Callers
// in repo.go map this to the service-layer sentinel that triggers
// "lost the race" semantics (service.ErrQrLoginNotPending for the QR
// transition, service.ErrUnauthenticated for the refresh-token
// rotation race). The production sdkScope path unwraps the SDK's typed
// *entdb.PreconditionFailure into this sentinel so the upstream type
// stays out of the Repository layer.
var errPreconditionFailed = errors.New("entdb: precondition failed")

// sdkScope adapts a *sdk.DbClient to entClient. It calls the SDK's
// package-level typed generic functions through a per-message switch
// — Go's lack of generic methods forces this; the call-site Repository
// methods still pass typed *schemapb.X messages, so the dispatch is
// purely a witness picker for sdk.Get[T] / sdk.Delete[T] and not a
// witness table for the wire payload.
type sdkScope struct {
	client    *sdk.DbClient
	tenantID  string
	transport sdk.Transport
}

func newSDKScope(client *sdk.DbClient, tenantID string) *sdkScope {
	transport, _ := TransportFromClient(client)
	return &sdkScope{client: client, tenantID: tenantID, transport: transport}
}

func (s *sdkScope) scope(actor string) (*sdk.Scope, error) {
	a, err := sdk.ParseActor(actor)
	if err != nil {
		return nil, fmt.Errorf("entdb: parse actor %q: %w", actor, err)
	}
	return s.client.Tenant(s.tenantID).Actor(a), nil
}

func (s *sdkScope) get(ctx context.Context, actor string, dst proto.Message, nodeID string) error {
	scope, err := s.scope(actor)
	if err != nil {
		return err
	}
	switch dst.(type) {
	case *schemapb.User:
		return getInto[*schemapb.User](ctx, scope, dst, nodeID)
	case *schemapb.RefreshToken:
		return getInto[*schemapb.RefreshToken](ctx, scope, dst, nodeID)
	case *schemapb.PasswordResetToken:
		return getInto[*schemapb.PasswordResetToken](ctx, scope, dst, nodeID)
	case *schemapb.PasskeyCredential:
		return getInto[*schemapb.PasskeyCredential](ctx, scope, dst, nodeID)
	case *schemapb.PasskeyChallenge:
		return getInto[*schemapb.PasskeyChallenge](ctx, scope, dst, nodeID)
	case *schemapb.QrLoginSession:
		return getInto[*schemapb.QrLoginSession](ctx, scope, dst, nodeID)
	case *schemapb.TotpCredential:
		return getInto[*schemapb.TotpCredential](ctx, scope, dst, nodeID)
	case *schemapb.RecoveryCode:
		return getInto[*schemapb.RecoveryCode](ctx, scope, dst, nodeID)
	case *schemapb.LoginChallenge:
		return getInto[*schemapb.LoginChallenge](ctx, scope, dst, nodeID)
	case *schemapb.UserInvitation:
		return getInto[*schemapb.UserInvitation](ctx, scope, dst, nodeID)
	case *schemapb.EmailVerificationToken:
		return getInto[*schemapb.EmailVerificationToken](ctx, scope, dst, nodeID)
	case *schemapb.EmailChangeToken:
		return getInto[*schemapb.EmailChangeToken](ctx, scope, dst, nodeID)
	case *schemapb.OAuthIdentity:
		return getInto[*schemapb.OAuthIdentity](ctx, scope, dst, nodeID)
	case *schemapb.IdentityVerificationRecord:
		return getInto[*schemapb.IdentityVerificationRecord](ctx, scope, dst, nodeID)
	case *schemapb.Organization:
		return getInto[*schemapb.Organization](ctx, scope, dst, nodeID)
	case *schemapb.OrganizationMembership:
		return getInto[*schemapb.OrganizationMembership](ctx, scope, dst, nodeID)
	case *schemapb.Session:
		return getInto[*schemapb.Session](ctx, scope, dst, nodeID)
	}
	return fmt.Errorf("entdb: get: unsupported message type %T", dst)
}

func (s *sdkScope) query(ctx context.Context, actor string, witness proto.Message, filter map[string]any) ([]queriedNode, error) {
	if s.transport != nil {
		if rows, ok, err := s.queryViaTransport(ctx, actor, witness, filter); ok {
			return rows, err
		}
	}
	scope, err := s.scope(actor)
	if err != nil {
		return nil, err
	}
	switch witness.(type) {
	case *schemapb.User:
		return queryAs[*schemapb.User](ctx, scope, filter)
	case *schemapb.RefreshToken:
		return queryAs[*schemapb.RefreshToken](ctx, scope, filter)
	case *schemapb.PasswordResetToken:
		return queryAs[*schemapb.PasswordResetToken](ctx, scope, filter)
	case *schemapb.PasskeyCredential:
		return queryAs[*schemapb.PasskeyCredential](ctx, scope, filter)
	case *schemapb.PasskeyChallenge:
		return queryAs[*schemapb.PasskeyChallenge](ctx, scope, filter)
	case *schemapb.QrLoginSession:
		return queryAs[*schemapb.QrLoginSession](ctx, scope, filter)
	case *schemapb.TotpCredential:
		return queryAs[*schemapb.TotpCredential](ctx, scope, filter)
	case *schemapb.RecoveryCode:
		return queryAs[*schemapb.RecoveryCode](ctx, scope, filter)
	case *schemapb.LoginChallenge:
		return queryAs[*schemapb.LoginChallenge](ctx, scope, filter)
	case *schemapb.UserInvitation:
		return queryAs[*schemapb.UserInvitation](ctx, scope, filter)
	case *schemapb.EmailVerificationToken:
		return queryAs[*schemapb.EmailVerificationToken](ctx, scope, filter)
	case *schemapb.EmailChangeToken:
		return queryAs[*schemapb.EmailChangeToken](ctx, scope, filter)
	case *schemapb.OAuthIdentity:
		return queryAs[*schemapb.OAuthIdentity](ctx, scope, filter)
	case *schemapb.IdentityVerificationRecord:
		return queryAs[*schemapb.IdentityVerificationRecord](ctx, scope, filter)
	case *schemapb.Organization:
		return queryAs[*schemapb.Organization](ctx, scope, filter)
	case *schemapb.OrganizationMembership:
		return queryAs[*schemapb.OrganizationMembership](ctx, scope, filter)
	case *schemapb.Session:
		return queryAs[*schemapb.Session](ctx, scope, filter)
	}
	return nil, fmt.Errorf("entdb: query: unsupported message type %T", witness)
}

// findByKey looks up a node via the typed unique-key index, then reads
// the typed payload via Get. This is the only path that exercises the
// server's secondary unique-key index — Query[T] with a name-keyed
// filter goes through a different (and currently buggy) read path.
func (s *sdkScope) findByKey(ctx context.Context, actor string, key sdk.UniqueKey[string], value string, dst proto.Message) (string, error) {
	scope, err := s.scope(actor)
	if err != nil {
		return "", err
	}
	node, err := sdk.GetByKey(ctx, scope, key, value)
	if err != nil {
		return "", err
	}
	if node == nil {
		return "", errNotFound
	}
	if err := s.get(ctx, actor, dst, node.NodeID); err != nil {
		return "", err
	}
	return node.NodeID, nil
}

func (s *sdkScope) create(ctx context.Context, actor string, msg proto.Message) (string, error) {
	scope, err := s.scope(actor)
	if err != nil {
		return "", err
	}
	plan := scope.Plan()
	plan.Create(msg)
	res, err := plan.Commit(ctx)
	if err != nil {
		return "", err
	}
	id, err := firstCreatedID(res)
	if err != nil {
		return "", err
	}
	if err := s.waitForNodeVisible(ctx, actor, msg, id); err != nil {
		return "", err
	}
	return id, nil
}

func (s *sdkScope) update(ctx context.Context, actor string, nodeID string, msg proto.Message) error {
	scope, err := s.scope(actor)
	if err != nil {
		return err
	}
	plan := scope.Plan()
	plan.Update(nodeID, msg)
	if _, err := plan.Commit(ctx); err != nil {
		return err
	}
	return s.waitForPatchVisible(ctx, actor, nodeID, msg)
}

func (s *sdkScope) updateIf(ctx context.Context, actor string, nodeID string, msg proto.Message, field string, equals any) error {
	scope, err := s.scope(actor)
	if err != nil {
		return err
	}
	plan := scope.Plan()
	plan.UpdateIf(nodeID, msg, field, equals)
	if _, err := plan.Commit(ctx); err != nil {
		if errors.Is(err, sdk.ErrPreconditionFailed) {
			return errPreconditionFailed
		}
		return err
	}
	return s.waitForPatchVisible(ctx, actor, nodeID, msg)
}

func (s *sdkScope) ensureUserTenantMember(ctx context.Context, userID, emailAddr, name, role string) error {
	// The global registry's Admin.CreateUser rejects empty name with
	// VALIDATION_ERROR. Identity does not require a display name on
	// signup (and the tenant-scoped User row already absorbed whatever
	// the caller passed), so default to the local-part of the email
	// when name is empty.
	if name == "" {
		name = userID
		if i := strings.IndexByte(emailAddr, '@'); emailAddr != "" && i > 0 {
			name = emailAddr[:i]
		}
	}
	admin := s.client.Admin()
	if _, err := admin.CreateUser(ctx, systemActor, userID, emailAddr, name); err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("entdb: register user %q: %w", userID, err)
	}
	if err := admin.AddTenantMember(ctx, systemActor, s.tenantID, userID, role); err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("entdb: add tenant member %q: %w", userID, err)
	}
	return nil
}

// isAlreadyExists reports whether err is a gRPC ALREADY_EXISTS status
// or carries the canonical "already exists" message fragment. The
// upstream Go server emits the typed gRPC status; the older Python
// implementation embedded the same code in plain-text errors. Both
// paths keep ensureUserTenantMember idempotent.
func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := status.FromError(err); ok {
		return st.Code() == codes.AlreadyExists
	}
	msg := err.Error()
	return strings.Contains(msg, "ALREADY_EXISTS") || strings.Contains(msg, "already exists")
}

// isTenantNotOpened reports whether err is the server-side
// FailedPrecondition signalling that the tenant has no on-disk WAL
// yet — the v1.12.x server returns this on QueryNodes against a
// tenant that has had no writes. Identity treats it as an empty
// result rather than an error so the query-then-create idempotency
// guard works on a brand-new tenant.
func isTenantNotOpened(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "tenant not opened")
}

func (s *sdkScope) rawUpdate(ctx context.Context, actor string, typeID int, nodeID string, patch map[string]any) error {
	if s.transport == nil {
		return errors.New("entdb: raw transport unavailable")
	}
	if _, err := s.transport.ExecuteAtomic(ctx, s.tenantID, actor, "", []sdk.Operation{{
		Type:   sdk.OpUpdateNode,
		TypeID: typeID,
		NodeID: nodeID,
		Patch:  patch,
	}}); err != nil {
		return err
	}
	// ExecuteAtomic queues the op on the WAL; the canonical store
	// catches up asynchronously. Wait for the patch to be visible
	// through a typed get before returning so the very next read
	// observes the update.
	witness, ok := rawUpdateWitness(typeID)
	if !ok {
		return nil
	}
	return s.waitForRawPatchVisible(ctx, actor, witness, nodeID, patch)
}

// rawUpdateWitness returns a zero-value typed *schemapb.X witness for
// the given type id so callers can build a typed get-msg for the
// post-rawUpdate visibility wait. Returns ok=false when the type id is
// outside the schema; callers can still proceed without the wait.
func rawUpdateWitness(typeID int) (proto.Message, bool) {
	if typeID == 1 {
		return &schemapb.User{}, true
	}
	return nil, false
}

// waitForRawPatchVisible polls a typed Get until the field-id map
// patch produced by rawUpdate is reflected in the stored node. The
// proto3-Range visibility helper used after Plan.Update doesn't
// understand raw field-id patches, so this helper does a structural
// match instead: every patch field becomes a typed proto-reflect Set
// against a typed witness, and we wait until the stored row's
// reflected values match.
//
// When the patch has an unknown field id, the wait is skipped (the
// caller's next read will hit the same applier eventually); the
// rawUpdate itself already succeeded on the server.
func (s *sdkScope) waitForRawPatchVisible(ctx context.Context, actor string, witness proto.Message, nodeID string, patch map[string]any) error {
	want := newMessageLike(witness)
	if !applyRawPatchToProto(want, patch) {
		return nil
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		got := newMessageLike(witness)
		err := s.get(ctx, actor, got, nodeID)
		if err == nil && rawPatchApplied(want.ProtoReflect(), got.ProtoReflect(), patch) {
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return err
			}
			return fmt.Errorf("entdb: raw patch visibility timeout for %s", nodeID)
		}
		if err := sleepOrContextDone(ctx, 50*time.Millisecond); err != nil {
			return err
		}
	}
}

// applyRawPatchToProto sets each field-id→value entry on the proto
// message via proto-reflect, so callers can build a "want" message
// from a rawUpdate map. Returns false when the patch can't be
// reflected onto the witness (unknown field id, wrong scalar kind);
// callers treat that as "skip the post-update wait, the server
// applied it anyway."
func applyRawPatchToProto(msg proto.Message, patch map[string]any) bool {
	fields := msg.ProtoReflect().Descriptor().Fields()
	for k, v := range patch {
		fd := lookupFieldByRawID(fields, k)
		if fd == nil {
			return false
		}
		val, ok := protoValueFromAny(fd, v)
		if !ok {
			return false
		}
		msg.ProtoReflect().Set(fd, val)
	}
	return true
}

// lookupFieldByRawID resolves a rawUpdate map key (decimal field id as
// a string) back to the proto descriptor. Returns nil when the key
// isn't a valid proto field-number (non-numeric, negative, > int32
// max, or unknown to the descriptor); callers treat that as "skip the
// post-update wait."
func lookupFieldByRawID(fields protoreflect.FieldDescriptors, key string) protoreflect.FieldDescriptor {
	n, err := strconv.ParseInt(key, 10, 32)
	if err != nil || n <= 0 {
		return nil
	}
	return fields.ByNumber(protoreflect.FieldNumber(n))
}

// rawPatchApplied reports whether every field in the rawUpdate patch
// matches the corresponding field on the stored proto. Zero values
// in the patch (e.g. failed_login_count=0) match only when the
// stored value is also zero, which is the whole point of the wait.
func rawPatchApplied(want, got protoreflect.Message, patch map[string]any) bool {
	fields := want.Descriptor().Fields()
	for k := range patch {
		fd := lookupFieldByRawID(fields, k)
		if fd == nil {
			continue
		}
		if !want.Get(fd).Equal(got.Get(fd)) {
			return false
		}
	}
	return true
}

// protoValueFromAny coerces a Go value from a rawUpdate map into a
// protoreflect.Value of the kind the field expects. Mirrors the
// conversions sdk.ExecuteAtomic performs on the wire. Returns ok=false
// when the value can't be coerced; callers treat that as "skip the
// post-update wait."
func protoValueFromAny(fd protoreflect.FieldDescriptor, v any) (protoreflect.Value, bool) {
	switch fd.Kind() {
	case protoreflect.StringKind:
		s, ok := v.(string)
		if !ok {
			return protoreflect.Value{}, false
		}
		return protoreflect.ValueOfString(s), true
	case protoreflect.BoolKind:
		b, ok := v.(bool)
		if !ok {
			return protoreflect.Value{}, false
		}
		return protoreflect.ValueOfBool(b), true
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		switch n := v.(type) {
		case int64:
			return protoreflect.ValueOfInt64(n), true
		case int:
			return protoreflect.ValueOfInt64(int64(n)), true
		case int32:
			return protoreflect.ValueOfInt64(int64(n)), true
		}
		return protoreflect.Value{}, false
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		switch n := v.(type) {
		case int64:
			if n < math.MinInt32 || n > math.MaxInt32 {
				return protoreflect.Value{}, false
			}
			return protoreflect.ValueOfInt32(int32(n)), true
		case int:
			if int64(n) < math.MinInt32 || int64(n) > math.MaxInt32 {
				return protoreflect.Value{}, false
			}
			return protoreflect.ValueOfInt32(int32(n)), true
		case int32:
			return protoreflect.ValueOfInt32(n), true
		}
		return protoreflect.Value{}, false
	}
	return protoreflect.Value{}, false
}

// expiresAtSweepSpec returns the (type id, expires_at field id) pair
// the raw transport needs to query and delete expired rows for the
// witness type. Returns ok=false for types the sweeper does not own;
// callers report that as an unsupported-type error rather than a
// silent no-op so a new sweep target can never land without an entry
// here. The values match the proto schema (see
// proto/identity/schema/schema.proto).
func expiresAtSweepSpec(witness proto.Message) (typeID, fieldID int, ok bool) {
	switch witness.(type) {
	case *schemapb.PasskeyChallenge:
		return 21, 4, true
	case *schemapb.PasswordResetToken:
		return 19, 3, true
	case *schemapb.EmailVerificationToken:
		return 29, 4, true
	case *schemapb.EmailChangeToken:
		return 30, 5, true
	case *schemapb.LoginChallenge:
		return 25, 3, true
	}
	return 0, 0, false
}

func (s *sdkScope) deleteExpired(ctx context.Context, actor string, witness proto.Message, beforeMs int64, limit int) (int, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("entdb: deleteExpired: limit must be > 0, got %d", limit)
	}
	if s.transport == nil {
		return 0, errors.New("entdb: deleteExpired: raw transport unavailable")
	}
	typeID, fieldID, ok := expiresAtSweepSpec(witness)
	if !ok {
		return 0, fmt.Errorf("entdb: deleteExpired: unsupported message type %T", witness)
	}

	// QueryNodes accepts payload-field-id keys (decimal string) for
	// the filter map, matching the wire's "field IDs, not field names,
	// on disk" invariant. "$lt" is the wire-level less-than operator
	// shipped in tenant-shard-db v1.12 (FilterLt in the typed SDK).
	filter := map[string]any{
		strconv.Itoa(fieldID): map[string]any{"$lt": beforeMs},
	}
	nodes, err := s.transport.QueryNodes(ctx, s.tenantID, actor, typeID, filter)
	if err != nil {
		// A tenant that has had no writes returns "tenant not opened";
		// treat that as "nothing to sweep" the same way the rest of
		// the repo does for query-then-create idempotency.
		if isTenantNotOpened(err) {
			return 0, nil
		}
		return 0, err
	}
	if len(nodes) == 0 {
		return 0, nil
	}

	// QueryNodes on tenant-shard-db v1.12.4 ignores WithLimit/WithOffset
	// (queryConfig is unused on the wire per scope.go's comment), so
	// the cap is applied client-side. The expires_at column is indexed
	// per the proto schema, so the server still walks an index range
	// — only the network payload is larger than strictly needed.
	if len(nodes) > limit {
		nodes = nodes[:limit]
	}

	ops := make([]sdk.Operation, 0, len(nodes))
	for _, n := range nodes {
		ops = append(ops, sdk.Operation{
			Type:   sdk.OpDeleteNode,
			TypeID: typeID,
			NodeID: n.NodeID,
		})
	}
	if _, err := s.transport.ExecuteAtomic(ctx, s.tenantID, actor, "", ops); err != nil {
		return 0, err
	}
	return len(ops), nil
}

func (s *sdkScope) delete(ctx context.Context, actor string, witness proto.Message, nodeID string) error {
	scope, err := s.scope(actor)
	if err != nil {
		return err
	}
	plan := scope.Plan()
	switch witness.(type) {
	case *schemapb.User:
		sdk.Delete[*schemapb.User](plan, nodeID)
	case *schemapb.RefreshToken:
		sdk.Delete[*schemapb.RefreshToken](plan, nodeID)
	case *schemapb.PasswordResetToken:
		sdk.Delete[*schemapb.PasswordResetToken](plan, nodeID)
	case *schemapb.PasskeyCredential:
		sdk.Delete[*schemapb.PasskeyCredential](plan, nodeID)
	case *schemapb.PasskeyChallenge:
		sdk.Delete[*schemapb.PasskeyChallenge](plan, nodeID)
	case *schemapb.QrLoginSession:
		sdk.Delete[*schemapb.QrLoginSession](plan, nodeID)
	case *schemapb.TotpCredential:
		sdk.Delete[*schemapb.TotpCredential](plan, nodeID)
	case *schemapb.RecoveryCode:
		sdk.Delete[*schemapb.RecoveryCode](plan, nodeID)
	case *schemapb.LoginChallenge:
		sdk.Delete[*schemapb.LoginChallenge](plan, nodeID)
	case *schemapb.UserInvitation:
		sdk.Delete[*schemapb.UserInvitation](plan, nodeID)
	case *schemapb.EmailVerificationToken:
		sdk.Delete[*schemapb.EmailVerificationToken](plan, nodeID)
	case *schemapb.EmailChangeToken:
		sdk.Delete[*schemapb.EmailChangeToken](plan, nodeID)
	case *schemapb.OAuthIdentity:
		sdk.Delete[*schemapb.OAuthIdentity](plan, nodeID)
	case *schemapb.IdentityVerificationRecord:
		sdk.Delete[*schemapb.IdentityVerificationRecord](plan, nodeID)
	case *schemapb.Organization:
		sdk.Delete[*schemapb.Organization](plan, nodeID)
	case *schemapb.OrganizationMembership:
		sdk.Delete[*schemapb.OrganizationMembership](plan, nodeID)
	case *schemapb.Session:
		sdk.Delete[*schemapb.Session](plan, nodeID)
	default:
		return fmt.Errorf("entdb: delete: unsupported message type %T", witness)
	}
	if _, err := plan.Commit(ctx); err != nil {
		return err
	}
	return s.waitForNodeDeleted(ctx, actor, witness, nodeID)
}

func getInto[T proto.Message](ctx context.Context, scope *sdk.Scope, dst proto.Message, nodeID string) error {
	v, err := sdk.Get[T](ctx, scope, nodeID)
	if err != nil {
		return err
	}
	if !isNonNilMessage(v) {
		return errNotFound
	}
	proto.Merge(dst, v)
	return nil
}

func queryAs[T proto.Message](ctx context.Context, scope *sdk.Scope, filter map[string]any) ([]queriedNode, error) {
	out, err := sdk.Query[T](ctx, scope, filter)
	if err != nil {
		return nil, err
	}
	res := make([]queriedNode, 0, len(out))
	for _, m := range out {
		if !isNonNilMessage(m) {
			continue
		}
		// NodeID stays empty here: sdk.Query[T] returns only the
		// typed payload. Find-then-update flows that need the node
		// id either fall back to the raw transport (queryViaTransport
		// above, which carries the id) or skip the leg entirely.
		res = append(res, queriedNode{Message: m})
	}
	return res, nil
}

func (s *sdkScope) queryViaTransport(ctx context.Context, actor string, witness proto.Message, filter map[string]any) ([]queriedNode, bool, error) {
	typeID, rawFilter, ok := rawQuerySpec(witness, filter)
	if !ok {
		return nil, false, nil
	}
	nodes, err := s.transport.QueryNodes(ctx, s.tenantID, actor, typeID, rawFilter)
	if err != nil {
		// tenant-shard-db v1.12.x returns FailedPrecondition
		// "tenant not opened" on a QueryNodes against a tenant that
		// hasn't had a write yet. Identity uses query-then-create
		// as the duplicate guard for several entities (OAuth links,
		// users by email), so an empty tenant is a valid
		// pre-condition for "no matches" rather than an error.
		if isTenantNotOpened(err) {
			return nil, true, nil
		}
		return nil, true, err
	}
	out := make([]queriedNode, 0, len(nodes))
	for _, node := range nodes {
		msg := newMessageLike(witness)
		if err := s.get(ctx, actor, msg, node.NodeID); err != nil {
			return nil, true, err
		}
		out = append(out, queriedNode{
			NodeID:  node.NodeID,
			Message: msg,
		})
	}
	return out, true, nil
}

// rawQueryFieldSpec maps proto field names to raw-transport field
// ids for one node type. The server's QueryNodes RPC takes the raw
// numeric filter keys, not the proto field names.
type rawQueryFieldSpec struct {
	typeID int
	fields map[string]string
}

var (
	rawQuerySpecUser                       = rawQueryFieldSpec{1, map[string]string{"email": "1"}}
	rawQuerySpecRefreshToken               = rawQueryFieldSpec{5, map[string]string{"user_id": "2"}}
	rawQuerySpecPasskeyCredential          = rawQueryFieldSpec{20, map[string]string{"user_id": "2"}}
	rawQuerySpecTotpCredential             = rawQueryFieldSpec{23, map[string]string{"user_id": "1"}}
	rawQuerySpecRecoveryCode               = rawQueryFieldSpec{24, map[string]string{"user_id": "1", "code_hash": "2"}}
	rawQuerySpecOAuthIdentity              = rawQueryFieldSpec{31, map[string]string{"user_id": "1", "provider": "2", "provider_user_id": "3"}}
	rawQuerySpecIdentityVerificationRecord = rawQueryFieldSpec{32, map[string]string{"user_id": "2"}}
	rawQuerySpecOrganizationMembership     = rawQueryFieldSpec{34, map[string]string{"organization_id": "1", "user_id": "2"}}
	rawQuerySpecSession                    = rawQueryFieldSpec{35, map[string]string{"sid": "1", "user_id": "2"}}
)

func rawQueryFieldSpecFor(witness proto.Message) (rawQueryFieldSpec, bool) {
	switch witness.(type) {
	case *schemapb.User:
		return rawQuerySpecUser, true
	case *schemapb.RefreshToken:
		return rawQuerySpecRefreshToken, true
	case *schemapb.PasskeyCredential:
		return rawQuerySpecPasskeyCredential, true
	case *schemapb.TotpCredential:
		return rawQuerySpecTotpCredential, true
	case *schemapb.RecoveryCode:
		return rawQuerySpecRecoveryCode, true
	case *schemapb.OAuthIdentity:
		return rawQuerySpecOAuthIdentity, true
	case *schemapb.IdentityVerificationRecord:
		return rawQuerySpecIdentityVerificationRecord, true
	case *schemapb.OrganizationMembership:
		return rawQuerySpecOrganizationMembership, true
	case *schemapb.Session:
		return rawQuerySpecSession, true
	default:
		return rawQueryFieldSpec{}, false
	}
}

func rawQuerySpec(witness proto.Message, filter map[string]any) (int, map[string]any, bool) {
	spec, ok := rawQueryFieldSpecFor(witness)
	if !ok {
		return 0, nil, false
	}
	rawFilter := make(map[string]any, len(filter))
	for k, v := range filter {
		fieldID, ok := spec.fields[k]
		if !ok {
			return 0, nil, false
		}
		rawFilter[fieldID] = v
	}
	return spec.typeID, rawFilter, true
}

func newMessageLike(witness proto.Message) proto.Message {
	return witness.ProtoReflect().New().Interface()
}

func (s *sdkScope) waitForNodeVisible(ctx context.Context, actor string, witness proto.Message, nodeID string) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		msg := newMessageLike(witness)
		err := s.get(ctx, actor, msg, nodeID)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		if err := sleepOrContextDone(ctx, 50*time.Millisecond); err != nil {
			return err
		}
	}
}

func (s *sdkScope) waitForPatchVisible(ctx context.Context, actor, nodeID string, patch proto.Message) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		msg := newMessageLike(patch)
		err := s.get(ctx, actor, msg, nodeID)
		if err == nil && patchApplied(patch.ProtoReflect(), msg.ProtoReflect()) {
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return err
			}
			return fmt.Errorf("entdb: patch visibility timeout for %s", nodeID)
		}
		if err := sleepOrContextDone(ctx, 50*time.Millisecond); err != nil {
			return err
		}
	}
}

func (s *sdkScope) waitForNodeDeleted(ctx context.Context, actor string, witness proto.Message, nodeID string) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		msg := newMessageLike(witness)
		err := s.get(ctx, actor, msg, nodeID)
		if errors.Is(err, errNotFound) {
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return err
			}
			return fmt.Errorf("entdb: delete visibility timeout for %s", nodeID)
		}
		if err := sleepOrContextDone(ctx, 50*time.Millisecond); err != nil {
			return err
		}
	}
}

func sleepOrContextDone(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func patchApplied(want, got protoreflect.Message) bool {
	set := true
	want.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if !got.Has(fd) {
			set = false
			return false
		}
		if got.Get(fd).Interface() != v.Interface() {
			set = false
			return false
		}
		return true
	})
	return set
}

func isNonNilMessage(m proto.Message) bool {
	if m == nil {
		return false
	}
	return m.ProtoReflect().IsValid()
}

func firstCreatedID(res *sdk.CommitResult) (string, error) {
	if res == nil {
		return "", errors.New("entdb: nil commit result")
	}
	if !res.Success {
		if res.Error != "" {
			return "", fmt.Errorf("entdb: commit: %s", res.Error)
		}
		return "", errors.New("entdb: commit not successful")
	}
	if len(res.CreatedNodeIDs) == 0 {
		return "", errors.New("entdb: commit succeeded but no node id returned")
	}
	return res.CreatedNodeIDs[0], nil
}
