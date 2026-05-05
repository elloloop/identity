package entdb

import (
	"context"
	"errors"
	"fmt"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"google.golang.org/protobuf/proto"

	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
)

// queriedNode pairs a typed proto message with its node id. The SDK's
// public typed Query[T] discards the node id (it returns []T only),
// which is a documented v1.7.0 limitation — typed find-then-update
// flows that need the node id can only work via this seam, with the
// in-memory test scope filling in the node id and the production
// scope leaving it empty until upstream lands the typed
// "QueryWithIDs" RPC. The realentdb integration test skips the
// PasswordLogin leg for this exact reason.
type queriedNode struct {
	NodeID  string
	Message proto.Message
	// ConsumedAtMarker carries a consumed_at timestamp for proto
	// types that do not yet expose the field on their schema (today:
	// PasswordResetToken). The in-memory test client populates this
	// from its side channel; the production sdkScope leaves it 0.
	// Once upstream adds the missing proto field, this field and
	// markConsumed go away in the same change.
	ConsumedAtMarker int64
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
	// the typed payload. Returns the assigned node id and any
	// consumed-at marker (used by token types whose proto does not yet
	// expose consumed_at — see markConsumed). Single logical operation
	// against the SDK's GetByKey + Get pair, the only path that
	// exercises the server's secondary unique-key index. Returns
	// errNotFound when the key has no matching row.
	findByKey(ctx context.Context, actor string, key sdk.UniqueKey[string], value string, dst proto.Message) (nodeID string, consumedAtMarker int64, err error)
	// query returns nodes matching a non-unique filter. Used for list
	// lookups (e.g. all RefreshTokens for a user). Unique-by-field
	// lookups must go through findByKey, which exercises the secondary
	// index.
	query(ctx context.Context, actor string, witness proto.Message, filter map[string]any) ([]queriedNode, error)
	create(ctx context.Context, actor string, msg proto.Message) (string, error)
	update(ctx context.Context, actor string, nodeID string, msg proto.Message) error
	delete(ctx context.Context, actor string, witness proto.Message, nodeID string) error
	// markConsumed records a consumed_at timestamp for node types
	// whose proto definition does not yet expose the field. Used
	// only by PasswordResetToken on v1.7.0; the conformance fake
	// tracks the marker on a side channel and the production
	// implementation is a no-op pending the upstream proto fix.
	markConsumed(ctx context.Context, actor string, witness proto.Message, nodeID string, atMs int64) error
}

// errNotFound is returned by entClient.get when the requested node id
// does not exist.
var errNotFound = errors.New("entdb: not found")

// sdkScope adapts a *sdk.DbClient to entClient. It calls the SDK's
// package-level typed generic functions through a per-message switch
// — Go's lack of generic methods forces this; the call-site Repository
// methods still pass typed *schemapb.X messages, so the dispatch is
// purely a witness picker for sdk.Get[T] / sdk.Delete[T] and not a
// witness table for the wire payload.
type sdkScope struct {
	client   *sdk.DbClient
	tenantID string
}

func newSDKScope(client *sdk.DbClient, tenantID string) *sdkScope {
	return &sdkScope{client: client, tenantID: tenantID}
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
	}
	return fmt.Errorf("entdb: get: unsupported message type %T", dst)
}

func (s *sdkScope) query(ctx context.Context, actor string, witness proto.Message, filter map[string]any) ([]queriedNode, error) {
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
	}
	return nil, fmt.Errorf("entdb: query: unsupported message type %T", witness)
}

// findByKey looks up a node via the typed unique-key index, then reads
// the typed payload via Get. This is the only path that exercises the
// server's secondary unique-key index — Query[T] with a name-keyed
// filter goes through a different (and currently buggy) read path.
func (s *sdkScope) findByKey(ctx context.Context, actor string, key sdk.UniqueKey[string], value string, dst proto.Message) (string, int64, error) {
	scope, err := s.scope(actor)
	if err != nil {
		return "", 0, err
	}
	node, err := sdk.GetByKey(ctx, scope, key, value)
	if err != nil {
		return "", 0, err
	}
	if node == nil {
		return "", 0, errNotFound
	}
	if err := s.get(ctx, actor, dst, node.NodeID); err != nil {
		return "", 0, err
	}
	// Production server has no side-channel marker; consumed_at lives
	// in the proto once upstream lands the field.
	return node.NodeID, 0, nil
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
	return firstCreatedID(res)
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
	return nil
}

// markConsumed is a no-op against the real server: PasswordResetToken
// on v1.7.0 has no consumed_at proto field. The production reset flow
// works because the server deletes consumed reset tokens after the
// password write succeeds. Once upstream lands the field this becomes
// a typed Update.
func (s *sdkScope) markConsumed(_ context.Context, _ string, _ proto.Message, _ string, _ int64) error {
	return nil
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
	default:
		return fmt.Errorf("entdb: delete: unsupported message type %T", witness)
	}
	if _, err := plan.Commit(ctx); err != nil {
		return err
	}
	return nil
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
		// NodeID stays empty here: sdk.Query[T] on v1.7.0 returns
		// only the typed payload. find-then-update flows that need
		// the node id are blocked on the upstream RPC fix; the
		// realentdb integration test skips PasswordLogin for this
		// reason.
		res = append(res, queriedNode{Message: m})
	}
	return res, nil
}

func isNonNilMessage(m proto.Message) bool {
	if m == nil {
		return false
	}
	return m.ProtoReflect().IsValid()
}

func firstCreatedID(res *sdk.CommitResult) (string, error) {
	if res == nil {
		return "", fmt.Errorf("entdb: nil commit result")
	}
	if !res.Success {
		if res.Error != "" {
			return "", fmt.Errorf("entdb: commit: %s", res.Error)
		}
		return "", fmt.Errorf("entdb: commit not successful")
	}
	if len(res.CreatedNodeIDs) == 0 {
		return "", fmt.Errorf("entdb: commit succeeded but no node id returned")
	}
	return res.CreatedNodeIDs[0], nil
}
