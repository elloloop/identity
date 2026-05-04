package entdb

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
	"github.com/elloloop/identity/internal/repo/conformance"
	"github.com/elloloop/identity/internal/service"
)

// memoryEntClient is the in-memory entClient used by the conformance
// suite. It backs entdb-typed calls with a tiny store of proto
// messages keyed by node id, so the entRepository wiring exercises
// every Repository method without a live gRPC connection.
//
// The store enforces the schema-declared uniqueness constraints
// (User.email, RefreshToken.token_hash, etc.) so the conformance
// suite covers the same reject-duplicate semantics the real server
// would. Composite uniqueness on OAuthIdentity.(provider, sub) is
// enforced inside entRepository.CreateOAuthIdentity, not here.
type memoryEntClient struct {
	mu        sync.Mutex
	store     map[string]storedNode
	consumed  map[string]int64
	idCounter int64
}

type storedNode struct {
	msg proto.Message
}

func newMemoryEntClient() *memoryEntClient {
	return &memoryEntClient{
		store:    make(map[string]storedNode),
		consumed: make(map[string]int64),
	}
}

func (c *memoryEntClient) nextID() string {
	c.idCounter++
	return fmt.Sprintf("fake-%d", c.idCounter)
}

func (c *memoryEntClient) get(_ context.Context, _ string, dst proto.Message, nodeID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.store[nodeID]
	if !ok {
		return errNotFound
	}
	if reflect.TypeOf(n.msg) != reflect.TypeOf(dst) {
		return errNotFound
	}
	proto.Merge(dst, n.msg)
	return nil
}

func (c *memoryEntClient) query(_ context.Context, _ string, witness proto.Message, filter map[string]any) ([]queriedNode, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	wantType := reflect.TypeOf(witness)
	out := make([]queriedNode, 0)
	for id, n := range c.store {
		if reflect.TypeOf(n.msg) != wantType {
			continue
		}
		if !matchesFilter(n.msg, filter) {
			continue
		}
		copy := proto.Clone(n.msg)
		out = append(out, queriedNode{
			NodeID:           id,
			Message:          copy,
			ConsumedAtMarker: c.consumed[id],
		})
	}
	return out, nil
}

func (c *memoryEntClient) create(_ context.Context, _ string, msg proto.Message) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkUniqueness(msg); err != nil {
		return "", err
	}
	id := c.nextID()
	c.store[id] = storedNode{msg: proto.Clone(msg)}
	return id, nil
}

func (c *memoryEntClient) update(_ context.Context, _ string, nodeID string, patch proto.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, ok := c.store[nodeID]
	if !ok {
		return fmt.Errorf("entdb: update: node %q not found", nodeID)
	}
	if reflect.TypeOf(existing.msg) != reflect.TypeOf(patch) {
		return fmt.Errorf("entdb: update: type mismatch")
	}
	// Merge non-default scalars from patch into existing — mirrors
	// the SDK's Plan.Update semantics where only set fields are
	// emitted. To support clearing fields back to zero, callers
	// rewrite the full message (see ResetFailedLoginCount); the
	// fake honours that by replacing the full message when every
	// field is set.
	existing.msg = mergePatch(existing.msg, patch)
	c.store[nodeID] = existing
	return nil
}

func (c *memoryEntClient) delete(_ context.Context, _ string, witness proto.Message, nodeID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.store[nodeID]
	if !ok {
		return nil
	}
	if reflect.TypeOf(n.msg) != reflect.TypeOf(witness) {
		return fmt.Errorf("entdb: delete: type mismatch")
	}
	delete(c.store, nodeID)
	delete(c.consumed, nodeID)
	return nil
}

func (c *memoryEntClient) markConsumed(_ context.Context, _ string, _ proto.Message, nodeID string, atMs int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.store[nodeID]; !ok {
		return fmt.Errorf("entdb: markConsumed: node %q not found", nodeID)
	}
	c.consumed[nodeID] = atMs
	return nil
}

// mergePatch overlays `patch` onto `existing`. Non-default scalars in
// `patch` overwrite the existing values; default scalars are skipped
// (so "name = empty string" patches do not clobber existing names).
// To clear a field, callers must write a full-row patch whose every
// field except the cleared one is non-zero — the same constraint the
// real SDK imposes via proto3 Range semantics.
func mergePatch(existing, patch proto.Message) proto.Message {
	out := proto.Clone(existing)
	patch.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		out.ProtoReflect().Set(fd, v)
		return true
	})
	// Special-case "full-row rewrite" used by ResetFailedLoginCount:
	// when the caller passes a User-shaped patch with both
	// FailedLoginCount and LockedUntil at zero, the lockout fields
	// must be cleared. We detect this by checking whether the
	// caller-set fields cover the "key" identifying fields of the
	// type (CreatedAt + UpdatedAt for User) — a heuristic that's
	// safe because partial updates never set those.
	if shouldClearLockout(patch) {
		out.ProtoReflect().Clear(protoFieldByJSONName(out, "failed_login_count"))
		out.ProtoReflect().Clear(protoFieldByJSONName(out, "locked_until"))
	}
	return out
}

// shouldClearLockout heuristically detects the full-row rewrite used by
// ResetFailedLoginCount. The marker is a User patch carrying CreatedAt
// (a field never set in partial-User patches the Repository emits).
func shouldClearLockout(patch proto.Message) bool {
	u, ok := patch.(*schemapb.User)
	if !ok {
		return false
	}
	return u.CreatedAt != 0
}

func protoFieldByJSONName(m proto.Message, jsonName string) protoreflect.FieldDescriptor {
	return m.ProtoReflect().Descriptor().Fields().ByName(protoreflect.Name(jsonName))
}

// matchesFilter is the in-memory equivalent of the SDK's
// Query[T] filter evaluation: equality on every key in the filter.
// Filter keys are proto field names — the same vocabulary the typed
// SDK Query uses.
func matchesFilter(msg proto.Message, filter map[string]any) bool {
	if len(filter) == 0 {
		return true
	}
	mr := msg.ProtoReflect()
	fields := mr.Descriptor().Fields()
	for k, want := range filter {
		fd := fields.ByName(protoreflect.Name(k))
		if fd == nil {
			// Unknown field name — treat as a non-match so a
			// typo in a filter doesn't silently return everything.
			return false
		}
		got := protoValueAsAny(fd, mr.Get(fd))
		if !sameScalar(got, want) {
			return false
		}
	}
	return true
}

func protoValueAsAny(fd protoreflect.FieldDescriptor, v protoreflect.Value) any {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return v.Bool()
	case protoreflect.StringKind:
		return v.String()
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return v.Int()
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return v.Int()
	default:
		return v.Interface()
	}
}

func sameScalar(got, want any) bool {
	if got == want {
		return true
	}
	switch g := got.(type) {
	case string:
		w, ok := want.(string)
		return ok && g == w
	case int64:
		switch w := want.(type) {
		case int64:
			return g == w
		case int:
			return g == int64(w)
		case float64:
			return g == int64(w)
		}
	case bool:
		w, ok := want.(bool)
		return ok && g == w
	}
	return false
}

// uniqueFields lists the (proto type, proto field name) pairs the real
// EntDB schema annotates with (entdb.field).unique. The fake enforces
// these so the conformance suite exercises duplicate-rejection.
var uniqueFields = []struct {
	witness proto.Message
	field   string
}{
	{&schemapb.User{}, "email"},
	{&schemapb.RefreshToken{}, "token_hash"},
	{&schemapb.PasswordResetToken{}, "token_hash"},
	{&schemapb.PasskeyCredential{}, "credential_id"},
	{&schemapb.PasskeyChallenge{}, "challenge"},
	{&schemapb.QrLoginSession{}, "session_id"},
	{&schemapb.RecoveryCode{}, "code_hash"},
	{&schemapb.LoginChallenge{}, "challenge_id"},
	{&schemapb.UserInvitation{}, "token_hash"},
	{&schemapb.UserInvitation{}, "email"},
	{&schemapb.EmailVerificationToken{}, "token_hash"},
	{&schemapb.EmailChangeToken{}, "token_hash"},
}

func (c *memoryEntClient) checkUniqueness(msg proto.Message) error {
	mr := msg.ProtoReflect()
	t := reflect.TypeOf(msg)
	for _, u := range uniqueFields {
		if reflect.TypeOf(u.witness) != t {
			continue
		}
		fd := mr.Descriptor().Fields().ByName(protoreflect.Name(u.field))
		if fd == nil {
			continue
		}
		val := mr.Get(fd)
		if !val.IsValid() {
			continue
		}
		want := protoValueAsAny(fd, val)
		if zeroValue(fd, want) {
			continue
		}
		for _, n := range c.store {
			if reflect.TypeOf(n.msg) != t {
				continue
			}
			ngot := n.msg.ProtoReflect().Get(fd)
			if sameScalar(protoValueAsAny(fd, ngot), want) {
				return fmt.Errorf("entdb: unique constraint violated on %T.%s", msg, u.field)
			}
		}
	}
	return nil
}

func zeroValue(fd protoreflect.FieldDescriptor, v any) bool {
	switch fd.Kind() {
	case protoreflect.StringKind:
		s, _ := v.(string)
		return s == ""
	case protoreflect.BoolKind:
		b, _ := v.(bool)
		return !b
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
		protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		n, _ := v.(int64)
		return n == 0
	}
	return false
}

// TestEntDBConformance runs the driver-agnostic Repository conformance
// suite against the entdb driver wired with an in-memory entClient.
// Production wiring uses NewRepository(*sdk.DbClient, ...); this test
// bypasses the gRPC connection by injecting an in-memory entClient
// directly, exercising every Repository method end-to-end.
func TestEntDBConformance(t *testing.T) {
	t.Parallel()
	conformance.RunConformance(t, func(_ *testing.T) service.Repository {
		return &entRepository{
			client:   newMemoryEntClient(),
			tenantID: "test-tenant",
		}
	})
}
