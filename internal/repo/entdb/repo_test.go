package entdb

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"

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
	idCounter int64
}

type storedNode struct {
	msg proto.Message
}

type duplicateUserEntClient struct {
	*memoryEntClient
}

func newMemoryEntClient() *memoryEntClient {
	return &memoryEntClient{
		store: make(map[string]storedNode),
	}
}

func newDuplicateUserEntClient() *duplicateUserEntClient {
	return &duplicateUserEntClient{memoryEntClient: newMemoryEntClient()}
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
			NodeID:  id,
			Message: copy,
		})
	}
	return out, nil
}

func (c *memoryEntClient) findByKey(_ context.Context, _ string, key sdk.UniqueKey[string], value string, dst proto.Message) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	wantType := reflect.TypeOf(dst)
	for id, n := range c.store {
		if reflect.TypeOf(n.msg) != wantType {
			continue
		}
		if !matchesFilter(n.msg, map[string]any{key.Name: value}) {
			continue
		}
		proto.Merge(dst, n.msg)
		return id, nil
	}
	return "", errNotFound
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

func (c *duplicateUserEntClient) create(_ context.Context, _ string, msg proto.Message) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
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
		return errors.New("entdb: update: type mismatch")
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
		return errors.New("entdb: delete: type mismatch")
	}
	delete(c.store, nodeID)
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

func TestCreateUser_DuplicateCreateDeletesLoser(t *testing.T) {
	t.Parallel()

	client := newDuplicateUserEntClient()
	repo := &entRepository{
		client:   client,
		tenantID: "test-tenant",
	}

	first := &service.User{Email: "dup@example.com", Status: "active"}
	firstID, err := repo.CreateUser(context.Background(), first)
	if err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}

	second := &service.User{Email: "dup@example.com", Status: "active"}
	if _, err := repo.CreateUser(context.Background(), second); err == nil {
		t.Fatal("second CreateUser: want duplicate cleanup error, got nil")
	}

	rows, err := client.query(context.Background(), systemActor, &schemapb.User{}, map[string]any{"email": "dup@example.com"})
	if err != nil {
		t.Fatalf("query dup@example.com: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows for dup@example.com = %d, want 1", len(rows))
	}
	if rows[0].NodeID != firstID {
		t.Fatalf("winner node id = %q, want %q", rows[0].NodeID, firstID)
	}
}

func TestEntRepositoryInputContracts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := &entRepository{
		client:   newMemoryEntClient(),
		tenantID: "test-tenant",
	}

	errorCases := []struct {
		name string
		run  func() error
	}{
		{"CreateUser_nil", func() error { _, err := repo.CreateUser(ctx, nil); return err }},
		{"UpdateUser_missing_id", func() error { return repo.UpdateUser(ctx, "", nil) }},
		{"SetUserEmailVerified_missing_id", func() error { return repo.SetUserEmailVerified(ctx, "", 1) }},
		{"IncrementFailedLoginCount_missing_id", func() error { _, err := repo.IncrementFailedLoginCount(ctx, ""); return err }},
		{"ResetFailedLoginCount_missing_id", func() error { return repo.ResetFailedLoginCount(ctx, "") }},
		{"SetUserLockedUntil_missing_id", func() error { return repo.SetUserLockedUntil(ctx, "", 1) }},
		{"CreateRefreshToken_nil", func() error { _, err := repo.CreateRefreshToken(ctx, nil); return err }},
		{"CreatePasskeyCredential_nil", func() error { _, err := repo.CreatePasskeyCredential(ctx, nil); return err }},
		{"UpdatePasskeyCredential_missing_id", func() error { return repo.UpdatePasskeyCredential(ctx, "", nil) }},
		{"CreatePasskeyChallenge_nil", func() error { _, err := repo.CreatePasskeyChallenge(ctx, nil); return err }},
		{"CreateQrLoginSession_nil", func() error { _, err := repo.CreateQrLoginSession(ctx, nil); return err }},
		{"UpdateQrLoginSession_missing_id", func() error { return repo.UpdateQrLoginSession(ctx, "", nil) }},
		{"CreateTotpCredential_nil", func() error { _, err := repo.CreateTotpCredential(ctx, nil); return err }},
		{"UpdateTotpCredential_missing_id", func() error { return repo.UpdateTotpCredential(ctx, "", nil) }},
		{"CreateRecoveryCode_nil", func() error { _, err := repo.CreateRecoveryCode(ctx, nil); return err }},
		{"UpdateRecoveryCode_missing_id", func() error { return repo.UpdateRecoveryCode(ctx, "", nil) }},
		{"CreateLoginChallenge_nil", func() error { _, err := repo.CreateLoginChallenge(ctx, nil); return err }},
		{"UpdateInvitation_missing_id", func() error { return repo.UpdateInvitation(ctx, "", nil) }},
		{"CreatePasswordResetToken_nil", func() error { return repo.CreatePasswordResetToken(ctx, nil) }},
		{"MarkPasswordResetTokenConsumed_missing_id", func() error { return repo.MarkPasswordResetTokenConsumed(ctx, "", 1) }},
		{"CreateEmailVerificationToken_nil", func() error { return repo.CreateEmailVerificationToken(ctx, nil) }},
		{"MarkEmailVerificationTokenConsumed_missing_id", func() error { return repo.MarkEmailVerificationTokenConsumed(ctx, "", 1) }},
		{"CreateEmailChangeToken_nil", func() error { return repo.CreateEmailChangeToken(ctx, nil) }},
		{"MarkEmailChangeTokenConsumed_missing_id", func() error { return repo.MarkEmailChangeTokenConsumed(ctx, "", 1) }},
		{"UpdateUserEmail_missing_id", func() error { return repo.UpdateUserEmail(ctx, "", "new@example.com", 1) }},
		{"CreateOAuthIdentity_nil", func() error { return repo.CreateOAuthIdentity(ctx, nil) }},
	}
	for _, tt := range errorCases {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}

	noResultCases := []struct {
		name string
		run  func() error
	}{
		{"FindUserByEmail_empty", func() error {
			got, err := repo.FindUserByEmail(ctx, "")
			return requireNilResult("FindUserByEmail", got, err)
		}},
		{"FindUserByEmail_missing", func() error {
			got, err := repo.FindUserByEmail(ctx, "missing@example.com")
			return requireNilResult("FindUserByEmail", got, err)
		}},
		{"GetUser_empty", func() error {
			got, err := repo.GetUser(ctx, "")
			return requireNilResult("GetUser", got, err)
		}},
		{"GetUser_missing", func() error {
			got, err := repo.GetUser(ctx, "missing-user")
			return requireNilResult("GetUser", got, err)
		}},
		{"DeleteRefreshToken_empty", func() error { return repo.DeleteRefreshToken(ctx, "") }},
		{"DeleteRefreshTokensForUser_empty", func() error { return repo.DeleteRefreshTokensForUser(ctx, "") }},
		{"ListPasskeyCredentials_empty", func() error {
			got, err := repo.ListPasskeyCredentials(ctx, "")
			if err != nil {
				return err
			}
			if len(got) != 0 {
				return fmt.Errorf("ListPasskeyCredentials returned %d rows", len(got))
			}
			return nil
		}},
		{"GetPasskeyCredentialByCredID_empty", func() error {
			got, err := repo.GetPasskeyCredentialByCredID(ctx, "")
			return requireNilResult("GetPasskeyCredentialByCredID", got, err)
		}},
		{"GetPasskeyCredentialByCredID_missing", func() error {
			got, err := repo.GetPasskeyCredentialByCredID(ctx, "missing-credential")
			return requireNilResult("GetPasskeyCredentialByCredID", got, err)
		}},
		{"GetPasskeyChallenge_empty", func() error {
			got, err := repo.GetPasskeyChallenge(ctx, "")
			return requireNilResult("GetPasskeyChallenge", got, err)
		}},
		{"GetPasskeyChallenge_missing", func() error {
			got, err := repo.GetPasskeyChallenge(ctx, "missing-challenge")
			return requireNilResult("GetPasskeyChallenge", got, err)
		}},
		{"DeletePasskeyChallenge_empty", func() error { return repo.DeletePasskeyChallenge(ctx, "") }},
		{"FindQrLoginSession_empty", func() error {
			got, err := repo.FindQrLoginSession(ctx, "")
			return requireNilResult("FindQrLoginSession", got, err)
		}},
		{"FindQrLoginSession_missing", func() error {
			got, err := repo.FindQrLoginSession(ctx, "missing-session")
			return requireNilResult("FindQrLoginSession", got, err)
		}},
		{"GetTotpCredential_empty", func() error {
			got, err := repo.GetTotpCredential(ctx, "")
			return requireNilResult("GetTotpCredential", got, err)
		}},
		{"DeleteTotpCredential_empty", func() error { return repo.DeleteTotpCredential(ctx, "") }},
		{"DeleteTotpCredentialsForUser_empty", func() error { return repo.DeleteTotpCredentialsForUser(ctx, "") }},
		{"FindRecoveryCodeByHash_empty_user", func() error {
			got, err := repo.FindRecoveryCodeByHash(ctx, "", "hash")
			return requireNilResult("FindRecoveryCodeByHash", got, err)
		}},
		{"FindRecoveryCodeByHash_empty_hash", func() error {
			got, err := repo.FindRecoveryCodeByHash(ctx, "user", "")
			return requireNilResult("FindRecoveryCodeByHash", got, err)
		}},
		{"DeleteRecoveryCodesForUser_empty", func() error { return repo.DeleteRecoveryCodesForUser(ctx, "") }},
		{"GetLoginChallengeByChallengeID_empty", func() error {
			got, err := repo.GetLoginChallengeByChallengeID(ctx, "")
			return requireNilResult("GetLoginChallengeByChallengeID", got, err)
		}},
		{"GetLoginChallengeByChallengeID_missing", func() error {
			got, err := repo.GetLoginChallengeByChallengeID(ctx, "missing-challenge")
			return requireNilResult("GetLoginChallengeByChallengeID", got, err)
		}},
		{"DeleteLoginChallenge_empty", func() error { return repo.DeleteLoginChallenge(ctx, "") }},
		{"FindInvitationByHash_empty", func() error {
			got, err := repo.FindInvitationByHash(ctx, "")
			return requireNilResult("FindInvitationByHash", got, err)
		}},
		{"FindInvitationByHash_missing", func() error {
			got, err := repo.FindInvitationByHash(ctx, "missing-token")
			return requireNilResult("FindInvitationByHash", got, err)
		}},
		{"FindPasswordResetTokenByHash_empty", func() error {
			got, err := repo.FindPasswordResetTokenByHash(ctx, "")
			return requireNilResult("FindPasswordResetTokenByHash", got, err)
		}},
		{"FindPasswordResetTokenByHash_missing", func() error {
			got, err := repo.FindPasswordResetTokenByHash(ctx, "missing-token")
			return requireNilResult("FindPasswordResetTokenByHash", got, err)
		}},
		{"FindEmailVerificationTokenByHash_empty", func() error {
			got, err := repo.FindEmailVerificationTokenByHash(ctx, "")
			return requireNilResult("FindEmailVerificationTokenByHash", got, err)
		}},
		{"FindEmailVerificationTokenByHash_missing", func() error {
			got, err := repo.FindEmailVerificationTokenByHash(ctx, "missing-token")
			return requireNilResult("FindEmailVerificationTokenByHash", got, err)
		}},
		{"FindEmailChangeTokenByHash_empty", func() error {
			got, err := repo.FindEmailChangeTokenByHash(ctx, "")
			return requireNilResult("FindEmailChangeTokenByHash", got, err)
		}},
		{"FindEmailChangeTokenByHash_missing", func() error {
			got, err := repo.FindEmailChangeTokenByHash(ctx, "missing-token")
			return requireNilResult("FindEmailChangeTokenByHash", got, err)
		}},
		{"FindUserByProviderID_empty_provider", func() error {
			got, err := repo.FindUserByProviderID(ctx, "", "provider-user")
			return requireNilResult("FindUserByProviderID", got, err)
		}},
		{"FindUserByProviderID_empty_provider_user", func() error {
			got, err := repo.FindUserByProviderID(ctx, "google", "")
			return requireNilResult("FindUserByProviderID", got, err)
		}},
		{"ListOAuthIdentitiesForUser_empty", func() error {
			got, err := repo.ListOAuthIdentitiesForUser(ctx, "")
			if err != nil {
				return err
			}
			if len(got) != 0 {
				return fmt.Errorf("ListOAuthIdentitiesForUser returned %d rows", len(got))
			}
			return nil
		}},
	}
	for _, tt := range noResultCases {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); err != nil {
				t.Fatal(err)
			}
		})
	}

	noOpUpdates := []struct {
		name string
		run  func() error
	}{
		{"UpdateUser_unknown_field", func() error { return repo.UpdateUser(ctx, "missing-user", map[string]any{"unknown": true}) }},
		{"UpdatePasskeyCredential_unknown_field", func() error {
			return repo.UpdatePasskeyCredential(ctx, "missing-passkey", map[string]any{"unknown": true})
		}},
		{"UpdateQrLoginSession_unknown_field", func() error {
			return repo.UpdateQrLoginSession(ctx, "missing-session", map[string]any{"unknown": true})
		}},
		{"UpdateTotpCredential_unknown_field", func() error {
			return repo.UpdateTotpCredential(ctx, "missing-totp", map[string]any{"unknown": true})
		}},
		{"UpdateRecoveryCode_unknown_field", func() error {
			return repo.UpdateRecoveryCode(ctx, "missing-code", map[string]any{"unknown": true})
		}},
		{"UpdateInvitation_unknown_field", func() error {
			return repo.UpdateInvitation(ctx, "missing-invitation", map[string]any{"unknown": true})
		}},
	}
	for _, tt := range noOpUpdates {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func requireNilResult[T any](name string, got *T, err error) error {
	if err != nil {
		return err
	}
	if got != nil {
		return fmt.Errorf("%s returned non-nil result", name)
	}
	return nil
}

func TestEntRepositoryProtoConvertersHandleNil(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		ok   bool
	}{
		{"user", userFromProto("node", nil) == nil},
		{"refresh", refreshTokenFromProto("node", nil) == nil},
		{"passkey", passkeyCredFromProto("node", nil) == nil},
		{"passkey_challenge", passkeyChallengeFromProto("node", nil) == nil},
		{"qr_session", qrSessionFromProto("node", nil) == nil},
		{"totp", totpCredFromProto("node", nil) == nil},
		{"recovery_code", recoveryCodeFromProto("node", nil) == nil},
		{"login_challenge", loginChallengeFromProto("node", nil) == nil},
		{"invitation", invitationFromProto("node", nil) == nil},
		{"password_reset", passwordResetFromProto("node", nil) == nil},
		{"email_verification", emailVerificationFromProto("node", nil) == nil},
		{"email_change", emailChangeFromProto("node", nil) == nil},
		{"oauth_identity", oauthIdentityFromProto("node", nil) == nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.ok {
				t.Fatal("converter returned non-nil result")
			}
		})
	}
}

func TestEntRepositoryUserPatchHelpers(t *testing.T) {
	t.Parallel()

	if actorStr("") != systemActor {
		t.Fatalf("actorStr empty = %q, want %q", actorStr(""), systemActor)
	}
	if actorStr("u-1") != "user:u-1" {
		t.Fatalf("actorStr user = %q", actorStr("u-1"))
	}

	if got := userProtoFromUser(nil); got == nil {
		t.Fatal("userProtoFromUser(nil) returned nil proto")
	}

	fields := map[string]any{
		"email":              "new@example.com",
		"name":               "New Name",
		"role":               "admin",
		"avatar_url":         "https://example.com/a.png",
		"password_hash":      "hash",
		"totp_required":      true,
		"failed_login_count": int32(3),
		"locked_until":       int(4),
		"status":             "active",
		"recovery_email":     "recover@example.com",
		"quota_bytes":        int64(5),
		"last_login_at":      float64(6),
		"updated_at":         int64(7),
		"email_verified":     true,
		"email_verified_at":  int64(8),
	}
	patch := &schemapb.User{}
	if !applyUserFields(patch, fields) {
		t.Fatal("applyUserFields returned false")
	}
	if patch.Email != "new@example.com" || patch.Name != "New Name" || patch.Role != "admin" ||
		patch.AvatarUrl != "https://example.com/a.png" || patch.PasswordHash != "hash" ||
		!patch.TotpRequired || patch.FailedLoginCount != 3 || patch.LockedUntil != 4 ||
		patch.Status != "active" || patch.RecoveryEmail != "recover@example.com" ||
		patch.QuotaBytes != 5 || patch.LastLoginAt != 6 || patch.UpdatedAt != 7 ||
		!patch.EmailVerified || patch.EmailVerifiedAt != 8 {
		t.Fatalf("applyUserFields patch = %#v", patch)
	}
	if applyUserFields(&schemapb.User{}, map[string]any{"unknown": true}) {
		t.Fatal("applyUserFields unknown field returned true")
	}

	wantRawPatch := map[string]any{
		"1":  "new@example.com",
		"2":  "New Name",
		"3":  "admin",
		"4":  "https://example.com/a.png",
		"6":  int64(7),
		"7":  "hash",
		"8":  true,
		"9":  int64(3),
		"10": int64(4),
		"11": "active",
		"12": "recover@example.com",
		"15": int64(5),
		"17": int64(6),
		"18": true,
		"19": int64(8),
	}
	if got := userFieldPatch(fields); !reflect.DeepEqual(got, wantRawPatch) {
		t.Fatalf("userFieldPatch = %#v, want %#v", got, wantRawPatch)
	}

	if needsFullUserRewrite(map[string]any{"email": "new@example.com", "totp_required": true, "quota_bytes": int64(1)}) {
		t.Fatal("needsFullUserRewrite returned true for non-zero fields")
	}
	zeroFields := []map[string]any{
		{"email": ""},
		{"totp_required": false},
		{"failed_login_count": int(0)},
		{"failed_login_count": int32(0)},
		{"failed_login_count": int64(0)},
	}
	for _, fields := range zeroFields {
		if !needsFullUserRewrite(fields) {
			t.Fatalf("needsFullUserRewrite(%#v) returned false", fields)
		}
	}

	if asString(3) != "" || asBool("true") || asInt64("7") != 0 {
		t.Fatal("conversion helpers did not default invalid inputs")
	}
}

func TestEntRepositoryUserOrderingAndCleanup(t *testing.T) {
	t.Parallel()

	rows := []queriedNode{
		{NodeID: "b", Message: &schemapb.User{CreatedAt: 20}},
		{NodeID: "c", Message: &schemapb.User{CreatedAt: 10}},
		{NodeID: "a", Message: &schemapb.User{CreatedAt: 10}},
	}
	if got := canonicalUserNodeID(nil); got != "" {
		t.Fatalf("canonicalUserNodeID(nil) = %q, want empty", got)
	}
	if got := canonicalUserNodeID(rows); got != "a" {
		t.Fatalf("canonicalUserNodeID = %q, want a", got)
	}
	if got := compareUserRows(rows[0], rows[1]); got <= 0 {
		t.Fatalf("compare newer vs older = %d, want positive", got)
	}
	if got := compareUserRows(rows[2], rows[1]); got >= 0 {
		t.Fatalf("compare lower node id = %d, want negative", got)
	}
	if got := compareUserRows(rows[1], rows[1]); got != 0 {
		t.Fatalf("compare same row = %d, want zero", got)
	}

	client := newMemoryEntClient()
	repo := &entRepository{client: client, tenantID: "test-tenant"}
	client.store["keep"] = storedNode{msg: &schemapb.User{Email: "dup@example.com"}}
	client.store["drop"] = storedNode{msg: &schemapb.User{Email: "dup@example.com"}}
	err := repo.deleteOtherUsers(context.Background(), []queriedNode{
		{NodeID: "keep", Message: &schemapb.User{}},
		{NodeID: "drop", Message: &schemapb.User{}},
	}, "keep")
	if err != nil {
		t.Fatalf("deleteOtherUsers: %v", err)
	}
	if got, err := repo.GetUser(context.Background(), "keep"); err != nil || got == nil {
		t.Fatalf("GetUser keep = %#v, %v", got, err)
	}
	if got, err := repo.GetUser(context.Background(), "drop"); err != nil || got != nil {
		t.Fatalf("GetUser drop = %#v, %v", got, err)
	}
}

func TestEntDBClientHelpers(t *testing.T) {
	t.Parallel()

	rawCases := []struct {
		name     string
		witness  proto.Message
		filter   map[string]any
		wantType int
		want     map[string]any
		wantOK   bool
	}{
		{"user_email", &schemapb.User{}, map[string]any{"email": "a@example.com"}, 1, map[string]any{"1": "a@example.com"}, true},
		{"refresh_user", &schemapb.RefreshToken{}, map[string]any{"user_id": "u"}, 5, map[string]any{"2": "u"}, true},
		{"passkey_user", &schemapb.PasskeyCredential{}, map[string]any{"user_id": "u"}, 20, map[string]any{"2": "u"}, true},
		{"totp_user", &schemapb.TotpCredential{}, map[string]any{"user_id": "u"}, 23, map[string]any{"1": "u"}, true},
		{"recovery_code", &schemapb.RecoveryCode{}, map[string]any{"user_id": "u", "code_hash": "h"}, 24, map[string]any{"1": "u", "2": "h"}, true},
		{"oauth_identity", &schemapb.OAuthIdentity{}, map[string]any{"user_id": "u", "provider": "google", "provider_user_id": "sub"}, 31, map[string]any{"1": "u", "2": "google", "3": "sub"}, true},
		{"unsupported_filter", &schemapb.User{}, map[string]any{"name": "n"}, 0, nil, false},
		{"unsupported_witness", &schemapb.EmailChangeToken{}, map[string]any{"token_hash": "h"}, 0, nil, false},
	}
	for _, tt := range rawCases {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotFilter, gotOK := rawQuerySpec(tt.witness, tt.filter)
			if gotOK != tt.wantOK || gotType != tt.wantType || !reflect.DeepEqual(gotFilter, tt.want) {
				t.Fatalf("rawQuerySpec = (%d, %#v, %v), want (%d, %#v, %v)", gotType, gotFilter, gotOK, tt.wantType, tt.want, tt.wantOK)
			}
		})
	}

	commitCases := []struct {
		name    string
		res     *sdk.CommitResult
		want    string
		wantErr bool
	}{
		{"nil", nil, "", true},
		{"unsuccessful_error", &sdk.CommitResult{Success: false, Error: "boom"}, "", true},
		{"unsuccessful_empty_error", &sdk.CommitResult{Success: false}, "", true},
		{"no_created_ids", &sdk.CommitResult{Success: true}, "", true},
		{"success", &sdk.CommitResult{Success: true, CreatedNodeIDs: []string{"node-1"}}, "node-1", false},
	}
	for _, tt := range commitCases {
		t.Run("firstCreatedID_"+tt.name, func(t *testing.T) {
			got, err := firstCreatedID(tt.res)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("firstCreatedID = %q, %v; want %q, nil", got, err, tt.want)
			}
		})
	}

	want := (&schemapb.User{Email: "a@example.com", FailedLoginCount: 3}).ProtoReflect()
	if !patchApplied(want, (&schemapb.User{Email: "a@example.com", FailedLoginCount: 3}).ProtoReflect()) {
		t.Fatal("patchApplied returned false for matching patch")
	}
	if patchApplied(want, (&schemapb.User{Email: "a@example.com"}).ProtoReflect()) {
		t.Fatal("patchApplied returned true for missing field")
	}
	if patchApplied(want, (&schemapb.User{Email: "other@example.com", FailedLoginCount: 3}).ProtoReflect()) {
		t.Fatal("patchApplied returned true for mismatched field")
	}

	if got := newMessageLike(&schemapb.User{}); reflect.TypeOf(got) != reflect.TypeOf(&schemapb.User{}) {
		t.Fatalf("newMessageLike type = %T", got)
	}
	if isNonNilMessage(nil) {
		t.Fatal("isNonNilMessage(nil) returned true")
	}
	var typedNil *schemapb.User
	if isNonNilMessage(typedNil) {
		t.Fatal("isNonNilMessage(typed nil) returned true")
	}
	if !isNonNilMessage(&schemapb.User{}) {
		t.Fatal("isNonNilMessage(valid message) returned false")
	}
}

func TestSDKScopeVisibilityWaitsStopOnContextCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scope := &sdkScope{}
	start := time.Now()

	cases := []struct {
		name string
		run  func() error
	}{
		{
			name: "node_visible",
			run: func() error {
				return scope.waitForNodeVisible(ctx, "invalid actor", &schemapb.User{}, "missing")
			},
		},
		{
			name: "patch_visible",
			run: func() error {
				return scope.waitForPatchVisible(ctx, "invalid actor", "missing", &schemapb.User{Email: "a@example.com"})
			},
		},
		{
			name: "node_deleted",
			run: func() error {
				return scope.waitForNodeDeleted(ctx, "invalid actor", &schemapb.User{}, "missing")
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, context.Canceled) {
				t.Fatalf("wait error = %v, want context.Canceled", err)
			}
		})
	}
	if elapsed := time.Since(start); elapsed >= 500*time.Millisecond {
		t.Fatalf("canceled waits took %s, want immediate return", elapsed)
	}
}
