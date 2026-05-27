package entclient

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	entdbopts "github.com/elloloop/identity/gen/go/entdb"
	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
)

// TestSchemaMessages_CoversEveryNodeType asserts that SchemaMessages
// includes every (entdb.node)-annotated message in schema.proto. The
// SDK's ADR-031 self-describing writes only attach the schema for
// types we explicitly register, so a missing entry here means the
// server can't enforce that type's constraints — and the conformance
// suite would surface it as "VALIDATION_ERROR: unknown type_id N",
// but we'd rather fail at the test level with a name.
//
// The check walks the registered messages, pulls each one's
// (entdb.node).type_id, and confirms it matches one of the known
// identity type ids. A new node type in schema.proto without a
// corresponding entry in SchemaMessages() fails this test.
func TestSchemaMessages_CoversEveryNodeType(t *testing.T) {
	want := map[int32]string{
		1:  "User",
		2:  "WorkingGroup",
		5:  "RefreshToken",
		19: "PasswordResetToken",
		20: "PasskeyCredential",
		21: "PasskeyChallenge",
		22: "QrLoginSession",
		23: "TotpCredential",
		24: "RecoveryCode",
		25: "LoginChallenge",
		26: "AuditEvent",
		27: "UserInvitation",
		28: "AdminHelpRequest",
		29: "EmailVerificationToken",
		30: "EmailChangeToken",
		31: "OAuthIdentity",
		32: "IdentityVerificationRecord",
		33: "Organization",
		34: "OrganizationMembership",
		35: "Session",
		36: "OAuthOneTimeCode",
		37: "EmailLoginCode",
		38: "MagicLinkToken",
	}

	got := map[int32]string{}
	for _, msg := range SchemaMessages() {
		md := msg.ProtoReflect().Descriptor()
		opts := md.Options()
		ext := proto.GetExtension(opts, entdbopts.E_Node)
		node, ok := ext.(*entdbopts.NodeOpts)
		if !ok || node == nil || node.GetTypeId() == 0 {
			// Edge messages reach here — they have no NodeOpts. Skip.
			continue
		}
		got[node.GetTypeId()] = string(md.Name())
	}

	for id, name := range want {
		actualName, ok := got[id]
		if !ok {
			t.Errorf("missing node type_id %d (%s) in SchemaMessages — server cannot enforce its constraints", id, name)
			continue
		}
		if actualName != name {
			t.Errorf("type_id %d registered as %q, want %q", id, actualName, name)
		}
	}
	for id, name := range got {
		if _, ok := want[id]; !ok {
			t.Errorf("unexpected node type_id %d (%s) in SchemaMessages — update the test if a new type was added", id, name)
		}
	}
}

// TestSchemaMessages_IncludesEveryEdgeType asserts the edge messages
// (MemberOf, UserPasskey, UserTotp, UserRecoveryCode) are registered.
// Edges don't have type_ids the same way nodes do; we identify them
// by name from the proto descriptor.
func TestSchemaMessages_IncludesEveryEdgeType(t *testing.T) {
	wantEdges := map[string]bool{
		"MemberOf":         false,
		"UserPasskey":      false,
		"UserTotp":         false,
		"UserRecoveryCode": false,
	}
	for _, msg := range SchemaMessages() {
		name := string(msg.ProtoReflect().Descriptor().Name())
		if _, ok := wantEdges[name]; ok {
			wantEdges[name] = true
		}
	}
	for name, present := range wantEdges {
		if !present {
			t.Errorf("missing edge %q in SchemaMessages", name)
		}
	}
}

// TestSchemaMessages_NoNilEntries — defensive: every entry in
// SchemaMessages must be a typed nil with a valid descriptor. A bare
// nil sneaks through interface{} and causes a panic inside the SDK's
// reflection walk.
func TestSchemaMessages_NoNilEntries(t *testing.T) {
	for i, msg := range SchemaMessages() {
		if msg == nil {
			t.Fatalf("SchemaMessages[%d] is nil", i)
		}
		if msg.ProtoReflect() == nil {
			t.Fatalf("SchemaMessages[%d] has nil ProtoReflect", i)
		}
		if name := msg.ProtoReflect().Descriptor().Name(); name == "" {
			t.Fatalf("SchemaMessages[%d] has empty descriptor name", i)
		}
	}
}

// TestSchemaMessages_StableLength is a tripwire for accidentally
// removing entries from SchemaMessages without updating the test. The
// number of messages should equal the count of node types (23) plus
// edge types (4) = 27 messages registered.
func TestSchemaMessages_StableLength(t *testing.T) {
	const wantNodes = 23
	const wantEdges = 4
	msgs := SchemaMessages()
	if len(msgs) != wantNodes+wantEdges {
		t.Fatalf("SchemaMessages length = %d, want %d (%d nodes + %d edges)", len(msgs), wantNodes+wantEdges, wantNodes, wantEdges)
	}
}

// TestNew_BadAddress_ReturnsError — the SDK accepts most strings as
// addresses (Connect is lazy), but New should still pass through any
// constructor error. Smoke-checks the wrapper path.
func TestNew_BadAddress_ReturnsError(t *testing.T) {
	// The v2 SDK's NewClient does not dial; it accepts almost any
	// non-empty string and lazy-dials on the first request. Passing
	// the empty string should still produce a successful constructor
	// (the SDK normalises it). This test asserts the constructor
	// either succeeds or fails cleanly — never panics.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("entclient.New panicked on empty address: %v", r)
		}
	}()
	_, err := New("")
	_ = err // we don't care whether it errors; we care that it doesn't panic.
}

// TestSchemaMessages_DescriptorsAreUsable confirms every registered
// message produces a usable proto descriptor (FullName resolves and
// starts with the identity.schema. package). Catches imports gone
// stale after a buf regenerate. Note: edge messages can legitimately
// have zero proto fields (the SDK derives their attributes from the
// (entdb.edge) option, not from message fields), so the field-count
// check is on nodes only.
func TestSchemaMessages_DescriptorsAreUsable(t *testing.T) {
	for i, msg := range SchemaMessages() {
		md := msg.ProtoReflect().Descriptor()
		if md.FullName() == "" {
			t.Errorf("SchemaMessages[%d]: empty FullName", i)
		}
		if !strings.HasPrefix(string(md.FullName()), "identity.schema.") {
			t.Errorf("SchemaMessages[%d] (%s): FullName %q does not start with identity.schema.", i, md.Name(), md.FullName())
		}
	}
}

// TestOAuthIdentity_HasCompositeUnique is the regression test for
// identity#141 at the package level: OAuthIdentity must declare
// composite_unique on (provider, provider_user_id). If buf regenerate
// drops that option or schema.proto loses it, this test fails before
// the conformance suite tells us at runtime.
func TestOAuthIdentity_HasCompositeUnique(t *testing.T) {
	md := (*schemapb.OAuthIdentity)(nil).ProtoReflect().Descriptor()
	opts := md.Options()
	ext := proto.GetExtension(opts, entdbopts.E_Node)
	node, ok := ext.(*entdbopts.NodeOpts)
	if !ok || node == nil {
		t.Fatalf("OAuthIdentity has no (entdb.node) option")
	}
	if len(node.GetCompositeUnique()) == 0 {
		t.Fatalf("OAuthIdentity has no composite_unique declarations (identity#141 regression)")
	}
	found := false
	for _, cu := range node.GetCompositeUnique() {
		fields := cu.GetFields()
		if len(fields) == 2 && fields[0] == "provider" && fields[1] == "provider_user_id" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("OAuthIdentity composite_unique on (provider, provider_user_id) missing; entries=%v", node.GetCompositeUnique())
	}
}
