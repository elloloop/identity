// Package entclient is identity's blessed wrapper around the
// tenant-shard-db Go SDK constructor. It pre-registers every
// (entdb.node)/(entdb.edge)-annotated message in identity's
// proto/identity/schema/schema.proto, so that the SDK's self-describing
// writes (ADR-031) carry the schema descriptor — including
// composite_unique constraints — to the entdb server. The server then
// materialises the schema in the same WAL event as the first data ops
// and enforces uniqueness/type/index rules atomically.
//
// Production code (cmd/identity/main.go), conformance tests, and
// integration tests all go through this constructor so the schema is
// attached consistently. Embedders wiring their own *sdk.DbClient can
// pass the same list to sdk.WithSchema(...) via [SchemaMessages].
package entclient

import (
	"google.golang.org/protobuf/proto"

	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb/v2"
)

// New constructs an SDK client connected to addr, with identity's
// schema attached. Additional ClientOptions are appended after the
// WithSchema so callers can override timeouts, transports, etc.
func New(addr string, opts ...sdk.ClientOption) (*sdk.DbClient, error) {
	base := []sdk.ClientOption{sdk.WithSchema(SchemaMessages()...)}
	return sdk.NewClient(addr, append(base, opts...)...)
}

// SchemaMessages returns one zero-valued instance of every identity
// node and edge type declared in schema.proto. The list mirrors the
// (entdb.node)/(entdb.edge) options block-by-block so a missing entry
// shows up as a build break the next time a message is added (the
// generated package won't have the type) rather than as a silent
// "constraint not enforced" runtime regression.
func SchemaMessages() []proto.Message {
	return []proto.Message{
		// Nodes (sorted by type_id for review-ability).
		(*schemapb.User)(nil),                       // 1
		(*schemapb.WorkingGroup)(nil),               // 2
		(*schemapb.RefreshToken)(nil),               // 5
		(*schemapb.PasswordResetToken)(nil),         // 19
		(*schemapb.PasskeyCredential)(nil),          // 20
		(*schemapb.PasskeyChallenge)(nil),           // 21
		(*schemapb.QrLoginSession)(nil),             // 22
		(*schemapb.TotpCredential)(nil),             // 23
		(*schemapb.RecoveryCode)(nil),               // 24
		(*schemapb.LoginChallenge)(nil),             // 25
		(*schemapb.AuditEvent)(nil),                 // 26
		(*schemapb.UserInvitation)(nil),             // 27
		(*schemapb.AdminHelpRequest)(nil),           // 28
		(*schemapb.EmailVerificationToken)(nil),     // 29
		(*schemapb.EmailChangeToken)(nil),           // 30
		(*schemapb.OAuthIdentity)(nil),              // 31 (composite_unique on provider+provider_user_id)
		(*schemapb.IdentityVerificationRecord)(nil), // 32
		(*schemapb.Organization)(nil),               // 33
		(*schemapb.OrganizationMembership)(nil),     // 34
		(*schemapb.Session)(nil),                    // 35
		(*schemapb.OAuthOneTimeCode)(nil),           // 36
		(*schemapb.EmailLoginCode)(nil),             // 37
		(*schemapb.MagicLinkToken)(nil),             // 38

		// Edges.
		(*schemapb.MemberOf)(nil),
		(*schemapb.UserPasskey)(nil),
		(*schemapb.UserTotp)(nil),
		(*schemapb.UserRecoveryCode)(nil),
	}
}
