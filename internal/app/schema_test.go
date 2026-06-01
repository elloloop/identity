package app

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	entdbopts "github.com/elloloop/identity/gen/go/entdb"
	identityschema "github.com/elloloop/identity/gen/go/identity/schema"
)

// expectedNodeTypes is the closed set of EntDB node types identity
// claims to own. If you add or remove a type from
// proto/identity/schema/schema.proto you MUST update this map (and
// the on-disk type IDs in internal/repo/entdb_fields.go and
// internal/service/entdb.go).
var expectedNodeTypes = map[string]int32{
	"User":                       1,
	"WorkingGroup":               2,
	"RefreshToken":               5,
	"PasswordResetToken":         19,
	"PasskeyCredential":          20,
	"PasskeyChallenge":           21,
	"QrLoginSession":             22,
	"TotpCredential":             23,
	"RecoveryCode":               24,
	"LoginChallenge":             25,
	"AuditEvent":                 26,
	"UserInvitation":             27,
	"AdminHelpRequest":           28,
	"EmailVerificationToken":     29,
	"EmailChangeToken":           30,
	"OAuthIdentity":              31,
	"IdentityVerificationRecord": 32,
	"Organization":               33,
	"OrganizationMembership":     34,
	"Session":                    35,
	"OAuthOneTimeCode":           36,
	"EmailLoginCode":             37,
	"MagicLinkToken":             38,
	"PhoneVerificationCode":      39,
}

func TestApplyOrLogSchemaGap_ReturnsNilWithLogger(t *testing.T) {
	t.Parallel()

	core, _ := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	err := applyOrLogSchemaGap(context.Background(), nil, logger)
	require.NoError(t, err)
}

func TestApplyOrLogSchemaGap_NilLoggerIsSafe(t *testing.T) {
	t.Parallel()
	require.NoError(t, applyOrLogSchemaGap(context.Background(), nil, nil))
}

func TestApplyOrLogSchemaGap_LogsEveryDeclaredNodeType(t *testing.T) {
	t.Parallel()

	core, recorded := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	require.NoError(t, applyOrLogSchemaGap(context.Background(), nil, logger))

	// Collect type_ids and names from schema_loaded events.
	declared := make(map[string]int32)
	for _, e := range recorded.FilterMessage("schema_loaded").All() {
		fields := e.ContextMap()
		name, _ := fields["name"].(string)
		switch v := fields["type_id"].(type) {
		case int32:
			declared[name] = v
		case int64:
			require.LessOrEqual(t, v, int64(math.MaxInt32))
			require.GreaterOrEqual(t, v, int64(math.MinInt32))
			declared[name] = int32(v) // #nosec G115 -- bounds checked above.
		}
	}

	require.Equal(t, expectedNodeTypes, declared,
		"identity schema declared types diverged from expected set; update either schema.proto or the test")
}

// The previous "schema_registration_pending_upstream_api" warning
// has been removed: EntDB's schema is client-side, so there is no
// server-side registration to wait for. The schema_loaded info entries
// covered by TestApplyOrLogSchemaGap_LogsEveryDeclaredNodeType are the
// canonical observability signal now. A test that the warning is
// ABSENT keeps regressions visible if anyone re-introduces it.
func TestApplyOrLogSchemaGap_NoPendingWarning(t *testing.T) {
	t.Parallel()

	core, recorded := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	require.NoError(t, applyOrLogSchemaGap(context.Background(), nil, logger))

	hits := recorded.FilterMessage("schema_registration_pending_upstream_api").All()
	require.Len(t, hits, 0, "the wrong upstream-gap warning was re-introduced")
}

// Identity binaries should never ship with a schema descriptor that
// has node-type-named messages but lacks the (entdb.node) annotation.
// We assert this by walking the FileDescriptor and verifying every
// expected type is in fact declared as a node.
func TestSchemaDescriptor_AllExpectedTypesAreDeclared(t *testing.T) {
	t.Parallel()

	fd := (&identityschema.User{}).ProtoReflect().Descriptor().ParentFile()
	declared, err := collectDeclaredNodeTypes(fd)
	require.NoError(t, err)

	got := make(map[string]int32, len(declared))
	for _, d := range declared {
		got[d.Name] = d.TypeID
	}
	for name, want := range expectedNodeTypes {
		require.Contains(t, got, name, "expected node type %s missing from schema descriptor", name)
		require.Equal(t, want, got[name], "type_id mismatch for %s", name)
	}
}

// collectDeclaredNodeTypes must reject schemas where a (entdb.node)
// option is missing on a message that should have one. We synthesise
// a malformed FileDescriptor to exercise that path (mutating the real
// schema would be out of scope for an in-process test).
func TestCollectDeclaredNodeTypes_ErrorsOnDuplicateTypeID(t *testing.T) {
	t.Parallel()

	fd := buildSyntheticFileDescriptorWithDuplicateTypeID(t)
	_, err := collectDeclaredNodeTypes(fd)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrSchemaMalformed))
}

// buildSyntheticFileDescriptorWithDuplicateTypeID assembles a minimal
// file descriptor with two messages annotated with the same
// (entdb.node).type_id, used to verify collectDeclaredNodeTypes
// flags duplicates.
func buildSyntheticFileDescriptorWithDuplicateTypeID(t *testing.T) protoreflect.FileDescriptor {
	t.Helper()

	mkMsg := func(name string, typeID int32) *descriptorpb.DescriptorProto {
		opts := &descriptorpb.MessageOptions{}
		proto.SetExtension(opts, entdbopts.E_Node, &entdbopts.NodeOpts{TypeId: typeID})
		return &descriptorpb.DescriptorProto{
			Name:    proto.String(name),
			Options: opts,
		}
	}

	fdProto := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("synthetic_dup.proto"),
		Package: proto.String("synthetic"),
		Syntax:  proto.String("proto3"),
		Dependency: []string{
			"entdb/entdb_options.proto",
		},
		MessageType: []*descriptorpb.DescriptorProto{
			mkMsg("A", 99),
			mkMsg("B", 99),
		},
	}

	files, err := protoFilesWithEntdb()
	require.NoError(t, err)

	fd, err := registerFileDescriptor(files, fdProto)
	require.NoError(t, err)
	return fd
}

// protoFilesWithEntdb returns a *protoregistry.Files seeded with the
// entdb options descriptor so synthetic schemas can depend on
// entdb/entdb_options.proto.
func protoFilesWithEntdb() (*protoregistry.Files, error) {
	files := new(protoregistry.Files)
	if err := files.RegisterFile(entdbopts.File_entdb_entdb_options_proto); err != nil {
		return nil, err
	}
	return files, nil
}

func registerFileDescriptor(files *protoregistry.Files, fdProto *descriptorpb.FileDescriptorProto) (protoreflect.FileDescriptor, error) {
	return protodesc.NewFile(fdProto, files)
}
