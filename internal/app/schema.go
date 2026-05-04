// Schema-apply (gap visibility).
//
// The identity service declares its EntDB node and edge types in
// proto/identity/schema/schema.proto using the upstream
// (entdb.node) / (entdb.edge) options. Eventually we want to push
// that descriptor to the EntDB server at startup so the server can
// enforce indexed/unique field constraints, retention, etc.
//
// Reality (today): the upstream EntDB SDK does NOT expose a
// RegisterSchema/ApplySchema method on *DbClient — see
// /Users/arun/projects/opensource/tenant-shard-db-go/sdk/go/entdb/.
// The server reads SCHEMA_FILE (yaml) at boot, but its
// internal/schema/registry.go::LoadDescriptor is a stub. So neither
// the SDK nor the server has a real schema-apply path yet.
//
// This file therefore makes the gap LOUD at startup by:
//
//  1. Loading the embedded FileDescriptor for identity's schema.
//  2. Iterating every message that has an (entdb.node) option.
//  3. Logging each one as schema_type_declared (so operators can see
//     the contract identity expects from the database).
//  4. Logging a single warning summarising the upstream gap.
//
// When the SDK eventually ships RegisterSchema (or whatever the
// final API ends up being), flip applyOrLogSchemaGap from "log
// gap" to "actually register" — the call site is marked with TODO
// below.
package app

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	entdbopts "github.com/elloloop/identity/gen/go/entdb"
	identityschema "github.com/elloloop/identity/gen/go/identity/schema"
	"github.com/elloloop/identity/internal/service"
)

// ErrSchemaMalformed indicates the embedded identity schema descriptor
// is missing required (entdb.node) annotations on messages we declared
// as node types. We treat this as an internal invariant violation —
// identity binaries should never ship with a schema that fails this
// check.
var ErrSchemaMalformed = errors.New("identity schema descriptor is malformed")

// applyOrLogSchemaGap inspects the embedded identity schema
// descriptor and emits one structured log line per declared node type,
// followed by a single summary warning describing the upstream
// schema-apply gap.
//
// db is currently unused — it is part of the signature so the call
// site does not need to change once the upstream SDK ships a real
// Register/Apply method. Today there is nothing to call.
//
// Returns a non-nil error only when the embedded schema descriptor
// itself is malformed (missing (entdb.node) on a declared message,
// duplicate type_ids, etc.). A live database failure would be
// reported here too once we wire actual RegisterSchema; for now,
// connectivity errors are the EntDB client's responsibility, not
// ours.
func applyOrLogSchemaGap(ctx context.Context, db service.DB, logger *zap.Logger) error {
	if logger == nil {
		logger = zap.NewNop()
	}
	_ = ctx
	_ = db // reserved for upstream RegisterSchema call — see TODO below.

	fd := (&identityschema.User{}).ProtoReflect().Descriptor().ParentFile()
	if fd == nil {
		return fmt.Errorf("%w: nil parent file descriptor", ErrSchemaMalformed)
	}

	declared, err := collectDeclaredNodeTypes(fd)
	if err != nil {
		return err
	}

	if len(declared) == 0 {
		return fmt.Errorf("%w: no (entdb.node) messages found in %s", ErrSchemaMalformed, fd.Path())
	}

	for _, t := range declared {
		logger.Info("schema_type_declared",
			zap.Int32("type_id", t.TypeID),
			zap.String("name", t.Name),
			zap.String("data_policy", t.DataPolicy),
			zap.String("subject_field", t.SubjectField),
		)
	}

	logger.Warn("schema_registration_pending_upstream_api",
		zap.Int("declared_node_types", len(declared)),
		zap.String("schema_file", string(fd.Path())),
		zap.String("hint",
			"identity declares the node types listed above; entdb's SDK does not "+
				"yet expose a Register/Apply method (server's internal "+
				"LoadDescriptor is a stub). Operations work today via permissive "+
				"defaults but indexed/unique fields and type-level validation "+
				"depend on upstream completing the schema registry. Track in "+
				"upstream tenant-shard-db-go repo."),
	)

	// TODO(upstream-schema-apply): when github.com/elloloop/tenant-shard-db
	// ships a RegisterSchema (or ApplySchema) method on *entdb.DbClient, call
	// it here with the FileDescriptorProto built from fd. Until then, this
	// function only logs the contract identity expects.
	//
	//	if applier, ok := any(db).(interface {
	//	        RegisterSchema(context.Context, *descriptorpb.FileDescriptorProto) error
	//	}); ok {
	//	        return applier.RegisterSchema(ctx, protodesc.ToFileDescriptorProto(fd))
	//	}

	return nil
}

// declaredNodeType is a flat view of an (entdb.node) annotation on a
// message in the identity schema, suitable for structured logging.
type declaredNodeType struct {
	Name         string
	TypeID       int32
	DataPolicy   string
	SubjectField string
}

// collectDeclaredNodeTypes walks every message in fd, reads its
// (entdb.node) option (if any), and returns one declaredNodeType per
// node-typed message. It is shared between applyOrLogSchemaGap and
// the test suite.
//
// Messages without an (entdb.node) annotation are skipped — they may
// be plain DTOs. Messages that look like node types (e.g. by naming
// convention) but lack the option are NOT flagged here; the test
// suite enforces the closed set of expected types.
func collectDeclaredNodeTypes(fd protoreflect.FileDescriptor) ([]declaredNodeType, error) {
	msgs := fd.Messages()
	out := make([]declaredNodeType, 0, msgs.Len())
	seen := make(map[int32]string, msgs.Len())

	for i := 0; i < msgs.Len(); i++ {
		md := msgs.Get(i)
		opts, _ := md.Options().(*descriptorpb.MessageOptions)
		if opts == nil {
			continue
		}
		if !proto.HasExtension(opts, entdbopts.E_Node) {
			continue
		}
		ext := proto.GetExtension(opts, entdbopts.E_Node)
		node, ok := ext.(*entdbopts.NodeOpts)
		if !ok || node == nil {
			return nil, fmt.Errorf("%w: message %s has malformed (entdb.node) option",
				ErrSchemaMalformed, md.FullName())
		}
		typeID := node.GetTypeId()
		if typeID == 0 {
			return nil, fmt.Errorf("%w: message %s has (entdb.node) but type_id=0",
				ErrSchemaMalformed, md.FullName())
		}
		if prev, dup := seen[typeID]; dup {
			return nil, fmt.Errorf("%w: type_id %d declared on both %s and %s",
				ErrSchemaMalformed, typeID, prev, md.FullName())
		}
		seen[typeID] = string(md.FullName())
		out = append(out, declaredNodeType{
			Name:         string(md.Name()),
			TypeID:       typeID,
			DataPolicy:   node.GetDataPolicy().String(),
			SubjectField: node.GetSubjectField(),
		})
	}
	return out, nil
}
