// Schema declaration listing.
//
// EntDB's schema is client-side: the SDK reads (entdb.node) /
// (entdb.edge) options off the proto descriptor at every call site,
// and the wire format is keyed by proto field id. There is no
// server-side "register schema" step to wait for — the previous
// "schema_registration_pending_upstream_api" warning was wrong about
// the SDK contract.
//
// This file therefore loads the embedded FileDescriptor for
// identity's schema and emits one structured log line per declared
// node type at startup, so operators can see the contract identity
// runs against. It does no I/O.
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
// descriptor and emits one structured `schema_loaded` log entry per
// declared node type. The db argument is reserved so the call site
// stays stable for any future server-side schema-apply hook the SDK
// might ship.
//
// Returns a non-nil error only when the embedded schema descriptor
// itself is malformed (missing (entdb.node) on a declared message,
// duplicate type_ids, etc.).
func applyOrLogSchemaGap(ctx context.Context, db service.DB, logger *zap.Logger) error {
	if logger == nil {
		logger = zap.NewNop()
	}
	_ = ctx
	_ = db

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
		logger.Info("schema_loaded",
			zap.Int32("type_id", t.TypeID),
			zap.String("name", t.Name),
			zap.String("data_policy", t.DataPolicy),
			zap.String("subject_field", t.SubjectField),
		)
	}

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
