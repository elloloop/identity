package identityserver

import (
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
)

// bridgeMethodSource returns the file a method on *grpcBridge resolves to. A
// method the bridge declares itself resolves into grpc_bridge.go; one promoted
// from the embedded UnimplementedIdentityServiceServer resolves into the
// generated protobuf package.
func bridgeMethodSource(t *testing.T, name string) string {
	t.Helper()
	m, ok := reflect.TypeOf(&grpcBridge{}).MethodByName(name)
	if !ok {
		return ""
	}
	fn := runtime.FuncForPC(m.Func.Pointer())
	if fn == nil {
		return ""
	}
	file, _ := fn.FileLine(m.Func.Pointer())
	return file
}

// TestGRPCBridge_DeclaresEveryRPC pins the native-gRPC surface against the
// proto: EVERY RPC on IdentityService must be declared on the bridge.
//
// *grpcBridge embeds UnimplementedIdentityServiceServer, so it always
// satisfies IdentityServiceServer no matter how many RPCs it forgets — the
// compiler cannot catch a gap and a host only finds out when a call comes
// back Unimplemented. The invariant is absolute rather than a list of
// tolerated gaps: an allowlist would let the next omission be waved through
// by adding a name to it, which is the same silent failure one step removed.
func TestGRPCBridge_DeclaresEveryRPC(t *testing.T) {
	t.Parallel()

	iface := reflect.TypeOf((*identitypb.IdentityServiceServer)(nil)).Elem()

	var missing []string
	for i := 0; i < iface.NumMethod(); i++ {
		name := iface.Method(i).Name
		// mustEmbedUnimplemented… is the generated forward-compatibility
		// guard, not an RPC.
		if strings.HasPrefix(name, "mustEmbed") {
			continue
		}
		src := bridgeMethodSource(t, name)
		if !strings.HasSuffix(src, "grpc_bridge.go") {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		t.Fatalf("these RPCs are not declared on the gRPC bridge, so a native-gRPC host\n"+
			"gets codes.Unimplemented for them: %v\n"+
			"Add each to identityserver/grpc_bridge.go — it is three lines:\n"+
			"\tfunc (b *grpcBridge) Foo(ctx context.Context, in *identitypb.FooRequest) (*identitypb.FooResponse, error) {\n"+
			"\t\treturn invoke(ctx, in, b.h.Foo)\n"+
			"\t}", missing)
	}
}

// TestGRPCBridge_ManagedMinorSurfaceIsBridged pins the epic's own RPCs
// explicitly, rather than leaving them to the general guard above. The
// guardian surface is the one a host is most likely to drive over native
// gRPC (a parent's dashboard in an embedding application), and
// CompletePasskeyRegistration carries the managed-child enrolment ticket —
// an unbridged one would strand a child's device with no way to enrol.
func TestGRPCBridge_ManagedMinorSurfaceIsBridged(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"CreateManagedChildAccount",
		"ListManagedChildren",
		"GetGuardians",
		"GetManagedChildProfile",
		"SetManagedChildPassword",
		"SetManagedChildUsername",
		"RevokeManagedChildSessions",
		"DeactivateManagedChildAccount",
		"ReactivateManagedChildAccount",
		"DeleteManagedChildAccount",
		"GrantParentalConsent",
		"RevokeParentalConsent",
		"SetAccountMarket",
		"SubmitDateOfBirth",
		"BeginPasskeyRegistration",
		"CompletePasskeyRegistration",
	} {
		if src := bridgeMethodSource(t, name); !strings.HasSuffix(src, "grpc_bridge.go") {
			t.Errorf("%s is not declared on the bridge (resolves to %q); a native-gRPC host "+
				"would get codes.Unimplemented", name, src)
		}
	}
}
