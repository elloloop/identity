package identityserver

import (
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
)

// unbridgedRPCs are the IdentityService methods *grpcBridge does not declare,
// and therefore serves as codes.Unimplemented via the embedded
// UnimplementedIdentityServiceServer.
//
// THIS LIST MAY ONLY SHRINK. It exists because the embedding is a silent
// failure mode: adding an RPC to the proto compiles cleanly, the bridge keeps
// satisfying the interface, and a native-gRPC host discovers the gap at
// runtime as Unimplemented. Enumerating the gap turns invisible debt into a
// list somebody can work through, and makes every NEW proto RPC fail this
// test until it is either bridged or deliberately recorded here.
//
// Before adding a name: bridging an RPC is three lines
// (`return invoke(ctx, in, b.h.Foo)`), so "not bridged yet" is rarely the
// right answer for a method a host would call.
var unbridgedRPCs = map[string]string{
	// Control plane.
	"AddProjectAuthDomain":         "control plane",
	"AdminAddProjectAuthDomain":    "control plane",
	"AdminAddTenantAdmin":          "control plane",
	"AdminCreateProject":           "control plane",
	"AdminCreateProjectCredential": "control plane",
	"AdminCreateTenant":            "control plane",
	"CreateFirstPlatformAdmin":     "control plane",
	"ListProjectAuthDomains":       "control plane",
	"SetPrimaryAuthDomain":         "control plane",
	"VerifyProjectAuthDomain":      "control plane",

	// Per-project configuration.
	"AdminDeleteProjectOAuthProvider": "per-project configuration",
	"AdminGetProjectAssurance":        "per-project configuration",
	"AdminListProjectOAuthProviders":  "per-project configuration",
	"AdminSetProjectAssurance":        "per-project configuration",
	"AdminSetProjectOAuthProvider":    "per-project configuration",
	"DeleteLoginPolicy":               "per-project configuration",
	"GetLoginPolicy":                  "per-project configuration",
	"GetProjectConfig":                "per-project configuration",
	"UpsertLoginPolicy":               "per-project configuration",
	"UpsertProjectConfig":             "per-project configuration",

	// Tenant membership and invitations.
	"AcceptTenantInvitation": "tenant membership and invitations",
	"CreateTenantInvitation": "tenant membership and invitations",
	"ListTenantInvitations":  "tenant membership and invitations",
	"ListTenantMembers":      "tenant membership and invitations",
	"RemoveTenantMember":     "tenant membership and invitations",

	// Self-service account lifecycle.
	"CancelAccountDeletion": "self-service account lifecycle",
	"DeleteMyAccount":       "self-service account lifecycle",
	"ExportMyData":          "self-service account lifecycle",

	// Linked identities.
	"LinkIdentity":         "linked identities",
	"ListLinkedIdentities": "linked identities",
	"UnlinkIdentity":       "linked identities",

	// Auth surfaces no native-grpc host has needed yet.
	"BeginPasskeySignup":       "auth surfaces no native-gRPC host has needed yet",
	"CompletePasskeySignup":    "auth surfaces no native-gRPC host has needed yet",
	"NativeOAuthLogin":         "auth surfaces no native-gRPC host has needed yet",
	"RequestPhoneVerification": "auth surfaces no native-gRPC host has needed yet",
	"VerifyPhoneCode":          "auth surfaces no native-gRPC host has needed yet",
}

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
// proto. *grpcBridge embeds UnimplementedIdentityServiceServer, so it always
// satisfies IdentityServiceServer no matter how many RPCs it forgets — the
// compiler cannot catch a gap and a host only finds out when a call comes
// back Unimplemented. This test compares the generated interface against the
// methods the bridge actually declares, and fails on any difference from the
// recorded set.
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

	// Anything unbridged that is NOT recorded: a new proto RPC slipped onto
	// the service without reaching the bridge.
	var unrecorded []string
	for _, name := range missing {
		if _, known := unbridgedRPCs[name]; !known {
			unrecorded = append(unrecorded, name)
		}
	}
	if len(unrecorded) > 0 {
		t.Fatalf("RPCs missing from the gRPC bridge and not recorded in unbridgedRPCs: %v\n"+
			"Bridge them in identityserver/grpc_bridge.go (three lines each), or add them to\n"+
			"unbridgedRPCs with the reason a native-gRPC host does not need them.", unrecorded)
	}

	// Anything recorded that IS now bridged: the list must shrink as work
	// lands, so a stale entry is an error too.
	bridged := make(map[string]bool, len(missing))
	for _, name := range missing {
		bridged[name] = true
	}
	var stale []string
	for name := range unbridgedRPCs {
		if !bridged[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Fatalf("these RPCs are bridged now — remove them from unbridgedRPCs: %v", stale)
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
