package identityserver

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
)

func peerContext(addr string, md metadata.MD) context.Context {
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(addr), Port: 5000}})
	if md != nil {
		ctx = metadata.NewIncomingContext(ctx, md)
	}
	return ctx
}

// The bridge attributes a call the way the HTTP chain does: x-forwarded-for
// counts only when the transport peer is a trusted proxy.
func TestGRPCBridge_ClientIP(t *testing.T) {
	trusted, err := middleware.ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	b := &grpcBridge{trustedProxies: trusted, logger: zap.NewNop()}
	xff := metadata.Pairs("x-forwarded-for", "203.0.113.5, 10.0.0.9")

	for _, tc := range []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"untrusted peer ignores x-forwarded-for", peerContext("198.51.100.4", xff), "198.51.100.4"},
		{"trusted peer honours x-forwarded-for", peerContext("10.0.0.2", xff), "203.0.113.5"},
		{"trusted peer without x-forwarded-for", peerContext("10.0.0.2", nil), "10.0.0.2"},
		{"no peer", context.Background(), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := b.clientIP(tc.ctx); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// Outside a live gRPC stream the retry-after header cannot be sent; the call
// is still refused, and the lost header is logged rather than dropped.
func TestGRPCBridge_ThrottleWithoutStream(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	b := &grpcBridge{logger: zap.New(core)}
	limit := middleware.PathLimit{
		PathPrefix: "/identity.v1.IdentityService/LookupUsers",
		Tag:        "directory_lookup",
		Limiter:    middleware.NewFixedWindowLimiter(time.Minute, 1, 0),
	}
	ctx := peerContext("198.51.100.4", nil)
	if err := b.throttle(ctx, limit); err != nil {
		t.Fatalf("first call: %v, want admitted", err)
	}
	if got := status.Code(b.throttle(ctx, limit)); got != codes.ResourceExhausted {
		t.Fatalf("second call: code = %v, want ResourceExhausted", got)
	}
	if logs.FilterMessage("rate_limit_retry_after_not_sent").Len() != 1 {
		t.Fatal("the unsent retry-after header was not logged")
	}
	if logs.FilterMessage("rate_limit_exceeded").Len() != 1 {
		t.Fatal("the refusal was not logged")
	}
}

// invoke sets the client IP header from the transport and never takes it
// from the caller's metadata, so a caller cannot choose the address its
// limits and audit entries are keyed on.
func TestGRPCBridge_InvokeSetsTheClientIPFromTheTransport(t *testing.T) {
	b := &grpcBridge{logger: zap.NewNop()}
	ctx := peerContext("198.51.100.4", metadata.Pairs("x-client-ip", "192.0.2.99", "x-forwarded-for", "192.0.2.98", "x-real-ip", "192.0.2.97"))
	var seen, xff, realIP string
	fn := func(_ context.Context, req *connect.Request[struct{}]) (*connect.Response[struct{}], error) {
		seen = req.Header().Get(middleware.ClientIPHeader)
		xff, realIP = req.Header().Get("X-Forwarded-For"), req.Header().Get("X-Real-Ip")
		return connect.NewResponse(&struct{}{}), nil
	}
	if _, err := invoke(ctx, b, &struct{}{}, fn); err != nil {
		t.Fatal(err)
	}
	if seen != "198.51.100.4" {
		t.Fatalf("handler saw client IP %q, want the transport peer", seen)
	}
	if xff != "" || realIP != "" {
		t.Fatalf("caller-supplied forwarding headers reached the handler: xff=%q real-ip=%q", xff, realIP)
	}
}

// The sign-in metadata a caller sent never reaches the handlers unless the
// host declared that its interceptor owns the key: an interceptor written
// before the keys existed would otherwise let a client vouch for its own
// recent sign-in, or say no recovery email opened its session. The amr has
// its own declaration, since a host that forwards auth_time may forward no
// amr, and a missing amr would read as a session no recovery email opened:
// until the host declares it, every session is marked unvouched and names no
// recovery email, whatever the client sent and whatever else the host trusts.
func TestGRPCBridge_SignInMetadataOnlyWhenTheHostOwnsIt(t *testing.T) {
	for _, sent := range []metadata.MD{
		metadata.Pairs("x-authenticated-auth-time", "1700000000", "x-authenticated-amr", "recovery_email",
			"x-authenticated-recovery-email-id", "rid-1"),
		metadata.Pairs("x-authenticated-auth-time", "1700000000"),
	} {
		for _, trust := range []grpcTrust{{}, {authTime: true}, {amr: true}, {authTime: true, amr: true}} {
			b := &grpcBridge{logger: zap.NewNop(), trust: trust}
			var authTime, recoveryEmailID string
			var amr []string
			fn := func(_ context.Context, req *connect.Request[struct{}]) (*connect.Response[struct{}], error) {
				authTime = req.Header().Get(middleware.AuthenticatedAuthTimeHeader)
				amr = req.Header().Values(middleware.AuthenticatedAMRHeader)
				recoveryEmailID = req.Header().Get(middleware.AuthenticatedRecoveryEmailIDHeader)
				return connect.NewResponse(&struct{}{}), nil
			}
			if _, err := invoke(peerContext("198.51.100.4", sent), b, &struct{}{}, fn); err != nil {
				t.Fatal(err)
			}
			if wantTime := map[bool]string{true: "1700000000"}[trust.authTime]; authTime != wantTime {
				t.Errorf("trust %+v, sent %v: handler saw auth time %q, want %q", trust, sent, authTime, wantTime)
			}
			wantAMR, wantID := []string{service.AMRUnvouched}, ""
			if trust.amr {
				wantAMR = sent.Get("x-authenticated-amr")
				if ids := sent.Get("x-authenticated-recovery-email-id"); len(ids) > 0 {
					wantID = ids[0]
				}
			}
			if !slices.Equal(amr, wantAMR) {
				t.Errorf("trust %+v, sent %v: handler saw amr %q, want %q", trust, sent, amr, wantAMR)
			}
			if recoveryEmailID != wantID {
				t.Errorf("trust %+v, sent %v: handler saw recovery email id %q, want %q", trust, sent, recoveryEmailID, wantID)
			}
		}
	}
}
