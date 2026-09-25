package identityserver

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/elloloop/identity/internal/middleware"
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
