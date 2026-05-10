package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	identityconnect "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/idv"
)

// newIDVHarness spins up a Connect server with an IDV service backed
// by a configurable stub provider. The other services are nil because
// this test exercises only the IDV RPC path.
func newIDVHarness(t *testing.T, provider idv.Provider) (identityconnect.IdentityServiceClient, *fakeRepo, string) {
	t.Helper()

	repo := newFakeRepo()
	uid, err := repo.CreateUser(context.Background(), &service.User{Email: "u@example.com", Status: "active"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	idvSvc := service.NewIdentityVerificationService(repo, provider, "tenant-1", zap.NewNop())
	h := NewIdentityHandler(nil, nil, nil, nil, nil, idvSvc, testConfig())

	mux := http.NewServeMux()
	path, handler := identityconnect.NewIdentityServiceHandler(h)
	mux.Handle(path, handler)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := identityconnect.NewIdentityServiceClient(srv.Client(), srv.URL)
	return client, repo, uid
}

func TestHandler_BeginIdentityVerification_HappyPath(t *testing.T) {
	t.Parallel()

	client, _, uid := newIDVHarness(t, idv.NewStubProvider())

	req := connect.NewRequest(&identitypb.BeginIdentityVerificationRequest{})
	authedReq(req, uid)

	res, err := client.BeginIdentityVerification(context.Background(), req)
	if err != nil {
		t.Fatalf("BeginIdentityVerification: %v", err)
	}
	if res.Msg.VerificationId == "" {
		t.Fatal("VerificationId empty")
	}
	if res.Msg.Provider != "stub" {
		t.Fatalf("Provider = %q; want stub", res.Msg.Provider)
	}
	if res.Msg.SessionToken == "" {
		t.Fatal("SessionToken empty")
	}
	if res.Msg.ExpiresAt == nil {
		t.Fatal("ExpiresAt nil")
	}
}

func TestHandler_BeginIdentityVerification_Unauthenticated(t *testing.T) {
	t.Parallel()

	client, _, _ := newIDVHarness(t, idv.NewStubProvider())

	_, err := client.BeginIdentityVerification(
		context.Background(),
		connect.NewRequest(&identitypb.BeginIdentityVerificationRequest{}),
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("CodeOf = %v; want Unauthenticated", got)
	}
}

func TestHandler_GetIdentityVerificationStatus_AfterBegin(t *testing.T) {
	t.Parallel()

	provider := idv.NewStubProvider()
	client, _, uid := newIDVHarness(t, provider)

	begin, err := client.BeginIdentityVerification(
		context.Background(),
		authedReq(connect.NewRequest(&identitypb.BeginIdentityVerificationRequest{}), uid),
	)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	status, err := client.GetIdentityVerificationStatus(
		context.Background(),
		authedReq(connect.NewRequest(&identitypb.GetIdentityVerificationStatusRequest{
			VerificationId: begin.Msg.VerificationId,
		}), uid),
	)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.Msg.Verification == nil {
		t.Fatal("Verification nil")
	}
	if got := status.Msg.Verification.Status; got != identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_APPROVED {
		t.Fatalf("status = %v; want APPROVED", got)
	}
}

func TestHandler_IDV_DisabledWhenServiceNil(t *testing.T) {
	t.Parallel()

	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, testConfig())
	mux := http.NewServeMux()
	path, handler := identityconnect.NewIdentityServiceHandler(h)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := identityconnect.NewIdentityServiceClient(srv.Client(), srv.URL)

	_, err := client.BeginIdentityVerification(
		context.Background(),
		authedReq(connect.NewRequest(&identitypb.BeginIdentityVerificationRequest{}), "u-1"),
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnimplemented {
		t.Fatalf("CodeOf = %v; want Unimplemented", got)
	}
}
