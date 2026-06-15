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
	h := NewIdentityHandler(nil, nil, nil, nil, nil, idvSvc, nil, nil, nil, nil, testConfig())

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

func TestHandler_BeginIdentityVerification_UnknownUserMapsToNotFound(t *testing.T) {
	t.Parallel()

	client, _, _ := newIDVHarness(t, idv.NewStubProvider())

	_, err := client.BeginIdentityVerification(
		context.Background(),
		authedReq(connect.NewRequest(&identitypb.BeginIdentityVerificationRequest{}), "no-such-user"),
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := connect.CodeOf(err); got != connect.CodeNotFound {
		t.Fatalf("CodeOf = %v; want NotFound", got)
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

func TestIDVStatusToProto_AllBranches(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want identitypb.IdentityVerificationStatus
	}{
		{service.IDVStatusPending, identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_PENDING},
		{service.IDVStatusInReview, identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_IN_REVIEW},
		{service.IDVStatusApproved, identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_APPROVED},
		{service.IDVStatusRejected, identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_REJECTED},
		{service.IDVStatusExpired, identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_EXPIRED},
		{"", identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_UNSPECIFIED},
		{"garbage", identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_UNSPECIFIED},
	}
	for _, tc := range cases {
		if got := idvStatusToProto(tc.in); got != tc.want {
			t.Errorf("idvStatusToProto(%q) = %v; want %v", tc.in, got, tc.want)
		}
	}
}

func TestIDVRecordToProto_NilReturnsNil(t *testing.T) {
	t.Parallel()
	if got := idvRecordToProto(nil); got != nil {
		t.Fatalf("idvRecordToProto(nil) = %v; want nil", got)
	}
}

func TestIDVRecordToProto_PopulatesAllFields(t *testing.T) {
	t.Parallel()

	rec := &service.IdentityVerificationRecord{
		NodeID:            "node-1",
		VerificationID:    "v-1",
		UserID:            "u-1",
		ProjectID:         "t-1",
		Provider:          "stub",
		ProviderSessionID: "sess-1",
		Status:            service.IDVStatusRejected,
		CreatedAt:         1_000,
		UpdatedAt:         2_000,
		CompletedAt:       3_000,
		RejectionReason:   "document_unreadable",
	}
	got := idvRecordToProto(rec)
	if got.Id != "node-1" || got.UserId != "u-1" || got.TenantId != "t-1" {
		t.Fatalf("ids: %+v", got)
	}
	if got.Provider != "stub" || got.ProviderSessionId != "sess-1" {
		t.Fatalf("provider: %+v", got)
	}
	if got.Status != identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_REJECTED {
		t.Fatalf("status: %v", got.Status)
	}
	if got.CreatedAt == nil || got.UpdatedAt == nil || got.CompletedAt == nil {
		t.Fatalf("timestamps: %+v", got)
	}
	if got.RejectionReason != "document_unreadable" {
		t.Fatalf("reason: %q", got.RejectionReason)
	}
}

func TestHandler_GetIdentityVerificationStatus_Unauthenticated(t *testing.T) {
	t.Parallel()

	client, _, _ := newIDVHarness(t, idv.NewStubProvider())

	_, err := client.GetIdentityVerificationStatus(
		context.Background(),
		connect.NewRequest(&identitypb.GetIdentityVerificationStatusRequest{}),
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("CodeOf = %v; want Unauthenticated", got)
	}
}

func TestHandler_GetIdentityVerificationStatus_NotFound(t *testing.T) {
	t.Parallel()

	client, repo, _ := newIDVHarness(t, idv.NewStubProvider())
	other, _ := repo.CreateUser(context.Background(), &service.User{Email: "other@example.com", Status: "active"})

	// No verification has been started for `other`; latest-lookup returns NotFound.
	_, err := client.GetIdentityVerificationStatus(
		context.Background(),
		authedReq(connect.NewRequest(&identitypb.GetIdentityVerificationStatusRequest{}), other),
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := connect.CodeOf(err); got != connect.CodeNotFound {
		t.Fatalf("CodeOf = %v; want NotFound", got)
	}
}

func TestHandler_GetIdentityVerificationStatus_DisabledWhenServiceNil(t *testing.T) {
	t.Parallel()

	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, testConfig())
	mux := http.NewServeMux()
	path, handler := identityconnect.NewIdentityServiceHandler(h)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := identityconnect.NewIdentityServiceClient(srv.Client(), srv.URL)

	_, err := client.GetIdentityVerificationStatus(
		context.Background(),
		authedReq(connect.NewRequest(&identitypb.GetIdentityVerificationStatusRequest{}), "u-1"),
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnimplemented {
		t.Fatalf("CodeOf = %v; want Unimplemented", got)
	}
}

func TestHandler_IDV_DisabledWhenServiceNil(t *testing.T) {
	t.Parallel()

	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, testConfig())
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
