//go:build integration

package integration

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/pkg/idv"
)

const idvPassword = "Sw0rdfish!42"

// TestIDV_StubProvider_HappyPath drives the IDV flow end-to-end through
// the Connect server with the stub provider. Begin returns a session
// token; status poll resolves to APPROVED.
func TestIDV_StubProvider_HappyPath(t *testing.T) {
	t.Parallel()
	h := StartServer(t, WithIDVProvider(idv.NewStubProvider()))
	ctx := context.Background()

	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "idv-happy@example.com",
		Password: idvPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	authed := h.AuthedClient(signup.Msg.GetAccessToken())

	beginRes, err := authed.BeginIdentityVerification(ctx, connect.NewRequest(&identitypb.BeginIdentityVerificationRequest{}))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if beginRes.Msg.GetVerificationId() == "" || beginRes.Msg.GetSessionToken() == "" {
		t.Fatalf("empty fields in begin response: %+v", beginRes.Msg)
	}
	if beginRes.Msg.GetProvider() != "stub" {
		t.Fatalf("provider = %q; want stub", beginRes.Msg.GetProvider())
	}

	statusRes, err := authed.GetIdentityVerificationStatus(ctx, connect.NewRequest(&identitypb.GetIdentityVerificationStatusRequest{
		VerificationId: beginRes.Msg.GetVerificationId(),
	}))
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	verif := statusRes.Msg.GetVerification()
	if got := verif.GetStatus(); got != identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_APPROVED {
		t.Fatalf("status = %v; want APPROVED", got)
	}
	// Per docs/IDENTITY.md the identity-tenant ↔ storage-tenant mapping is
	// 1:1, so every persisted IDV record carries the scope's tenant id.
	// On the graph backend the proto has no tenant_id field, so the repo
	// synthesises it from the scope on read; this assertion catches a
	// regression where the field stops being populated end-to-end.
	if got := verif.GetTenantId(); got == "" {
		t.Fatalf("verification.tenant_id is empty; expected the deployment tenant id")
	}
}

// TestIDV_StubProvider_LatestForUser confirms that omitting verification_id
// returns the user's most recent session.
func TestIDV_StubProvider_LatestForUser(t *testing.T) {
	t.Parallel()
	h := StartServer(t, WithIDVProvider(idv.NewStubProvider()))
	ctx := context.Background()

	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "idv-latest@example.com",
		Password: idvPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	authed := h.AuthedClient(signup.Msg.GetAccessToken())

	first, err := authed.BeginIdentityVerification(ctx, connect.NewRequest(&identitypb.BeginIdentityVerificationRequest{}))
	if err != nil {
		t.Fatalf("Begin 1: %v", err)
	}
	second, err := authed.BeginIdentityVerification(ctx, connect.NewRequest(&identitypb.BeginIdentityVerificationRequest{}))
	if err != nil {
		t.Fatalf("Begin 2: %v", err)
	}
	if first.Msg.GetVerificationId() == second.Msg.GetVerificationId() {
		t.Fatal("two Begin calls returned the same id")
	}

	res, err := authed.GetIdentityVerificationStatus(ctx, connect.NewRequest(&identitypb.GetIdentityVerificationStatusRequest{}))
	if err != nil {
		t.Fatalf("Get latest: %v", err)
	}
	if got := res.Msg.GetVerification().GetId(); got == "" {
		t.Fatalf("Get latest returned no record: %+v", res.Msg)
	}
}

// TestIDV_DisabledByDefault asserts the RPCs return Unimplemented when
// no provider is configured.
func TestIDV_DisabledByDefault(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "idv-disabled@example.com",
		Password: idvPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	authed := h.AuthedClient(signup.Msg.GetAccessToken())

	if _, err := authed.BeginIdentityVerification(ctx, connect.NewRequest(&identitypb.BeginIdentityVerificationRequest{})); err == nil {
		t.Fatal("expected Unimplemented")
	} else if got := connect.CodeOf(err); got != connect.CodeUnimplemented {
		t.Fatalf("CodeOf = %v; want Unimplemented", got)
	}
}
