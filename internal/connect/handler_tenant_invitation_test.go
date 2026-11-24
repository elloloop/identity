package connect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/email"
)

const invitationLinkToken = "f00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeed"

func invitationTokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// invitationReadServer serves a MembershipService whose mailer delivers, over
// an operator's tenant "Acme" holding one pending invitation to
// invitee@example.com from its owner, emailed, whose address already has an
// account.
func invitationReadServer(t *testing.T) *membershipServer {
	t.Helper()
	invitations := newConnectInvitationStore()
	inv := &service.TenantInvitation{
		ID: "inv-1", ProjectID: testProjectID, TenantID: "tenant-1", TokenHash: invitationTokenHash(invitationLinkToken),
		Email: "invitee@example.com", InvitedBy: "owner-1", Role: service.RoleMember,
		Status: service.InvitationStatusPending, ExpiresAtMs: 4_102_444_800_000, TokenOnlyInEmail: true,
	}
	invitations.byHash[inv.TokenHash], invitations.byID[inv.ID] = inv, inv
	users := &connectUserDirectory{byID: map[string]*service.User{
		"owner-1": {ID: "owner-1", Name: "Maya Chen", Email: "maya@example.com"},
	}}
	accounts := memory.New()
	if _, err := accounts.WithProject(testProjectID).CreateUser(context.Background(), &service.User{Email: "invitee@example.com", Status: service.StatusActive}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tenants := &connectTenantStore{tenant: &service.Tenant{ID: "tenant-1", ProjectID: testProjectID, Name: "Acme", Status: service.TenantStatusClaimed}}
	svc := service.NewMembershipService(invitations, &connectMembershipStore{}, tenants, users,
		email.NewLogOnly(zap.NewNop()), true, &config.Config{}, zap.NewNop()).WithAccounts(accounts)
	return startMembershipServer(t, svc)
}

// The invitation's link is read with no session, and the answer is not kept
// by a cache along the way.
func TestGetTenantInvitation_OverTheWireWithoutASession(t *testing.T) {
	t.Parallel()
	srv := invitationReadServer(t)

	resp, err := srv.client.GetTenantInvitation(context.Background(),
		connect.NewRequest(&identitypb.GetTenantInvitationRequest{Token: invitationLinkToken}))
	if err != nil {
		t.Fatalf("GetTenantInvitation: %v", err)
	}
	got := resp.Msg
	if got.GetTenantId() != "tenant-1" || got.GetTenantName() != "Acme" ||
		got.GetInviterName() != "Maya Chen" || got.GetInviterEmail() != "maya@example.com" ||
		got.GetEmail() != "invitee@example.com" || got.GetRole() != service.RoleMember ||
		got.GetExpiresAtMs() != 4_102_444_800_000 || got.GetStatus() != service.InvitationStatusPending ||
		!got.GetAccountExists() {
		t.Fatalf("response = %+v", got)
	}
	if cc := resp.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}

// The sign-up is gated as PasswordSignup is, before the service runs: the
// password sign-up switch, then the assurance token. A request that passes
// both reaches the service, which has no invitations on this harness.
func TestSignUpWithTenantInvitation_GatedAsPasswordSignup(t *testing.T) {
	t.Parallel()
	req := func() *connect.Request[identitypb.SignUpWithTenantInvitationRequest] {
		return withClientHeaders(connect.NewRequest(&identitypb.SignUpWithTenantInvitationRequest{
			Token: invitationLinkToken, Name: "Ravi Kumar", Password: strongPW,
		}))
	}

	off := newHarness(t)
	off.cfg.PasswordSignupEnabled = false
	_, err := off.client.SignUpWithTenantInvitation(context.Background(), req())
	requireCode(t, err, connect.CodeFailedPrecondition)

	assured := newHarnessWithWebAssurance(t, &fakeVerifier{}, enableAssurance)
	_, err = assured.client.SignUpWithTenantInvitation(context.Background(), req())
	requireCode(t, err, connect.CodePermissionDenied)
	_, err = assured.client.SignUpWithTenantInvitation(context.Background(), assuredRequest(req(), exchangeWebToken(t, assured, "captcha-solution")))
	requireCode(t, err, connect.CodeUnimplemented)
	if n := len(assured.repo.users); n != 0 {
		t.Fatalf("%d accounts created, want none", n)
	}
}

func TestGetTenantInvitation_OverTheWireRefusals(t *testing.T) {
	t.Parallel()
	srv := invitationReadServer(t)
	ctx := context.Background()

	_, err := srv.client.GetTenantInvitation(ctx, connect.NewRequest(&identitypb.GetTenantInvitationRequest{Token: "not-a-real-token"}))
	requireCode(t, err, connect.CodeNotFound)
	_, err = srv.client.GetTenantInvitation(ctx, connect.NewRequest(&identitypb.GetTenantInvitationRequest{}))
	requireCode(t, err, connect.CodeInvalidArgument)

	_, err = startMembershipServer(t, nil).client.GetTenantInvitation(ctx,
		connect.NewRequest(&identitypb.GetTenantInvitationRequest{Token: invitationLinkToken}))
	requireCode(t, err, connect.CodeUnimplemented)
}
