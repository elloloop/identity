//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/service"
)

func enrollTotp(
	t *testing.T,
	h *Harness,
	email string,
) (identityconnectgen.IdentityServiceClient, string, []string) {
	t.Helper()

	ctx := context.Background()
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    email,
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}

	authed := h.AuthedClient(signup.Msg.AccessToken)
	begin, err := authed.BeginTotpSetup(ctx, connect.NewRequest(&identitypb.BeginTotpSetupRequest{}))
	if err != nil {
		t.Fatalf("BeginTotpSetup: %v", err)
	}
	if begin.Msg.Secret == "" {
		t.Fatalf("BeginTotpSetup returned empty secret")
	}
	if !strings.HasPrefix(begin.Msg.QrCodeUri, "otpauth://totp/") {
		t.Fatalf("unexpected TOTP QR URI: %q", begin.Msg.QrCodeUri)
	}
	if len(begin.Msg.RecoveryCodes) != 10 {
		t.Fatalf("recovery code count = %d, want 10", len(begin.Msg.RecoveryCodes))
	}
	h.WaitForTotpCredential(t, signup.Msg.GetUser().GetId(), func(rec *service.TotpCredRecord) bool {
		return !rec.Verified
	})

	verifyCode := generateTotpCodeAt(t, begin.Msg.Secret, time.Now())
	verify, err := authed.VerifyTotpSetup(ctx, connect.NewRequest(&identitypb.VerifyTotpSetupRequest{
		Code: verifyCode,
	}))
	if err != nil {
		t.Fatalf("VerifyTotpSetup: %v", err)
	}
	if !verify.Msg.Verified {
		t.Fatalf("expected VerifyTotpSetup to report verified=true")
	}

	return authed, begin.Msg.Secret, begin.Msg.RecoveryCodes
}

func requireTotpLoginChallenge(t *testing.T, h *Harness, email string) string {
	t.Helper()

	login, err := h.Client.PasswordLogin(context.Background(), connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    email,
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordLogin: %v", err)
	}
	if !login.Msg.TotpRequired {
		t.Fatalf("expected totp_required=true")
	}
	if login.Msg.LoginChallengeId == "" {
		t.Fatalf("expected login challenge id")
	}
	if login.Msg.AccessToken != "" || login.Msg.RefreshToken != "" {
		t.Fatalf("PasswordLogin should not mint tokens before TOTP verification")
	}

	return login.Msg.LoginChallengeId
}

func TestTotp_EnrollVerifyAndDisable(t *testing.T) {
	t.Parallel()

	h := StartServer(t)
	authed, secret, _ := enrollTotp(t, h, "totp-disable@example.com")
	ctx := context.Background()

	challengeID := requireTotpLoginChallenge(t, h, "totp-disable@example.com")
	loginCode := generateTotpCodeAt(t, secret, time.Now())
	verifyLogin, err := h.Client.VerifyTotp(ctx, connect.NewRequest(&identitypb.VerifyTotpRequest{
		LoginChallengeId: challengeID,
		Code:             loginCode,
	}))
	if err != nil {
		t.Fatalf("VerifyTotp: %v", err)
	}
	if verifyLogin.Msg.AccessToken == "" || verifyLogin.Msg.RefreshToken == "" {
		t.Fatalf("expected VerifyTotp to mint tokens")
	}

	if _, err := authed.DisableTotp(ctx, connect.NewRequest(&identitypb.DisableTotpRequest{
		Password: goodPassword,
	})); err != nil {
		t.Fatalf("DisableTotp: %v", err)
	}
	h.WaitForUser(t, "totp-disable@example.com", func(user *service.User) bool {
		return !user.TotpRequired
	})

	postDisable, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "totp-disable@example.com",
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("post-disable PasswordLogin: %v", err)
	}
	if postDisable.Msg.TotpRequired {
		t.Fatalf("expected TOTP to be disabled")
	}
	if postDisable.Msg.AccessToken == "" || postDisable.Msg.RefreshToken == "" {
		t.Fatalf("expected password login to mint tokens after TOTP disable")
	}
}

func TestTotp_RegenRecoveryCodesConsumeAndReplayRejected(t *testing.T) {
	t.Parallel()

	h := StartServer(t)
	authed, _, originalCodes := enrollTotp(t, h, "totp-recovery@example.com")
	ctx := context.Background()

	regen, err := authed.RegenerateRecoveryCodes(ctx, connect.NewRequest(&identitypb.RegenerateRecoveryCodesRequest{
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("RegenerateRecoveryCodes: %v", err)
	}
	if len(regen.Msg.RecoveryCodes) != 10 {
		t.Fatalf("regenerated recovery code count = %d, want 10", len(regen.Msg.RecoveryCodes))
	}

	oldChallengeID := requireTotpLoginChallenge(t, h, "totp-recovery@example.com")
	_, err = h.Client.VerifyTotp(ctx, connect.NewRequest(&identitypb.VerifyTotpRequest{
		LoginChallengeId: oldChallengeID,
		Code:             originalCodes[0],
	}))
	if err == nil {
		t.Fatalf("expected original recovery code to be invalid after regeneration")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err=%v)", got, err)
	}

	validChallengeID := requireTotpLoginChallenge(t, h, "totp-recovery@example.com")
	validRecoveryCode := regen.Msg.RecoveryCodes[0]
	verify, err := h.Client.VerifyTotp(ctx, connect.NewRequest(&identitypb.VerifyTotpRequest{
		LoginChallengeId: validChallengeID,
		Code:             validRecoveryCode,
	}))
	if err != nil {
		t.Fatalf("VerifyTotp with regenerated recovery code: %v", err)
	}
	if verify.Msg.AccessToken == "" || verify.Msg.RefreshToken == "" {
		t.Fatalf("expected regenerated recovery code to mint tokens")
	}

	replayChallengeID := requireTotpLoginChallenge(t, h, "totp-recovery@example.com")
	_, err = h.Client.VerifyTotp(ctx, connect.NewRequest(&identitypb.VerifyTotpRequest{
		LoginChallengeId: replayChallengeID,
		Code:             validRecoveryCode,
	}))
	if err == nil {
		t.Fatalf("expected replayed recovery code to fail")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("replay code = %v, want Unauthenticated (err=%v)", got, err)
	}
}
