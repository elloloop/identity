//go:build integration

package integration

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/service"
)

func registerSpecPasskey(
	t *testing.T,
	h *Harness,
	email string,
	deviceName string,
) (string, identityconnectgen.IdentityServiceClient) {
	t.Helper()

	ctx := context.Background()
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    email,
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	h.WaitForUser(t, email, func(user *service.User) bool {
		return user.ID == signup.Msg.GetUser().GetId()
	})
	h.WaitForRefreshTokenCount(t, signup.Msg.GetUser().GetId(), 1)

	authed := h.AuthedClient(signup.Msg.AccessToken)
	begin, err := authed.BeginPasskeyRegistration(ctx, connect.NewRequest(&identitypb.BeginPasskeyRegistrationRequest{
		DeviceName: deviceName,
	}))
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}

	h.SetPasskeyChallengeValue(t, begin.Msg.ChallengeId, specPasskeyRegistrationChallenge(t))

	complete, err := authed.CompletePasskeyRegistration(ctx, connect.NewRequest(&identitypb.CompletePasskeyRegistrationRequest{
		ChallengeId:    begin.Msg.ChallengeId,
		CredentialJson: buildPasskeyRegistrationCredentialJSON(t),
		DeviceName:     deviceName,
	}))
	if err != nil {
		t.Fatalf("CompletePasskeyRegistration: %v", err)
	}

	if got := complete.Msg.GetCredential().GetCredentialId(); got != specPasskeyCredentialID(t) {
		t.Fatalf("credential id = %q, want %q", got, specPasskeyCredentialID(t))
	}
	h.ListPasskeyCredentials(t, signup.Msg.GetUser().GetId())

	return signup.Msg.GetUser().GetId(), authed
}

func registerPasskeyForLogin(
	t *testing.T,
	h *Harness,
	email string,
	deviceName string,
) (string, identityconnectgen.IdentityServiceClient) {
	t.Helper()

	ctx := context.Background()
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    email,
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	h.WaitForUser(t, email, func(user *service.User) bool {
		return user.ID == signup.Msg.GetUser().GetId()
	})
	h.WaitForRefreshTokenCount(t, signup.Msg.GetUser().GetId(), 1)

	authed := h.AuthedClient(signup.Msg.AccessToken)
	begin, err := authed.BeginPasskeyRegistration(ctx, connect.NewRequest(&identitypb.BeginPasskeyRegistrationRequest{
		DeviceName: deviceName,
	}))
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}

	h.SetPasskeyChallengeValue(t, begin.Msg.ChallengeId, specPasskeyLoginRegistrationChallenge(t))

	complete, err := authed.CompletePasskeyRegistration(ctx, connect.NewRequest(&identitypb.CompletePasskeyRegistrationRequest{
		ChallengeId:    begin.Msg.ChallengeId,
		CredentialJson: buildPasskeyLoginRegistrationCredentialJSON(t),
		DeviceName:     deviceName,
	}))
	if err != nil {
		t.Fatalf("CompletePasskeyRegistration: %v", err)
	}

	if got := complete.Msg.GetCredential().GetCredentialId(); got != specPasskeyLoginCredentialID(t) {
		t.Fatalf("credential id = %q, want %q", got, specPasskeyLoginCredentialID(t))
	}
	h.ListPasskeyCredentials(t, signup.Msg.GetUser().GetId())

	return signup.Msg.GetUser().GetId(), authed
}

func TestPasskey_RegisterSuccess(t *testing.T) {
	t.Parallel()

	h := startPasskeyVectorServer(t)
	userID, _ := registerSpecPasskey(t, h, "passkey-register@example.com", "Primary Key")

	recs := h.ListPasskeyCredentials(t, userID)
	if len(recs) != 1 {
		t.Fatalf("credential count = %d, want 1", len(recs))
	}

	cred := recs[0]
	if cred.CredentialID != specPasskeyCredentialID(t) {
		t.Fatalf("stored credential id = %q, want %q", cred.CredentialID, specPasskeyCredentialID(t))
	}
	if cred.DeviceName != "Primary Key" {
		t.Fatalf("device name = %q, want %q", cred.DeviceName, "Primary Key")
	}
	if cred.PublicKey == "" || cred.AAGUID == "" || cred.Transports == "" {
		t.Fatalf("expected persisted public key, aaguid, and transports")
	}

	if count := h.CountRefreshTokensForUser(t, userID); count != 1 {
		t.Fatalf("refresh token count = %d, want 1", count)
	}
}

func TestPasskey_RegisterTamperedChallengeRejected(t *testing.T) {
	t.Parallel()

	h := startPasskeyVectorServer(t)
	ctx := context.Background()

	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "passkey-challenge@example.com",
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}

	authed := h.AuthedClient(signup.Msg.AccessToken)
	begin, err := authed.BeginPasskeyRegistration(ctx, connect.NewRequest(&identitypb.BeginPasskeyRegistrationRequest{
		DeviceName: "Challenge Key",
	}))
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}

	h.SetPasskeyChallengeValue(t, begin.Msg.ChallengeId, "tampered-registration-challenge")

	_, err = authed.CompletePasskeyRegistration(ctx, connect.NewRequest(&identitypb.CompletePasskeyRegistrationRequest{
		ChallengeId:    begin.Msg.ChallengeId,
		CredentialJson: buildPasskeyRegistrationCredentialJSON(t),
		DeviceName:     "Challenge Key",
	}))
	if err == nil {
		t.Fatalf("expected challenge mismatch to fail")
	}
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err=%v)", got, err)
	}
}

func TestPasskey_LoginSuccess(t *testing.T) {
	t.Parallel()

	h := startPasskeyVectorServer(t)
	userID, _ := registerPasskeyForLogin(t, h, "passkey-login@example.com", "Login Key")
	ctx := context.Background()

	begin, err := h.Client.BeginPasskeyLogin(ctx, connect.NewRequest(&identitypb.BeginPasskeyLoginRequest{
		Email: "passkey-login@example.com",
	}))
	if err != nil {
		t.Fatalf("BeginPasskeyLogin: %v", err)
	}
	h.SetPasskeyChallengeValue(t, begin.Msg.ChallengeId, specPasskeyLoginChallenge(t))

	login, err := h.Client.CompletePasskeyLogin(ctx, connect.NewRequest(&identitypb.CompletePasskeyLoginRequest{
		ChallengeId:    begin.Msg.ChallengeId,
		CredentialJson: buildPasskeyAssertionCredentialJSON(t),
	}))
	if err != nil {
		t.Fatalf("CompletePasskeyLogin: %v", err)
	}
	if login.Msg.AccessToken == "" || login.Msg.RefreshToken == "" {
		t.Fatalf("expected passkey login to mint access and refresh tokens")
	}
	if got := login.Msg.GetUser().GetId(); got != userID {
		t.Fatalf("login user id = %q, want %q", got, userID)
	}

	currentUser, err := h.AuthedClient(login.Msg.AccessToken).GetCurrentUser(ctx, connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if got := currentUser.Msg.GetUser().GetId(); got != userID {
		t.Fatalf("GetCurrentUser id = %q, want %q", got, userID)
	}
}

func TestPasskey_LoginCounterRegressionRejected(t *testing.T) {
	t.Parallel()

	h := startPasskeyVectorServer(t)
	_, _ = registerPasskeyForLogin(t, h, "passkey-counter@example.com", "Counter Key")
	ctx := context.Background()

	h.SetPasskeyCredentialSignCount(t, specPasskeyLoginCredentialID(t), 1)

	begin, err := h.Client.BeginPasskeyLogin(ctx, connect.NewRequest(&identitypb.BeginPasskeyLoginRequest{
		Email: "passkey-counter@example.com",
	}))
	if err != nil {
		t.Fatalf("BeginPasskeyLogin: %v", err)
	}
	h.SetPasskeyChallengeValue(t, begin.Msg.ChallengeId, specPasskeyLoginChallenge(t))

	_, err = h.Client.CompletePasskeyLogin(ctx, connect.NewRequest(&identitypb.CompletePasskeyLoginRequest{
		ChallengeId:    begin.Msg.ChallengeId,
		CredentialJson: buildPasskeyAssertionCredentialJSON(t),
	}))
	if err == nil {
		t.Fatalf("expected counter regression to fail")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err=%v)", got, err)
	}
}
