//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
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

// TestPasskeySignup_ThenLoginSuccess drives the full Connect stack: create a
// brand-new account from a passkey (unauthenticated), then log in with that
// same passkey. The login succeeding end-to-end proves the user id minted at
// BeginPasskeySignup was persisted as both the account id and the credential's
// owner — i.e. the WebAuthn handle binding is correct across the real server.
func TestPasskeySignup_ThenLoginSuccess(t *testing.T) {
	t.Parallel()

	h := startPasskeyVectorServer(t)
	ctx := context.Background()
	const email = "passkey-firstsignup@example.com"

	begin, err := h.Client.BeginPasskeySignup(ctx, connect.NewRequest(&identitypb.BeginPasskeySignupRequest{
		Email:      email,
		DeviceName: "Signup Key",
	}))
	if err != nil {
		t.Fatalf("BeginPasskeySignup: %v", err)
	}
	h.SetPasskeyChallengeValue(t, begin.Msg.ChallengeId, specPasskeyLoginRegistrationChallenge(t))

	// BeginPasskeySignup emailed a 6-digit OTP that proves control of the
	// address in-flow; CompletePasskeySignup requires it.
	otp := extractLoginCodeFromMailer(t, h, email)

	complete, err := h.Client.CompletePasskeySignup(ctx, connect.NewRequest(&identitypb.CompletePasskeySignupRequest{
		ChallengeId:    begin.Msg.ChallengeId,
		CredentialJson: buildPasskeyLoginRegistrationCredentialJSON(t),
		Email:          email,
		OtpCode:        otp,
		DeviceName:     "Signup Key",
	}))
	if err != nil {
		t.Fatalf("CompletePasskeySignup: %v", err)
	}
	user := complete.Msg.GetUser()
	userID := user.GetId()
	if userID == "" {
		t.Fatalf("CompletePasskeySignup returned no user id")
	}
	// The OTP proved inbox control, so the account is created already verified —
	// there is never an unverified account carrying a passkey (the pre-hijacking
	// surface this fix closes).
	if !user.GetEmailVerified() {
		t.Fatalf("passkey signup must create an already-verified account")
	}
	// A session issues immediately (no verification gate); the account is verified.
	if complete.Msg.AccessToken == "" || complete.Msg.RefreshToken == "" {
		t.Fatalf("expected a session for a verified passkey signup")
	}
	h.WaitForUser(t, email, func(user *service.User) bool { return user.ID == userID })

	if recs := h.ListPasskeyCredentials(t, userID); len(recs) != 1 {
		t.Fatalf("passkey credential count after signup = %d, want 1", len(recs))
	}

	// Log in with the passkey created during signup.
	loginBegin, err := h.Client.BeginPasskeyLogin(ctx, connect.NewRequest(&identitypb.BeginPasskeyLoginRequest{
		Email: email,
	}))
	if err != nil {
		t.Fatalf("BeginPasskeyLogin: %v", err)
	}
	h.SetPasskeyChallengeValue(t, loginBegin.Msg.ChallengeId, specPasskeyLoginChallenge(t))

	login, err := h.Client.CompletePasskeyLogin(ctx, connect.NewRequest(&identitypb.CompletePasskeyLoginRequest{
		ChallengeId:    loginBegin.Msg.ChallengeId,
		CredentialJson: buildPasskeyAssertionCredentialJSON(t),
	}))
	if err != nil {
		t.Fatalf("CompletePasskeyLogin after signup: %v", err)
	}
	if got := login.Msg.GetUser().GetId(); got != userID {
		t.Fatalf("login user id = %q, want %q", got, userID)
	}
	if login.Msg.AccessToken == "" || login.Msg.RefreshToken == "" {
		t.Fatalf("expected passkey login to mint access and refresh tokens")
	}
}

// extractLoginCodeFromMailer pulls the 6-digit OTP out of the most recent
// "Your login code" email captured by the harness mailer — the same code
// BeginPasskeySignup emails to prove in-flow control of the address.
func extractLoginCodeFromMailer(t *testing.T, h *Harness, addr string) string {
	t.Helper()
	sent := h.Mailer.Sent()
	for i := len(sent) - 1; i >= 0; i-- {
		msg := sent[i]
		if msg.To != addr || msg.Subject != "Your login code" {
			continue
		}
		for _, line := range strings.Split(msg.Text, "\n") {
			s := strings.TrimSpace(line)
			if len(s) == 6 && isAllASCIIDigits(s) {
				return s
			}
		}
	}
	t.Fatalf("no login-code email with a 6-digit code found for %q", addr)
	return ""
}

func isAllASCIIDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
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
