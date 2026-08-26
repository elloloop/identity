//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/passwords"
)

// seedAdult creates a consent-capable adult account (password + a verified
// phone as the strong factor) directly in the repository and signs it in,
// returning its user id and an authenticated client.
func seedAdult(t *testing.T, h *Harness, email string) (string, identityconnectgen.IdentityServiceClient) {
	t.Helper()
	hash, err := passwords.Hash(goodPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	adultID, err := h.Repo.CreateUser(context.Background(), &service.User{
		Email:         email,
		Status:        "active",
		Role:          "member",
		PasswordHash:  hash,
		EmailVerified: true,
		PhoneVerified: true,
	})
	if err != nil {
		t.Fatalf("seed adult: %v", err)
	}
	login, err := h.Client.PasswordLogin(context.Background(), connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    email,
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("adult login: %v", err)
	}
	return adultID, h.AuthedClient(login.Msg.AccessToken)
}

// TestManagedChildAccount_Password_EndToEnd drives the parent-creates-child
// flow over the real Connect handler chain: the adult creates a username-
// identified child with a password, and the child signs in with that username.
func TestManagedChildAccount_Password_EndToEnd(t *testing.T) {
	h := StartServer(t)
	ctx := context.Background()
	_, authed := seedAdult(t, h, "parent-mc@example.org")

	create, err := authed.CreateManagedChildAccount(ctx, connect.NewRequest(&identitypb.CreateManagedChildAccountRequest{
		Username:       "kid.one",
		DisplayName:    "Kid One",
		DateOfBirthMs:  time.Now().AddDate(-8, 0, 0).UnixMilli(),
		Password:       goodPassword,
		PolicyVersion:  "children-privacy-notice-v1",
		StepUpPassword: goodPassword,
	}))
	if err != nil {
		t.Fatalf("CreateManagedChildAccount: %v", err)
	}
	child := create.Msg.GetChild()
	if child.GetUsername() != "kid.one" || child.GetEmail() != "" {
		t.Fatalf("child identity = username %q email %q", child.GetUsername(), child.GetEmail())
	}
	if child.GetStatus() != identitypb.UserStatus_USER_STATUS_ACTIVE {
		t.Fatalf("child status = %v, want ACTIVE (born active, never pending)", child.GetStatus())
	}
	if create.Msg.GetConsent().GetConsentingUserId() == "" || !create.Msg.GetConsent().GetSteppedUp() {
		t.Fatalf("consent record incomplete: %+v", create.Msg.GetConsent())
	}
	if create.Msg.GetEnrolmentToken() != "" {
		t.Fatal("password arm must not return an enrolment token")
	}

	// The child signs in with its username, case-insensitively.
	login, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "Kid.One",
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("child PasswordLogin by username: %v", err)
	}
	if login.Msg.GetUser().GetId() != child.GetId() || login.Msg.GetAccessToken() == "" {
		t.Fatalf("username login: user=%q token empty=%v", login.Msg.GetUser().GetId(), login.Msg.GetAccessToken() == "")
	}
}

// TestManagedChildAccount_PasskeyEnrolment_EndToEnd drives the bootstrap half:
// the adult creates a passwordless child, the child's device redeems the
// enrolment ticket through the passkey registration ceremony WITHOUT a
// session, and completing the ceremony returns the child's first session —
// which then authenticates as the child.
func TestManagedChildAccount_PasskeyEnrolment_EndToEnd(t *testing.T) {
	h := startPasskeyVectorServer(t)
	ctx := context.Background()
	_, authed := seedAdult(t, h, "parent-pk@example.org")

	create, err := authed.CreateManagedChildAccount(ctx, connect.NewRequest(&identitypb.CreateManagedChildAccountRequest{
		Username:         "kid.two",
		DisplayName:      "Kid Two",
		DateOfBirthMs:    time.Now().AddDate(-9, 0, 0).UnixMilli(),
		PasskeyEnrolment: true,
		PolicyVersion:    "children-privacy-notice-v1",
		StepUpPassword:   goodPassword,
	}))
	if err != nil {
		t.Fatalf("CreateManagedChildAccount: %v", err)
	}
	ticket := create.Msg.GetEnrolmentToken()
	if ticket == "" {
		t.Fatal("passkey_enrolment arm must return an enrolment ticket")
	}
	childID := create.Msg.GetChild().GetId()

	// The child's device: NO session — the ticket in the body is the credential.
	begin, err := h.Client.BeginPasskeyRegistration(ctx, connect.NewRequest(&identitypb.BeginPasskeyRegistrationRequest{
		DeviceName:     "kid-ipad",
		EnrolmentToken: ticket,
	}))
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration with enrolment ticket: %v", err)
	}
	h.SetPasskeyChallengeValue(t, begin.Msg.ChallengeId, specPasskeyRegistrationChallenge(t))

	complete, err := h.Client.CompletePasskeyRegistration(ctx, connect.NewRequest(&identitypb.CompletePasskeyRegistrationRequest{
		ChallengeId:    begin.Msg.ChallengeId,
		CredentialJson: buildPasskeyRegistrationCredentialJSON(t),
		DeviceName:     "kid-ipad",
		EnrolmentToken: ticket,
	}))
	if err != nil {
		t.Fatalf("CompletePasskeyRegistration with enrolment ticket: %v", err)
	}
	if got := complete.Msg.GetCredential().GetCredentialId(); got != specPasskeyCredentialID(t) {
		t.Fatalf("credential id = %q, want %q", got, specPasskeyCredentialID(t))
	}
	if complete.Msg.GetAccessToken() == "" || complete.Msg.GetRefreshToken() == "" {
		t.Fatal("enrolment completion must issue the child's first token pair")
	}

	// The issued session authenticates as the child.
	me, err := h.AuthedClient(complete.Msg.GetAccessToken()).GetCurrentUser(ctx, connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
	if err != nil {
		t.Fatalf("GetCurrentUser with enrolment-issued session: %v", err)
	}
	if me.Msg.GetUser().GetId() != childID {
		t.Fatalf("session user = %q, want child %q", me.Msg.GetUser().GetId(), childID)
	}

	// The credential is registered to the child.
	creds := h.ListPasskeyCredentials(t, childID)
	if len(creds) != 1 {
		t.Fatalf("child passkeys = %d, want 1", len(creds))
	}
}

// TestManagedChildAccount_EnrolmentTicketMisuse pins the ticket's posture: it
// never authenticates a session-bearing call, and the ceremony refuses both a
// sessionless request without a ticket and a ticket presented alongside a
// session.
func TestManagedChildAccount_EnrolmentTicketMisuse(t *testing.T) {
	h := startPasskeyVectorServer(t)
	ctx := context.Background()
	_, authed := seedAdult(t, h, "parent-misuse@example.org")

	create, err := authed.CreateManagedChildAccount(ctx, connect.NewRequest(&identitypb.CreateManagedChildAccountRequest{
		Username:         "kid.three",
		DateOfBirthMs:    time.Now().AddDate(-7, 0, 0).UnixMilli(),
		PasskeyEnrolment: true,
		PolicyVersion:    "children-privacy-notice-v1",
		StepUpPassword:   goodPassword,
	}))
	if err != nil {
		t.Fatalf("CreateManagedChildAccount: %v", err)
	}
	ticket := create.Msg.GetEnrolmentToken()

	// The ticket as a Bearer credential authenticates NOTHING (a purpose token
	// is not a session); the handler then refuses the credential-less call.
	_, err = h.AuthedClient(ticket).BeginPasskeyRegistration(ctx, connect.NewRequest(&identitypb.BeginPasskeyRegistrationRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("ticket as bearer: code = %v, want Unauthenticated", connect.CodeOf(err))
	}

	// Sessionless without a ticket: refused.
	_, err = h.Client.BeginPasskeyRegistration(ctx, connect.NewRequest(&identitypb.BeginPasskeyRegistrationRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("sessionless no ticket: code = %v, want Unauthenticated", connect.CodeOf(err))
	}

	// Session + ticket together: ambiguous, refused.
	_, err = authed.BeginPasskeyRegistration(ctx, connect.NewRequest(&identitypb.BeginPasskeyRegistrationRequest{
		EnrolmentToken: ticket,
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("session + ticket: code = %v, want InvalidArgument", connect.CodeOf(err))
	}
}
