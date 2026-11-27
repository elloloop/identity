//go:build integration && realpostgres

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

// setUpManagedAccount creates username@mt.domain in mt and sets it up with
// validPassword, returning its id and the set-up's refresh token.
func setUpManagedAccount(t *testing.T, h *RedesignHarness, mt managedTenant, username string) (string, string) {
	t.Helper()
	delivery := fmt.Sprintf("%s-%d@example.net", username, time.Now().UnixNano())
	if _, err := createManaged(mt.owner, username, mt.domain, strings.ToUpper(username[:1])+username[1:], delivery, service.RoleMember); err != nil {
		t.Fatalf("create %s: %v", username, err)
	}
	done, err := setUp(h, extractMailedToken(t, h, delivery), validPassword)
	if err != nil {
		t.Fatalf("set up %s: %v", username, err)
	}
	return done.GetUser().GetId(), done.GetRefreshToken()
}

// signInMethods are the ways a managed account at addr signs in, each
// returning the error that ended it.
func signInMethods(h *RedesignHarness, addr string) map[string]func(t *testing.T) error {
	client := brandedClient(h, "")
	ctx := context.Background()
	return map[string]func(t *testing.T) error{
		"password": func(*testing.T) error {
			_, err := client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{Email: addr, Password: validPassword}))
			return err
		},
		"email code": func(t *testing.T) error {
			t.Helper()
			h.Mailer.Reset()
			if _, err := client.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: addr})); err != nil {
				return err
			}
			if len(h.Mailer.Sent()) == 0 {
				return errors.New("no code sent")
			}
			_, err := client.VerifyEmailLoginCode(ctx, connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{Email: addr, Code: extractRedesignLoginCode(t, h)}))
			return err
		},
		"magic link": func(t *testing.T) error {
			t.Helper()
			h.Mailer.Reset()
			if _, err := client.RequestMagicLink(ctx, connect.NewRequest(&identitypb.RequestMagicLinkRequest{Email: addr, ReturnTo: managedReturnTo})); err != nil {
				return err
			}
			sent := h.Mailer.Sent()
			if len(sent) == 0 {
				return errors.New("no link sent")
			}
			_, err := client.RedeemMagicLink(ctx, connect.NewRequest(&identitypb.RedeemMagicLinkRequest{Token: extractToken(t, sent[len(sent)-1].Text)}))
			return err
		},
	}
}

const managedReturnTo = "https://app.example.com/done"

// enableManagedSignIn is enableManagedAccounts with a return URL a magic
// link may name.
func enableManagedSignIn(c *config.Config) {
	enableManagedAccounts(c)
	c.OAuthAllowedReturnURLs = "https://app.example.com/"
}

// refresh rotates refreshToken on the branded host.
func refresh(h *RedesignHarness, refreshToken string) (*identitypb.RefreshTokenResponse, error) {
	resp, err := brandedClient(h, "").RefreshToken(context.Background(), connect.NewRequest(&identitypb.RefreshTokenRequest{RefreshToken: refreshToken}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// TestRedesign_ManagedAccounts_SignInNeedsAnActiveMembership drives every
// sign-in method of a managed account against a real Postgres: each signs in
// while the account is set up and its membership active; each, and a
// refresh, is refused while the membership is suspended, which spends the
// refreshed token; restored, each signs in again; and removed from the
// tenant, none does.
func TestRedesign_ManagedAccounts_SignInNeedsAnActiveMembership(t *testing.T) {
	h := startRedesignHarnessWith(t, enableManagedSignIn)
	setProjectConfig(t, h, managedAccountsConfig)
	ctx := context.Background()
	mt := newManagedTenant(t, h, "managed-signin")
	userID, refreshToken := setUpManagedAccount(t, h, mt, "kim")
	addr := "kim@" + mt.domain
	methods := signInMethods(h, addr)

	for name, signIn := range methods {
		if err := signIn(t); err != nil {
			t.Fatalf("%s while active: %v", name, err)
		}
	}
	rotated, err := refresh(h, refreshToken)
	if err != nil {
		t.Fatalf("refresh while active: %v", err)
	}

	if _, err := mt.owner.client.SuspendTenantMember(ctx, connect.NewRequest(&identitypb.SuspendTenantMemberRequest{TenantId: mt.tenantID, UserId: userID})); err != nil {
		t.Fatalf("SuspendTenantMember: %v", err)
	}
	for name, signIn := range methods {
		if err := signIn(t); connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("%s while suspended = %v, want FailedPrecondition", name, err)
		}
	}
	if _, err := refresh(h, rotated.GetRefreshToken()); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("refresh while suspended = %v, want FailedPrecondition", err)
	}
	if _, err := refresh(h, rotated.GetRefreshToken()); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("the refused refresh token again = %v, want Unauthenticated: it was spent", err)
	}

	if _, err := mt.owner.client.RestoreTenantMember(ctx, connect.NewRequest(&identitypb.RestoreTenantMemberRequest{TenantId: mt.tenantID, UserId: userID})); err != nil {
		t.Fatalf("RestoreTenantMember: %v", err)
	}
	for name, signIn := range methods {
		if err := signIn(t); err != nil {
			t.Fatalf("%s once restored: %v", name, err)
		}
	}

	if _, err := mt.owner.client.RemoveTenantMember(ctx, connect.NewRequest(&identitypb.RemoveTenantMemberRequest{TenantId: mt.tenantID, UserId: userID})); err != nil {
		t.Fatalf("RemoveTenantMember: %v", err)
	}
	for name, signIn := range methods {
		if err := signIn(t); connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("%s once removed = %v, want FailedPrecondition", name, err)
		}
	}
}

// TestRedesign_ManagedAccounts_TotpSignInNeedsAnActiveMembership: a managed
// account with two-step sign-in passes its password step, and its code mints
// no session once its membership is suspended.
func TestRedesign_ManagedAccounts_TotpSignInNeedsAnActiveMembership(t *testing.T) {
	h := startRedesignHarnessWith(t, enableManagedSignIn)
	setProjectConfig(t, h, managedAccountsConfig)
	ctx := context.Background()
	mt := newManagedTenant(t, h, "managed-totp")
	userID, _ := setUpManagedAccount(t, h, mt, "lee")
	addr := "lee@" + mt.domain
	login, err := brandedClient(h, "").PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{Email: addr, Password: validPassword}))
	if err != nil {
		t.Fatalf("PasswordLogin: %v", err)
	}
	if got := decodeTokenClaims(t, login.Msg.GetAccessToken())["managed"]; got != true {
		t.Fatalf("managed claim = %#v, want the JSON boolean true", got)
	}
	authed := brandedClient(h, login.Msg.GetAccessToken())
	begin, err := authed.BeginTotpSetup(ctx, connect.NewRequest(&identitypb.BeginTotpSetupRequest{}))
	if err != nil {
		t.Fatalf("BeginTotpSetup: %v", err)
	}
	if _, err := authed.VerifyTotpSetup(ctx, connect.NewRequest(&identitypb.VerifyTotpSetupRequest{Code: generateTotpCodeAt(t, begin.Msg.GetSecret(), time.Now())})); err != nil {
		t.Fatalf("VerifyTotpSetup: %v", err)
	}
	if _, err := mt.owner.client.SuspendTenantMember(ctx, connect.NewRequest(&identitypb.SuspendTenantMemberRequest{TenantId: mt.tenantID, UserId: userID})); err != nil {
		t.Fatalf("SuspendTenantMember: %v", err)
	}
	challenge, err := brandedClient(h, "").PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{Email: addr, Password: validPassword}))
	if err != nil || !challenge.Msg.GetTotpRequired() {
		t.Fatalf("password step = %+v %v, want a two-step challenge", challenge, err)
	}
	_, err = brandedClient(h, "").VerifyTotp(ctx, connect.NewRequest(&identitypb.VerifyTotpRequest{
		LoginChallengeId: challenge.Msg.GetLoginChallengeId(), Code: begin.Msg.GetRecoveryCodes()[0],
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("two-step code while suspended = %v, want FailedPrecondition", err)
	}
}

// TestRedesign_ManagedAccounts_InvitedAfterResetSignsNothingIn: a managed
// account taken back to invited after it was set up, as a reset leaves it,
// holds no session by any method, nor by refreshing a session it had.
func TestRedesign_ManagedAccounts_InvitedAfterResetSignsNothingIn(t *testing.T) {
	h := startRedesignHarnessWith(t, enableManagedSignIn)
	setProjectConfig(t, h, managedAccountsConfig)
	mt := newManagedTenant(t, h, "managed-reset")
	userID, refreshToken := setUpManagedAccount(t, h, mt, "max")
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("GATEWAY_POSTGRES_DSN"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `UPDATE users SET status = 'invited' WHERE project_id = $1 AND id = $2`, h.ProjectID, userID); err != nil {
		t.Fatalf("take the account back: %v", err)
	}
	for name, signIn := range signInMethods(h, "max@"+mt.domain) {
		if err := signIn(t); err == nil {
			t.Fatalf("%s signed an invited managed account in", name)
		}
	}
	if _, err := refresh(h, refreshToken); err == nil {
		t.Fatal("a refresh signed an invited managed account in")
	}
}
