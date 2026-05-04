//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	"github.com/elloloop/identity/pkg/oauth"
)

// staticExchanger is an in-memory oauth.Exchanger that returns a
// canned Identity for any non-empty code, used so the integration
// test exercises the full Connect → service → registry path without
// standing up a real OIDC provider.
type staticExchanger struct {
	identity *oauth.Identity
	err      error
}

func (s *staticExchanger) Exchange(_ context.Context, code, _ string) (*oauth.Identity, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.identity, nil
}

// TestOAuthLogin_EndToEnd_GoogleStub verifies the full RPC path:
// OAuthLogin returns tokens, the access token is acceptable to
// GetCurrentUser, and the user is auto-provisioned with email_verified.
func TestOAuthLogin_EndToEnd_GoogleStub(t *testing.T) {
	t.Parallel()

	reg := oauth.NewRegistry()
	reg.Register("google", &staticExchanger{
		identity: &oauth.Identity{
			ProviderUserID: "google-sub-1",
			Email:          "alice@example.com",
			EmailVerified:  true,
			Name:           "Alice OAuth",
			AvatarURL:      "https://avatars/example/alice.png",
			Provider:       "google",
		},
	})

	h := StartServer(t, WithOAuthRegistry(reg))
	ctx := context.Background()

	resp, err := h.Client.OAuthLogin(ctx, connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        "code-from-google",
		Provider:    "google",
		RedirectUri: "https://app/callback",
	}))
	if err != nil {
		t.Fatalf("OAuthLogin: %v", err)
	}
	if resp.Msg.AccessToken == "" {
		t.Fatal("OAuthLogin returned empty access_token")
	}
	if resp.Msg.RefreshToken == "" {
		t.Fatal("OAuthLogin returned empty refresh_token")
	}
	if got := resp.Msg.GetUser().GetEmail(); got != "alice@example.com" {
		t.Errorf("user email = %q", got)
	}
	if !resp.Msg.GetUser().GetEmailVerified() {
		t.Error("user email_verified should be true")
	}

	// The minted access token should let us call GetCurrentUser.
	authed := h.AuthedClient(resp.Msg.AccessToken)
	cur, err := authed.GetCurrentUser(ctx, connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if got := cur.Msg.GetUser().GetEmail(); got != "alice@example.com" {
		t.Errorf("GetCurrentUser email = %q", got)
	}
}

// TestOAuthLogin_DisabledWithoutRegistry verifies the service rejects
// OAuth login when the harness is configured without any registry.
func TestOAuthLogin_DisabledWithoutRegistry(t *testing.T) {
	t.Parallel()
	h := StartServer(t) // no registry

	_, err := h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:     "x",
		Provider: "google",
	}))
	if err == nil {
		t.Fatal("expected error when oauth disabled")
	}
	var connErr *connect.Error
	if !errors.As(err, &connErr) {
		t.Fatalf("expected connect.Error, got %T", err)
	}
	if connErr.Code() != connect.CodeUnavailable {
		t.Errorf("code = %v, want Unavailable", connErr.Code())
	}
}

// TestOAuthLogin_UnknownProvider exercises the InvalidArgument path.
func TestOAuthLogin_UnknownProvider(t *testing.T) {
	t.Parallel()
	reg := oauth.NewRegistry()
	reg.Register("google", &staticExchanger{
		identity: &oauth.Identity{Email: "x@x", EmailVerified: true, Provider: "google"},
	})
	h := StartServer(t, WithOAuthRegistry(reg))

	_, err := h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:     "x",
		Provider: "yahoo",
	}))
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	var connErr *connect.Error
	if !errors.As(err, &connErr) {
		t.Fatalf("expected connect.Error, got %T", err)
	}
	if connErr.Code() != connect.CodeInvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", connErr.Code())
	}
}

// TestOAuthLogin_ExchangerErrorRejected verifies provider failures
// surface as Unauthenticated.
func TestOAuthLogin_ExchangerErrorRejected(t *testing.T) {
	t.Parallel()
	reg := oauth.NewRegistry()
	reg.Register("google", &staticExchanger{err: oauth.ErrCodeExchangeFailed})
	h := StartServer(t, WithOAuthRegistry(reg))

	_, err := h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:     "anything",
		Provider: "google",
	}))
	if err == nil {
		t.Fatal("expected error from failing exchanger")
	}
	var connErr *connect.Error
	if !errors.As(err, &connErr) {
		t.Fatalf("expected connect.Error, got %T", err)
	}
	if connErr.Code() != connect.CodeUnauthenticated {
		t.Errorf("code = %v, want Unauthenticated", connErr.Code())
	}
}
