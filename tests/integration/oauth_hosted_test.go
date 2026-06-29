//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/oauth"
)

// hostedStubProvider is both an Exchanger and an Authorizer, so it can
// drive the full hosted flow: AuthorizationURL echoes the state token
// back as the `state` query param (mirroring a real provider's
// behaviour), and Exchange returns a canned verified identity.
type hostedStubProvider struct {
	identity *oauth.Identity
}

func (p *hostedStubProvider) AuthorizationURL(_ context.Context, redirectURI, state, _ string) (string, error) {
	u, _ := url.Parse("https://accounts.example.com/authorize")
	q := u.Query()
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (p *hostedStubProvider) Exchange(_ context.Context, params oauth.ExchangeParams) (*oauth.Identity, error) {
	return p.identity, nil
}

// noRedirectClient returns the harness HTTP client configured to NOT
// follow redirects, so a test can inspect the 302 Location header.
func noRedirectClient(h *Harness) *http.Client {
	c := *h.HTTP
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &c
}

func newHostedRegistry() *oauth.Registry {
	reg := oauth.NewRegistry()
	reg.Register("google", &hostedStubProvider{
		identity: &oauth.Identity{
			ProviderUserID: "google-sub-hosted",
			Email:          "hosted@example.com",
			EmailVerified:  true,
			Name:           "Hosted User",
			Provider:       "google",
		},
	})
	return reg
}

// TestHostedOAuth_EndToEnd walks the entire hosted flow:
//
//	GET /oauth/start/google?return_to=... -> 302 to provider
//	GET /oauth/callback/google?state=&code= -> 302 to return_to?code=<otc>
//	RedeemOAuthCode{code} -> tokens
//	tokens authenticate GetCurrentUser
func TestHostedOAuth_EndToEnd(t *testing.T) {
	t.Parallel()

	const returnTo = "https://app.example.com/auth/finish"
	h := StartServer(
		t,
		WithOAuthRegistry(newHostedRegistry()),
		WithConfig(func(c *config.Config) { c.OAuthAllowedReturnURLs = "https://app.example.com/" }),
	)
	client := noRedirectClient(h)
	ctx := context.Background()

	// 1. Start: expect a 302 to the provider carrying the state token.
	startURL := h.BaseURL + "/oauth/start/google?return_to=" + url.QueryEscape(returnTo)
	startResp, err := client.Get(startURL)
	if err != nil {
		t.Fatalf("GET /oauth/start: %v", err)
	}
	startResp.Body.Close()
	if startResp.StatusCode != http.StatusFound {
		t.Fatalf("start status = %d, want 302", startResp.StatusCode)
	}
	authLoc, err := url.Parse(startResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse provider redirect: %v", err)
	}
	stateToken := authLoc.Query().Get("state")
	if stateToken == "" {
		t.Fatal("provider redirect carried no state token")
	}
	// The redirect_uri the provider sees must be the identity callback.
	if got := authLoc.Query().Get("redirect_uri"); !strings.HasSuffix(got, "/oauth/callback/google") {
		t.Fatalf("provider redirect_uri = %q, want .../oauth/callback/google", got)
	}

	// 2. Callback: provider redirects back with state + code. Expect a
	// 302 to return_to?code=<otc>.
	callbackURL := h.BaseURL + "/oauth/callback/google?state=" + url.QueryEscape(stateToken) + "&code=auth-code-xyz"
	req, err := http.NewRequest("GET", callbackURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	for _, c := range startResp.Cookies() {
		req.AddCookie(c)
	}
	cbResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /oauth/callback: %v", err)
	}
	cbResp.Body.Close()
	if cbResp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", cbResp.StatusCode)
	}
	redirect, err := url.Parse(cbResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse callback redirect: %v", err)
	}
	if !strings.HasPrefix(cbResp.Header.Get("Location"), returnTo) {
		t.Fatalf("callback redirect = %q, want prefix %q", cbResp.Header.Get("Location"), returnTo)
	}
	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatal("callback redirect carried no one-time code")
	}

	// 3. Redeem: the SPA exchanges the one-time code for tokens.
	redeem, err := h.Client.RedeemOAuthCode(ctx, connect.NewRequest(&identitypb.RedeemOAuthCodeRequest{Code: code}))
	if err != nil {
		t.Fatalf("RedeemOAuthCode: %v", err)
	}
	if redeem.Msg.AccessToken == "" || redeem.Msg.RefreshToken == "" {
		t.Fatal("redeem returned empty tokens")
	}
	if got := redeem.Msg.GetUser().GetEmail(); got != "hosted@example.com" {
		t.Errorf("user email = %q", got)
	}

	// 4. The minted access token authenticates GetCurrentUser.
	authed := h.AuthedClient(redeem.Msg.AccessToken)
	cur, err := authed.GetCurrentUser(ctx, connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if got := cur.Msg.GetUser().GetEmail(); got != "hosted@example.com" {
		t.Errorf("GetCurrentUser email = %q", got)
	}

	// 5. Replay: the one-time code is single-use.
	if _, err := h.Client.RedeemOAuthCode(ctx, connect.NewRequest(&identitypb.RedeemOAuthCodeRequest{Code: code})); err == nil {
		t.Fatal("second RedeemOAuthCode succeeded, want Unauthenticated")
	} else if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("replay redeem code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}

// TestHostedOAuth_ReturnToRejected verifies the fail-closed allowlist:
// a return_to outside GATEWAY_OAUTH_ALLOWED_RETURN_URLS is rejected at
// /oauth/start with 400, before any provider round-trip.
func TestHostedOAuth_ReturnToRejected(t *testing.T) {
	t.Parallel()

	h := StartServer(
		t,
		WithOAuthRegistry(newHostedRegistry()),
		WithConfig(func(c *config.Config) { c.OAuthAllowedReturnURLs = "https://app.example.com/" }),
	)
	client := noRedirectClient(h)

	resp, err := client.Get(h.BaseURL + "/oauth/start/google?return_to=" + url.QueryEscape("https://evil.example.net/steal"))
	if err != nil {
		t.Fatalf("GET /oauth/start: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("disallowed return_to status = %d, want 400", resp.StatusCode)
	}
}

// TestHostedOAuth_DisabledWhenAllowlistEmpty verifies that with no
// allowlist configured the hosted routes are not registered (404) while
// the headless RPC still works.
func TestHostedOAuth_DisabledWhenAllowlistEmpty(t *testing.T) {
	t.Parallel()

	h := StartServer(t, WithOAuthRegistry(newHostedRegistry()))
	client := noRedirectClient(h)

	resp, err := client.Get(h.BaseURL + "/oauth/start/google?return_to=https://app.example.com/")
	if err != nil {
		t.Fatalf("GET /oauth/start: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("hosted route status with empty allowlist = %d, want 404", resp.StatusCode)
	}

	// Headless OAuthLogin still works unchanged.
	out, err := h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        "code-x",
		Provider:    "google",
		RedirectUri: "https://app/callback",
	}))
	if err != nil {
		t.Fatalf("headless OAuthLogin: %v", err)
	}
	if out.Msg.AccessToken == "" {
		t.Fatal("headless OAuthLogin returned no token")
	}
}
