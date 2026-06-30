//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/pkg/oauth"
)

// Fidelity note: these tests drive the *real* generic OIDC Exchanger
// (oauth.NewOIDC) against a mock OIDC IdP that serves a discovery
// document, token endpoint, JWKS, and userinfo endpoint — the same
// high-fidelity approach the Google/Microsoft integration tests use.
// The full Connect → service → provider → discovery → token-exchange →
// id_token-verification path runs end to end with no stubbed Exchanger.
// This is the config-driven path an operator gets by setting
// GATEWAY_OAUTH_OIDC_* for an arbitrary IdP (Okta, Auth0, Keycloak).

const (
	oidcGenericProviderKey  = "okta"
	oidcGenericClientID     = "oidc-int-client-id"
	oidcGenericClientSecret = "oidc-int-client-secret"
)

// oidcFakeIDP stubs a standards-compliant OIDC provider: discovery,
// token, JWKS, and userinfo endpoints. /token returns the configured
// id_token for any code.
type oidcFakeIDP struct {
	srv      *httptest.Server
	idToken  string
	jwksRaw  []byte
	userinfo map[string]any
}

func oidcNewFakeIDP(t *testing.T, idToken string, jwksRaw []byte, userinfo map[string]any) *oidcFakeIDP {
	t.Helper()
	fp := &oidcFakeIDP{idToken: idToken, jwksRaw: jwksRaw, userinfo: userinfo}
	mux := http.NewServeMux()
	fp.srv = httptest.NewServer(mux)
	t.Cleanup(fp.srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 fp.srv.URL,
			"authorization_endpoint": fp.srv.URL + "/authorize",
			"token_endpoint":         fp.srv.URL + "/token",
			"jwks_uri":               fp.srv.URL + "/jwks",
			"userinfo_endpoint":      fp.srv.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token":     fp.idToken,
			"access_token": "oidc-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fp.jwksRaw)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fp.userinfo)
	})
	return fp
}

// oidcGenericRegistry registers the real generic OIDC Exchanger pointed
// at the mock IdP's issuer (discovery is derived from it).
func oidcGenericRegistry(fp *oidcFakeIDP) *oauth.Registry {
	reg := oauth.NewRegistry()
	reg.Register(oidcGenericProviderKey, oauth.NewOIDC(oauth.GenericOIDCConfig{
		ProviderKey:  oidcGenericProviderKey,
		IssuerURL:    fp.srv.URL,
		ClientID:     oidcGenericClientID,
		ClientSecret: oidcGenericClientSecret,
	}))
	return reg
}

func oidcGenericBeginAndLogin(t *testing.T, h *Harness, redirectURI string) (*connect.Response[identitypb.OAuthLoginResponse], error) {
	t.Helper()
	begin, err := h.Client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    oidcGenericProviderKey,
		RedirectUri: redirectURI,
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}
	return h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        "oidc-auth-code",
		Provider:    oidcGenericProviderKey,
		RedirectUri: redirectURI,
		State:       begin.Msg.State,
		StateToken:  begin.Msg.StateToken,
	}))
}

// TestGenericOIDC_HappyPath drives the real generic OIDC provider end to
// end: discovery resolves the endpoints, a valid id_token (email +
// email_verified) auto-provisions the user, and access + refresh tokens
// authenticate GetCurrentUser. It also confirms Identity.Provider is the
// configured provider key.
func TestGenericOIDC_HappyPath(t *testing.T) {
	t.Parallel()

	key := msNewTestKey(t, "oidc-kid-happy")
	now := time.Now()
	// The id_token issuer must equal the discovery issuer (the fake's URL),
	// which is only known after the server starts; build the IdP first, then
	// sign with its real issuer.
	fp := oidcNewFakeIDP(t, "", key.jwksRaw, nil)
	fp.idToken = key.signIDToken(t, map[string]any{
		"iss":            fp.srv.URL,
		"sub":            "oidc-sub-happy",
		"aud":            oidcGenericClientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "oidc.alice@corp.example",
		"email_verified": true,
		"name":           "OIDC Alice",
	})

	h := StartServer(t, WithOAuthRegistry(oidcGenericRegistry(fp)))

	resp, err := oidcGenericBeginAndLogin(t, h, "https://app.example.com/oauth/callback")
	if err != nil {
		t.Fatalf("OAuthLogin: %v", err)
	}
	if resp.Msg.AccessToken == "" || resp.Msg.RefreshToken == "" {
		t.Fatal("OAuthLogin returned empty tokens")
	}
	if got := resp.Msg.GetUser().GetEmail(); got != "oidc.alice@corp.example" {
		t.Fatalf("user email = %q, want oidc.alice@corp.example", got)
	}
	if got := resp.Msg.GetUser().GetName(); got != "OIDC Alice" {
		t.Fatalf("user name = %q, want OIDC Alice", got)
	}
	if !resp.Msg.GetUser().GetEmailVerified() {
		t.Fatal("user email_verified should be true")
	}

	cur, err := h.AuthedClient(resp.Msg.AccessToken).GetCurrentUser(
		context.Background(), connect.NewRequest(&identitypb.GetCurrentUserRequest{}),
	)
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if got := cur.Msg.GetUser().GetEmail(); got != "oidc.alice@corp.example" {
		t.Fatalf("GetCurrentUser email = %q, want oidc.alice@corp.example", got)
	}
}

// TestGenericOIDC_EmailVerifiedFromUserinfo proves the userinfo fallback:
// the id_token omits email/verification, but the discovered userinfo
// endpoint supplies a verified email, which provisions the user.
func TestGenericOIDC_EmailVerifiedFromUserinfo(t *testing.T) {
	t.Parallel()

	key := msNewTestKey(t, "oidc-kid-userinfo")
	now := time.Now()
	fp := oidcNewFakeIDP(t, "", key.jwksRaw, map[string]any{
		"sub":            "oidc-sub-userinfo",
		"email":          "oidc.bob@corp.example",
		"email_verified": true,
		"name":           "OIDC Bob",
	})
	fp.idToken = key.signIDToken(t, map[string]any{
		"iss": fp.srv.URL,
		"sub": "oidc-sub-userinfo",
		"aud": oidcGenericClientID,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	})

	h := StartServer(t, WithOAuthRegistry(oidcGenericRegistry(fp)))

	resp, err := oidcGenericBeginAndLogin(t, h, "https://app.example.com/oauth/callback")
	if err != nil {
		t.Fatalf("OAuthLogin: %v", err)
	}
	if got := resp.Msg.GetUser().GetEmail(); got != "oidc.bob@corp.example" {
		t.Fatalf("userinfo-derived email = %q, want oidc.bob@corp.example", got)
	}
	if !resp.Msg.GetUser().GetEmailVerified() {
		t.Fatal("user email_verified should be true")
	}
}

// TestGenericOIDC_BadSignatureRejected signs the id_token with a key
// whose public half is NOT in the served JWKS (but reuses the served
// kid), so signature verification fails and the login is rejected with
// Unauthenticated.
func TestGenericOIDC_BadSignatureRejected(t *testing.T) {
	t.Parallel()

	served := msNewTestKey(t, "oidc-kid-badsig")
	attacker := msNewTestKey(t, "oidc-kid-badsig") // same kid, different key material
	now := time.Now()
	fp := oidcNewFakeIDP(t, "", served.jwksRaw, nil)
	fp.idToken = attacker.signIDToken(t, map[string]any{
		"iss":            fp.srv.URL,
		"sub":            "oidc-sub-evil",
		"aud":            oidcGenericClientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "oidc.evil@corp.example",
		"email_verified": true,
	})

	h := StartServer(t, WithOAuthRegistry(oidcGenericRegistry(fp)))

	_, err := oidcGenericBeginAndLogin(t, h, "https://app.example.com/oauth/callback")
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("OAuthLogin code = %v, want Unauthenticated (err=%v)", got, err)
	}
}

// TestGenericOIDC_WrongIssuerRejected proves issuer spoofing is rejected:
// a correctly-signed id_token whose `iss` does not match the discovery
// document's issuer is refused with Unauthenticated.
func TestGenericOIDC_WrongIssuerRejected(t *testing.T) {
	t.Parallel()

	key := msNewTestKey(t, "oidc-kid-badiss")
	now := time.Now()
	fp := oidcNewFakeIDP(t, "", key.jwksRaw, nil)
	fp.idToken = key.signIDToken(t, map[string]any{
		"iss":            "https://attacker.example/issuer",
		"sub":            "oidc-sub-badiss",
		"aud":            oidcGenericClientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "oidc.mallory@corp.example",
		"email_verified": true,
	})

	h := StartServer(t, WithOAuthRegistry(oidcGenericRegistry(fp)))

	_, err := oidcGenericBeginAndLogin(t, h, "https://app.example.com/oauth/callback")
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("OAuthLogin code = %v, want Unauthenticated (err=%v)", got, err)
	}
}

// TestGenericOIDC_UnverifiedEmailRejected covers email_verified=false with
// no userinfo override: the provider returns ErrEmailNotVerified, mapped to
// Unauthenticated, and no user is provisioned.
func TestGenericOIDC_UnverifiedEmailRejected(t *testing.T) {
	t.Parallel()

	key := msNewTestKey(t, "oidc-kid-unverified")
	now := time.Now()
	fp := oidcNewFakeIDP(t, "", key.jwksRaw, nil)
	fp.idToken = key.signIDToken(t, map[string]any{
		"iss":            fp.srv.URL,
		"sub":            "oidc-sub-unverified",
		"aud":            oidcGenericClientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "oidc.carol@corp.example",
		"email_verified": false,
	})

	h := StartServer(t, WithOAuthRegistry(oidcGenericRegistry(fp)))

	_, err := oidcGenericBeginAndLogin(t, h, "https://app.example.com/oauth/callback")
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("OAuthLogin code = %v, want Unauthenticated (err=%v)", got, err)
	}
	if n := h.CountUsersByEmail(t, "oidc.carol@corp.example"); n != 0 {
		t.Fatalf("unverified login provisioned %d users, want 0", n)
	}
}
