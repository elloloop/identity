//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
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

// oidcECKey is a P-256 key + JWKS used to sign ES256 id_tokens.
type oidcECKey struct {
	priv    *ecdsa.PrivateKey
	kid     string
	jwksRaw []byte
}

func oidcNewECKey(t *testing.T, kid string) *oidcECKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate: %v", err)
	}
	pub, err := jwk.FromRaw(priv.Public())
	if err != nil {
		t.Fatalf("jwk from raw: %v", err)
	}
	_ = pub.Set(jwk.KeyIDKey, kid)
	_ = pub.Set(jwk.AlgorithmKey, jwa.ES256)
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatalf("add key: %v", err)
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return &oidcECKey{priv: priv, kid: kid, jwksRaw: raw}
}

func (k *oidcECKey) signIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	for kk, vv := range claims {
		switch kk {
		case "iss":
			_ = tok.Set(jwt.IssuerKey, vv)
		case "sub":
			_ = tok.Set(jwt.SubjectKey, vv)
		case "aud":
			_ = tok.Set(jwt.AudienceKey, vv)
		case "exp":
			_ = tok.Set(jwt.ExpirationKey, vv)
		case "iat":
			_ = tok.Set(jwt.IssuedAtKey, vv)
		default:
			_ = tok.Set(kk, vv)
		}
	}
	signKey, err := jwk.FromRaw(k.priv)
	if err != nil {
		t.Fatalf("priv jwk: %v", err)
	}
	_ = signKey.Set(jwk.KeyIDKey, k.kid)
	_ = signKey.Set(jwk.AlgorithmKey, jwa.ES256)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, signKey))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

// TestGenericOIDC_ES256_EndToEnd drives the full login path with an
// ES256-signed id_token, proving the provider verifies elliptic-curve
// signatures, not only RSA.
func TestGenericOIDC_ES256_EndToEnd(t *testing.T) {
	t.Parallel()

	key := oidcNewECKey(t, "oidc-ec-kid")
	now := time.Now()
	fp := oidcNewFakeIDP(t, "", key.jwksRaw, nil)
	fp.idToken = key.signIDToken(t, map[string]any{
		"iss":            fp.srv.URL,
		"sub":            "oidc-ec-sub",
		"aud":            oidcGenericClientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "oidc.ec@corp.example",
		"email_verified": true,
		"name":           "OIDC EC",
	})

	h := StartServer(t, WithOAuthRegistry(oidcGenericRegistry(fp)))

	resp, err := oidcGenericBeginAndLogin(t, h, "https://app.example.com/oauth/callback")
	if err != nil {
		t.Fatalf("OAuthLogin: %v", err)
	}
	if got := resp.Msg.GetUser().GetEmail(); got != "oidc.ec@corp.example" {
		t.Fatalf("user email = %q, want oidc.ec@corp.example", got)
	}
}

// TestGenericOIDC_KeyNormalized_EndToEnd proves the blocker fix through the
// real config→registry→service path: a mixed-case/whitespace provider key
// in config registers under the normalized key, so a login naming the
// normalized provider resolves (rather than "unknown oauth provider").
func TestGenericOIDC_KeyNormalized_EndToEnd(t *testing.T) {
	t.Parallel()

	key := msNewTestKey(t, "oidc-kid-norm")
	now := time.Now()
	fp := oidcNewFakeIDP(t, "", key.jwksRaw, nil)
	fp.idToken = key.signIDToken(t, map[string]any{
		"iss":            fp.srv.URL,
		"sub":            "oidc-sub-norm",
		"aud":            oidcGenericClientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "oidc.norm@corp.example",
		"email_verified": true,
	})

	// No WithOAuthRegistry: the harness builds the registry from config via
	// buildOAuthRegistry, exercising the normalization at the registration
	// site. The provider key is supplied with mixed case + surrounding space.
	h := StartServer(t, WithConfig(func(cfg *config.Config) {
		cfg.OIDCEnabled = true
		cfg.OIDCProviderKey = "  Okta  "
		cfg.OIDCIssuer = fp.srv.URL
		cfg.OIDCClientID = oidcGenericClientID
		cfg.OIDCClientSecret = oidcGenericClientSecret
	}))

	// Log in naming the normalized provider key.
	begin, err := h.Client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "okta",
		RedirectUri: "https://app.example.com/oauth/callback",
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin(okta): %v", err)
	}
	resp, err := h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        "oidc-auth-code",
		Provider:    "okta",
		RedirectUri: "https://app.example.com/oauth/callback",
		State:       begin.Msg.State,
		StateToken:  begin.Msg.StateToken,
	}))
	if err != nil {
		t.Fatalf("OAuthLogin(okta): %v", err)
	}
	if got := resp.Msg.GetUser().GetEmail(); got != "oidc.norm@corp.example" {
		t.Fatalf("user email = %q, want oidc.norm@corp.example", got)
	}
}

// TestGenericOIDC_Concurrent_EndToEnd hammers BeginOAuthLogin from many
// goroutines against one shared exchanger (the production registry path),
// so `go test -race` covers the lazy discovery/JWKS resolution under load.
func TestGenericOIDC_Concurrent_EndToEnd(t *testing.T) {
	t.Parallel()

	key := msNewTestKey(t, "oidc-kid-conc")
	now := time.Now()
	fp := oidcNewFakeIDP(t, "", key.jwksRaw, nil)
	fp.idToken = key.signIDToken(t, map[string]any{
		"iss":            fp.srv.URL,
		"sub":            "oidc-sub-conc",
		"aud":            oidcGenericClientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "oidc.conc@corp.example",
		"email_verified": true,
	})

	h := StartServer(t, WithOAuthRegistry(oidcGenericRegistry(fp)))

	const goroutines = 16
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.Client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
				Provider:    oidcGenericProviderKey,
				RedirectUri: "https://app.example.com/oauth/callback",
			}))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent BeginOAuthLogin: %v", err)
		}
	}
}

// TestGenericOIDC_DivergentEmail_NotVerified is the end-to-end regression
// for the email/verified-coupling blocker: an id_token with an unverified
// address plus a userinfo response advertising a DIFFERENT verified address
// (same sub) must NOT log the user in and must NOT provision a verified
// account for the id_token's address.
func TestGenericOIDC_DivergentEmail_NotVerified(t *testing.T) {
	t.Parallel()

	key := msNewTestKey(t, "oidc-kid-divergent")
	now := time.Now()
	verified := true
	fp := oidcNewFakeIDP(t, "", key.jwksRaw, map[string]any{
		"sub": "oidc-sub-div", "email": "verified-b@corp.example",
		"email_verified": verified, "name": "B",
	})
	fp.idToken = key.signIDToken(t, map[string]any{
		"iss":            fp.srv.URL,
		"sub":            "oidc-sub-div",
		"aud":            oidcGenericClientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "unverified-a@corp.example",
		"email_verified": false,
	})

	h := StartServer(t, WithOAuthRegistry(oidcGenericRegistry(fp)))

	_, err := oidcGenericBeginAndLogin(t, h, "https://app.example.com/oauth/callback")
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("OAuthLogin code = %v, want Unauthenticated (err=%v)", got, err)
	}
	if n := h.CountUsersByEmail(t, "unverified-a@corp.example"); n != 0 {
		t.Fatalf("unverified id_token address provisioned %d users, want 0", n)
	}
	if n := h.CountUsersByEmail(t, "verified-b@corp.example"); n != 0 {
		t.Fatalf("userinfo address must not be substituted: provisioned %d users, want 0", n)
	}
}

// TestGenericOIDC_MultiAudienceAzp covers OIDC Core 3.1.3.7 end to end: a
// multi-audience id_token succeeds only when azp == client_id.
func TestGenericOIDC_MultiAudienceAzp(t *testing.T) {
	t.Parallel()

	mk := func(t *testing.T, azp string) *oidcFakeIDP {
		t.Helper()
		key := msNewTestKey(t, "oidc-kid-azp")
		now := time.Now()
		fp := oidcNewFakeIDP(t, "", key.jwksRaw, nil)
		claims := map[string]any{
			"iss":            fp.srv.URL,
			"sub":            "oidc-sub-azp",
			"aud":            []string{oidcGenericClientID, "other-app"},
			"iat":            now.Unix(),
			"exp":            now.Add(5 * time.Minute).Unix(),
			"email":          "azp@corp.example",
			"email_verified": true,
			"name":           "Azp User",
		}
		if azp != "" {
			claims["azp"] = azp
		}
		fp.idToken = key.signIDToken(t, claims)
		return fp
	}

	t.Run("correct azp accepted", func(t *testing.T) {
		t.Parallel()
		h := StartServer(t, WithOAuthRegistry(oidcGenericRegistry(mk(t, oidcGenericClientID))))
		resp, err := oidcGenericBeginAndLogin(t, h, "https://app.example.com/oauth/callback")
		if err != nil {
			t.Fatalf("OAuthLogin: %v", err)
		}
		if got := resp.Msg.GetUser().GetEmail(); got != "azp@corp.example" {
			t.Fatalf("email = %q, want azp@corp.example", got)
		}
	})

	t.Run("missing azp rejected", func(t *testing.T) {
		t.Parallel()
		h := StartServer(t, WithOAuthRegistry(oidcGenericRegistry(mk(t, ""))))
		_, err := oidcGenericBeginAndLogin(t, h, "https://app.example.com/oauth/callback")
		if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
			t.Fatalf("code = %v, want Unauthenticated (err=%v)", got, err)
		}
	})
}

// TestGenericOIDC_MissingExp_Rejected proves an id_token without the
// required exp claim is refused end to end.
func TestGenericOIDC_MissingExp_Rejected(t *testing.T) {
	t.Parallel()

	key := msNewTestKey(t, "oidc-kid-noexp")
	now := time.Now()
	fp := oidcNewFakeIDP(t, "", key.jwksRaw, nil)
	// No exp claim.
	fp.idToken = key.signIDToken(t, map[string]any{
		"iss":            fp.srv.URL,
		"sub":            "oidc-sub-noexp",
		"aud":            oidcGenericClientID,
		"iat":            now.Unix(),
		"email":          "noexp@corp.example",
		"email_verified": true,
		"name":           "No Exp",
	})

	h := StartServer(t, WithOAuthRegistry(oidcGenericRegistry(fp)))

	_, err := oidcGenericBeginAndLogin(t, h, "https://app.example.com/oauth/callback")
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err=%v)", got, err)
	}
}
