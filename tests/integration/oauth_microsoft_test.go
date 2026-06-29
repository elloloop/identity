//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// Fidelity note: these tests drive the *real* Microsoft Exchanger
// (oauth.NewMicrosoft) against a mock token + JWKS HTTP endpoint —
// the same high-fidelity approach oauth_oidc_test.go uses for Google.
// The Microsoft provider exposes TokenURL/JWKSURL/IssuerFormat
// overrides, so the full Connect → service → provider → token-exchange
// → id_token-verification path runs end to end with no stubbed
// Exchanger. The only thing not exercised is the upstream redirect to
// login.microsoftonline.com: our mock token endpoint returns the signed
// id_token for any authorization code, since the code is opaque to the
// exchange and the redirect is the provider's concern, not identity's.

const (
	microsoftTestTenantID     = "11112222-3333-4444-5555-666677778888"
	microsoftTestIssuerFormat = "https://login.microsoft.test/%s/v2.0"
	microsoftTestClientID     = "ms-int-client-id"
	microsoftTestClientSecret = "ms-int-client-secret"
)

func microsoftTestIssuer(tenantID string) string {
	return "https://login.microsoft.test/" + tenantID + "/v2.0"
}

// msTestKey is an RSA key plus its matching JWK Set and kid, used to
// sign id_tokens and serve JWKS for the mock Microsoft endpoints.
type msTestKey struct {
	priv    *rsa.PrivateKey
	kid     string
	jwksRaw []byte
}

func msNewTestKey(t *testing.T, kid string) *msTestKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	pub, err := jwk.FromRaw(priv.Public())
	if err != nil {
		t.Fatalf("jwk from raw: %v", err)
	}
	if err := pub.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := pub.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatalf("add key: %v", err)
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return &msTestKey{priv: priv, kid: kid, jwksRaw: raw}
}

// signIDToken signs the given claims as an RS256 compact JWS, mapping
// the registered claim names so jwx encodes time/audience correctly.
func (k *msTestKey) signIDToken(t *testing.T, claims map[string]any) string {
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
	if err := signKey.Set(jwk.KeyIDKey, k.kid); err != nil {
		t.Fatalf("kid: %v", err)
	}
	if err := signKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("alg: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, signKey))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

// msFakeProvider stubs a Microsoft Azure AD token + JWKS endpoint.
// Its /token endpoint returns the configured id_token for any code.
type msFakeProvider struct {
	srv     *httptest.Server
	idToken string
	jwksRaw []byte
}

func msNewFakeProvider(t *testing.T, idToken string, jwksRaw []byte) *msFakeProvider {
	t.Helper()
	fp := &msFakeProvider{idToken: idToken, jwksRaw: jwksRaw}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token":     fp.idToken,
			"access_token": "ms-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fp.jwksRaw)
	})
	fp.srv = httptest.NewServer(mux)
	t.Cleanup(fp.srv.Close)
	return fp
}

func (fp *msFakeProvider) url(path string) string { return fp.srv.URL + path }

// microsoftRegistry registers the real Microsoft Exchanger pointed at
// the mock provider's token/JWKS endpoints and test issuer format.
func microsoftRegistry(fp *msFakeProvider) *oauth.Registry {
	reg := oauth.NewRegistry()
	reg.Register("microsoft", oauth.NewMicrosoft(oauth.MicrosoftConfig{
		ClientID:     microsoftTestClientID,
		ClientSecret: microsoftTestClientSecret,
		TenantID:     microsoftTestTenantID,
		TokenURL:     fp.url("/token"),
		JWKSURL:      fp.url("/jwks"),
		IssuerFormat: microsoftTestIssuerFormat,
	}))
	return reg
}

// microsoftBeginAndLogin runs the BeginOAuthLogin → OAuthLogin flow for
// the "microsoft" provider, threading the server-owned state/state-token
// through exactly as a real client would. The authorization code is
// opaque to the exchange, so any non-empty value works.
func microsoftBeginAndLogin(
	t *testing.T,
	h *Harness,
	redirectURI string,
) (*connect.Response[identitypb.OAuthLoginResponse], error) {
	t.Helper()
	begin, err := h.Client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "microsoft",
		RedirectUri: redirectURI,
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}
	return h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        "ms-auth-code",
		Provider:    "microsoft",
		RedirectUri: redirectURI,
		State:       begin.Msg.State,
		StateToken:  begin.Msg.StateToken,
	}))
}

// TestMicrosoftOAuth_HappyPath drives the real Microsoft provider end to
// end: a valid id_token (email + email-verified by issuance) auto-
// provisions the user, sets the email, marks it verified, and returns
// access + refresh tokens that authenticate GetCurrentUser.
func TestMicrosoftOAuth_HappyPath(t *testing.T) {
	t.Parallel()

	key := msNewTestKey(t, "ms-kid-happy")
	now := time.Now()
	idToken := key.signIDToken(t, map[string]any{
		"iss":                microsoftTestIssuer(microsoftTestTenantID),
		"sub":                "ms-sub-happy",
		"oid":                "ms-oid-happy",
		"tid":                microsoftTestTenantID,
		"aud":                microsoftTestClientID,
		"iat":                now.Unix(),
		"exp":                now.Add(5 * time.Minute).Unix(),
		"email":              "ms.alice@contoso.com",
		"preferred_username": "ms.alice@contoso.com",
		"name":               "MS Alice",
	})
	fp := msNewFakeProvider(t, idToken, key.jwksRaw)
	h := StartServer(t, WithOAuthRegistry(microsoftRegistry(fp)))

	resp, err := microsoftBeginAndLogin(t, h, "https://app.example.com/oauth/callback")
	if err != nil {
		t.Fatalf("OAuthLogin: %v", err)
	}
	if resp.Msg.AccessToken == "" {
		t.Fatal("OAuthLogin returned empty access_token")
	}
	if resp.Msg.RefreshToken == "" {
		t.Fatal("OAuthLogin returned empty refresh_token")
	}
	if got := resp.Msg.GetUser().GetEmail(); got != "ms.alice@contoso.com" {
		t.Fatalf("user email = %q, want ms.alice@contoso.com", got)
	}
	if got := resp.Msg.GetUser().GetName(); got != "MS Alice" {
		t.Fatalf("user name = %q, want MS Alice", got)
	}
	if !resp.Msg.GetUser().GetEmailVerified() {
		t.Fatal("user email_verified should be true")
	}

	cur, err := h.AuthedClient(resp.Msg.AccessToken).GetCurrentUser(
		context.Background(),
		connect.NewRequest(&identitypb.GetCurrentUserRequest{}),
	)
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if got := cur.Msg.GetUser().GetEmail(); got != "ms.alice@contoso.com" {
		t.Fatalf("GetCurrentUser email = %q, want ms.alice@contoso.com", got)
	}
}

// TestMicrosoftOAuth_UPNFallback mirrors microsoft_test.go's
// EmailFromUPNFallback at the integration layer: an id_token with no
// `email` claim but a `upn` derives the email from the UPN.
func TestMicrosoftOAuth_UPNFallback(t *testing.T) {
	t.Parallel()

	key := msNewTestKey(t, "ms-kid-upn")
	now := time.Now()
	idToken := key.signIDToken(t, map[string]any{
		"iss": microsoftTestIssuer(microsoftTestTenantID),
		"sub": "ms-sub-upn",
		"oid": "ms-oid-upn",
		"tid": microsoftTestTenantID,
		"aud": microsoftTestClientID,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		// No "email" claim; only a UPN.
		"upn":  "ms.bob@contoso.com",
		"name": "MS Bob",
	})
	fp := msNewFakeProvider(t, idToken, key.jwksRaw)
	h := StartServer(t, WithOAuthRegistry(microsoftRegistry(fp)))

	resp, err := microsoftBeginAndLogin(t, h, "https://app.example.com/oauth/callback")
	if err != nil {
		t.Fatalf("OAuthLogin: %v", err)
	}
	if got := resp.Msg.GetUser().GetEmail(); got != "ms.bob@contoso.com" {
		t.Fatalf("UPN-derived email = %q, want ms.bob@contoso.com", got)
	}
	if !resp.Msg.GetUser().GetEmailVerified() {
		t.Fatal("user email_verified should be true")
	}
}

// TestMicrosoftOAuth_TenantWiredFromConfig asserts the provider is wired
// for GATEWAY_MICROSOFT_TENANT_ID: with the config-built registry (no
// override), the authorization URL targets that tenant's authorize
// endpoint rather than the multi-tenant "common" endpoint.
func TestMicrosoftOAuth_TenantWiredFromConfig(t *testing.T) {
	t.Parallel()

	h := StartServer(t, WithConfig(func(cfg *config.Config) {
		cfg.MicrosoftClientID = microsoftTestClientID
		cfg.MicrosoftClientSecret = microsoftTestClientSecret
		cfg.MicrosoftTenantID = microsoftTestTenantID
	}))

	begin, err := h.Client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "microsoft",
		RedirectUri: "https://app.example.com/oauth/callback",
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}
	wantPath := "/" + microsoftTestTenantID + "/oauth2/v2.0/authorize"
	if !strings.Contains(begin.Msg.AuthorizationUrl, wantPath) {
		t.Fatalf("authorization URL %q does not target tenant path %q",
			begin.Msg.AuthorizationUrl, wantPath)
	}
	if strings.Contains(begin.Msg.AuthorizationUrl, "/common/oauth2") {
		t.Fatalf("authorization URL %q used the common endpoint despite configured tenant",
			begin.Msg.AuthorizationUrl)
	}
}

// TestMicrosoftOAuth_WrongIssuerRejected proves cross-tenant/issuer
// spoofing is rejected: an id_token whose `iss` does not match the
// issuer derived from its own `tid` claim is refused with Unauthenticated.
func TestMicrosoftOAuth_WrongIssuerRejected(t *testing.T) {
	t.Parallel()

	key := msNewTestKey(t, "ms-kid-badiss")
	now := time.Now()
	// tid claims our tenant, but iss belongs to a different tenant —
	// expectedIss = fmt.Sprintf(IssuerFormat, tid) won't match.
	idToken := key.signIDToken(t, map[string]any{
		"iss":                microsoftTestIssuer("99990000-aaaa-bbbb-cccc-ddddeeeeffff"),
		"sub":                "ms-sub-evil",
		"oid":                "ms-oid-evil",
		"tid":                microsoftTestTenantID,
		"aud":                microsoftTestClientID,
		"iat":                now.Unix(),
		"exp":                now.Add(5 * time.Minute).Unix(),
		"preferred_username": "ms.evil@contoso.com",
	})
	fp := msNewFakeProvider(t, idToken, key.jwksRaw)
	h := StartServer(t, WithOAuthRegistry(microsoftRegistry(fp)))

	_, err := microsoftBeginAndLogin(t, h, "https://app.example.com/oauth/callback")
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("OAuthLogin code = %v, want Unauthenticated (err=%v)", got, err)
	}
}

// TestMicrosoftOAuth_UnverifiedEmailRejected covers the verified_email=false
// path: the provider returns ErrEmailNotVerified, which the service maps to
// Unauthenticated, so no user is provisioned and no tokens are minted.
func TestMicrosoftOAuth_UnverifiedEmailRejected(t *testing.T) {
	t.Parallel()

	key := msNewTestKey(t, "ms-kid-unverified")
	now := time.Now()
	idToken := key.signIDToken(t, map[string]any{
		"iss":                microsoftTestIssuer(microsoftTestTenantID),
		"sub":                "ms-sub-unverified",
		"oid":                "ms-oid-unverified",
		"tid":                microsoftTestTenantID,
		"aud":                microsoftTestClientID,
		"iat":                now.Unix(),
		"exp":                now.Add(5 * time.Minute).Unix(),
		"preferred_username": "ms.carol@contoso.com",
		"verified_email":     false,
	})
	fp := msNewFakeProvider(t, idToken, key.jwksRaw)
	h := StartServer(t, WithOAuthRegistry(microsoftRegistry(fp)))

	_, err := microsoftBeginAndLogin(t, h, "https://app.example.com/oauth/callback")
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("OAuthLogin code = %v, want Unauthenticated (err=%v)", got, err)
	}
	if n := h.CountUsersByEmail(t, "ms.carol@contoso.com"); n != 0 {
		t.Fatalf("unverified login provisioned %d users, want 0", n)
	}
}
