package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// testECKey is an ES256 (P-256) key + matching JWK set the Apple/OIDC
// tests use to sign and serve id_tokens.
type testECKey struct {
	Priv    *ecdsa.PrivateKey
	JWKSet  jwk.Set
	KID     string
	JWKJSON []byte
}

func newTestECKey(t *testing.T, kid string) *testECKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate: %v", err)
	}
	pubKey, err := jwk.FromRaw(priv.Public())
	if err != nil {
		t.Fatalf("jwk from raw: %v", err)
	}
	_ = pubKey.Set(jwk.KeyIDKey, kid)
	_ = pubKey.Set(jwk.AlgorithmKey, jwa.ES256)
	set := jwk.NewSet()
	if err := set.AddKey(pubKey); err != nil {
		t.Fatalf("add key: %v", err)
	}
	jwksJSON, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return &testECKey{Priv: priv, JWKSet: set, KID: kid, JWKJSON: jwksJSON}
}

func (k *testECKey) signIDToken(t *testing.T, claims map[string]any) string {
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
	signKey, err := jwk.FromRaw(k.Priv)
	if err != nil {
		t.Fatalf("priv jwk: %v", err)
	}
	_ = signKey.Set(jwk.KeyIDKey, k.KID)
	_ = signKey.Set(jwk.AlgorithmKey, jwa.ES256)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, signKey))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

// newTestApplePrivateKeyPEM returns a PKCS#8 PEM EC private key suitable
// for AppleConfig.PrivateKeyPEM.
func newTestApplePrivateKeyPEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func appleConfigFor(t *testing.T, fp *fakeProvider, key *testECKey, now time.Time) AppleConfig {
	t.Helper()
	return AppleConfig{
		ClientID:      "com.example.service",
		TeamID:        "TEAM123",
		KeyID:         "KEY123",
		PrivateKeyPEM: newTestApplePrivateKeyPEM(t),
		HTTPClient:    fp.srv.Client(),
		TokenURL:      fp.URL("/token"),
		JWKSURL:       fp.URL("/jwks"),
		Issuer:        appleIssuer,
		Now:           nowFunc(now),
	}
}

func TestApple_Exchange_HappyPath_NameFromContext(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := newTestECKey(t, "apple-kid")
	fp := newFakeProvider(t)
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)
	idToken := key.signIDToken(t, map[string]any{
		"iss":            appleIssuer,
		"sub":            "apple-sub-1",
		"aud":            "com.example.service",
		"email":          "User@Example.com",
		"email_verified": "true",
		"exp":            now.Add(time.Hour),
		"iat":            now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})

	ex := NewApple(appleConfigFor(t, fp, key, now))
	ctx := WithAppleName(context.Background(), "Ada Lovelace")
	id, err := ex.Exchange(ctx, "the-code", "https://app/cb")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if id.Provider != "apple" {
		t.Errorf("provider = %q", id.Provider)
	}
	if id.Email != "user@example.com" {
		t.Errorf("email = %q", id.Email)
	}
	if !id.EmailVerified {
		t.Errorf("email not verified")
	}
	if id.ProviderUserID != "apple-sub-1" {
		t.Errorf("sub = %q", id.ProviderUserID)
	}
	if id.Name != "Ada Lovelace" {
		t.Errorf("name = %q", id.Name)
	}
}

func TestApple_Exchange_EmailVerifiedBool(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := newTestECKey(t, "apple-kid")
	fp := newFakeProvider(t)
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)
	idToken := key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "com.example.service",
		"email": "a@b.com", "email_verified": true,
		"exp": now.Add(time.Hour), "iat": now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})

	ex := NewApple(appleConfigFor(t, fp, key, now))
	id, err := ex.Exchange(context.Background(), "c", "https://app/cb")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if !id.EmailVerified || id.Email != "a@b.com" {
		t.Errorf("got %+v", id)
	}
}

func TestApple_Exchange_RejectsUnverifiedEmail(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := newTestECKey(t, "apple-kid")
	fp := newFakeProvider(t)
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)
	idToken := key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "com.example.service",
		"email": "a@b.com", "email_verified": "false",
		"exp": now.Add(time.Hour), "iat": now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})

	ex := NewApple(appleConfigFor(t, fp, key, now))
	_, err := ex.Exchange(context.Background(), "c", "https://app/cb")
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got %v", err)
	}
}

func TestApple_Exchange_BadAudience(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := newTestECKey(t, "apple-kid")
	fp := newFakeProvider(t)
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)
	idToken := key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "someone-else",
		"email": "a@b.com", "email_verified": "true",
		"exp": now.Add(time.Hour), "iat": now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})

	ex := NewApple(appleConfigFor(t, fp, key, now))
	_, err := ex.Exchange(context.Background(), "c", "https://app/cb")
	if !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestApple_Exchange_RejectsRS256IDToken(t *testing.T) {
	// An attacker-supplied RS256 token must be rejected: Apple signs ES256.
	now := time.Unix(1_700_000_000, 0)
	ecKey := newTestECKey(t, "apple-kid")
	rsaKey := newTestKey(t, "apple-kid")
	fp := newFakeProvider(t)
	// Serve the EC JWKS but sign the token with RSA under the same kid.
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", ecKey.JWKJSON)
	idToken := rsaKey.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "com.example.service",
		"email": "a@b.com", "email_verified": "true",
		"exp": now.Add(time.Hour), "iat": now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})

	ex := NewApple(appleConfigFor(t, fp, ecKey, now))
	_, err := ex.Exchange(context.Background(), "c", "https://app/cb")
	if !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestApple_AuthorizationURL_FormPost(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := newTestECKey(t, "apple-kid")
	fp := newFakeProvider(t)
	ex := NewApple(appleConfigFor(t, fp, key, now)).(Authorizer)
	u, err := ex.AuthorizationURL(context.Background(), "https://app/cb", "state123", "challenge")
	if err != nil {
		t.Fatalf("auth url: %v", err)
	}
	if !strings.Contains(u, "response_mode=form_post") {
		t.Errorf("missing form_post: %s", u)
	}
	if !strings.Contains(u, "scope=openid+email+name") {
		t.Errorf("missing scopes: %s", u)
	}
}

func TestApple_NewApple_BadPrivateKey(t *testing.T) {
	ex := NewApple(AppleConfig{
		ClientID: "c", TeamID: "t", KeyID: "k", PrivateKeyPEM: "not-a-key",
	})
	_, err := ex.Exchange(context.Background(), "code", "https://app/cb")
	if !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

func TestApple_Exchange_TokenEndpointError(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := newTestECKey(t, "apple-kid")
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"error": "invalid_grant"})
	ex := NewApple(appleConfigFor(t, fp, key, now))
	_, err := ex.Exchange(context.Background(), "c", "https://app/cb")
	if !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

func TestAppleBoolString(t *testing.T) {
	cases := map[string]bool{`"true"`: true, `true`: true, `"false"`: false, `false`: false, `""`: false}
	for in, want := range cases {
		var b appleBoolString
		if err := b.UnmarshalJSON([]byte(in)); err != nil {
			t.Fatalf("unmarshal %q: %v", in, err)
		}
		if bool(b) != want {
			t.Errorf("%q => %v, want %v", in, bool(b), want)
		}
	}
	var b appleBoolString
	if err := b.UnmarshalJSON([]byte(`"maybe"`)); err == nil {
		t.Errorf("expected error for invalid bool")
	}
}
