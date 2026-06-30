package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func oidcDiscoveryHandler(fp *fakeProvider) http.HandlerFunc {
	return jsonHandler(map[string]any{
		"issuer":                 fp.srv.URL,
		"authorization_endpoint": fp.URL("/authorize"),
		"token_endpoint":         fp.URL("/token"),
		"jwks_uri":               fp.URL("/jwks"),
		"userinfo_endpoint":      fp.URL("/userinfo"),
	})
}

func newGenericOIDCProvider(t *testing.T) (*fakeProvider, *testKey) {
	t.Helper()
	fp := newFakeProvider(t)
	key := newTestKey(t, "oidc-kid")
	fp.mux.HandleFunc("/.well-known/openid-configuration", oidcDiscoveryHandler(fp))
	fp.mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)
	return fp, key
}

func genericOIDCConfig(fp *fakeProvider, now time.Time) GenericOIDCConfig {
	return GenericOIDCConfig{
		ProviderKey:  "okta",
		IssuerURL:    fp.srv.URL,
		ClientID:     "client-1",
		ClientSecret: "secret-1",
		HTTPClient:   fp.srv.Client(),
		Now:          nowFunc(now),
	}
}

func TestGenericOIDC_Exchange_HappyPath(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fp, key := newGenericOIDCProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss": fp.srv.URL, "sub": "okta-sub", "aud": "client-1",
		"email": "Worker@Corp.com", "email_verified": true, "name": "Worker Bee",
		"exp": now.Add(time.Hour), "iat": now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})

	ex := NewOIDC(genericOIDCConfig(fp, now))
	id, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if id.Provider != "okta" || id.Email != "worker@corp.com" || id.Name != "Worker Bee" {
		t.Errorf("got %+v", id)
	}
	if id.ProviderUserID != "okta-sub" || !id.EmailVerified {
		t.Errorf("got %+v", id)
	}
}

func TestGenericOIDC_Exchange_EmailVerifiedFromUserinfo(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fp, key := newGenericOIDCProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss": fp.srv.URL, "sub": "s", "aud": "client-1",
		"exp": now.Add(time.Hour), "iat": now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken, "access_token": "at"})
	verified := true
	fp.mux.HandleFunc("/userinfo", jsonHandler(oidcUserInfo{
		Sub: "s", Email: "u@corp.com", EmailVerified: &verified, Name: "U",
	}))

	ex := NewOIDC(genericOIDCConfig(fp, now))
	id, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if id.Email != "u@corp.com" || !id.EmailVerified || id.Name != "U" {
		t.Errorf("got %+v", id)
	}
}

func TestGenericOIDC_Exchange_RejectsUnverifiedEmail(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fp, key := newGenericOIDCProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss": fp.srv.URL, "sub": "s", "aud": "client-1",
		"email": "u@corp.com", "email_verified": false,
		"exp": now.Add(time.Hour), "iat": now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})

	ex := NewOIDC(genericOIDCConfig(fp, now))
	_, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"})
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got %v", err)
	}
}

func TestGenericOIDC_Exchange_MissingDiscovery(t *testing.T) {
	// Discovery endpoint returns 404 → ErrCodeExchangeFailed.
	fp := newFakeProvider(t)
	cfg := GenericOIDCConfig{
		ProviderKey:  "okta",
		DiscoveryURL: fp.URL("/.well-known/openid-configuration"),
		ClientID:     "client-1",
		ClientSecret: "secret-1",
		HTTPClient:   fp.srv.Client(),
		Now:          nowFunc(time.Now()),
	}
	ex := NewOIDC(cfg)
	_, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"})
	if !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

func TestGenericOIDC_AuthorizationURL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fp, _ := newGenericOIDCProvider(t)
	ex := NewOIDC(GenericOIDCConfig{
		ProviderKey:  "okta",
		IssuerURL:    fp.srv.URL,
		ClientID:     "client-1",
		ClientSecret: "secret-1",
		Scopes:       []string{"email", "profile", "groups"},
		HTTPClient:   fp.srv.Client(),
		Now:          nowFunc(now),
	}).(Authorizer)
	u, err := ex.AuthorizationURL(context.Background(), "https://app/cb", "state", "challenge")
	if err != nil {
		t.Fatalf("auth url: %v", err)
	}
	if !strings.Contains(u, "/authorize") {
		t.Errorf("wrong endpoint: %s", u)
	}
	if !strings.Contains(u, "openid") {
		t.Errorf("openid scope not ensured: %s", u)
	}
}

func TestGenericOIDC_AuthorizationURL_NoClientID(t *testing.T) {
	ex := NewOIDC(GenericOIDCConfig{ProviderKey: "okta", DiscoveryURL: "https://x/disco"}).(Authorizer)
	if _, err := ex.AuthorizationURL(context.Background(), "https://app/cb", "s", "c"); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

func TestGenericOIDC_Exchange_MissingCodeAndCreds(t *testing.T) {
	ex := NewOIDC(GenericOIDCConfig{ProviderKey: "okta", IssuerURL: "https://x", ClientID: "c", ClientSecret: "s"})
	if _, err := ex.Exchange(context.Background(), ExchangeParams{RedirectURI: "https://app/cb"}); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("missing code: want ErrCodeExchangeFailed, got %v", err)
	}
	exNoCreds := NewOIDC(GenericOIDCConfig{ProviderKey: "okta", IssuerURL: "https://x"})
	if _, err := exNoCreds.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"}); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("missing creds: want ErrCodeExchangeFailed, got %v", err)
	}
}

func TestGenericOIDC_Exchange_ProviderTokenError(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fp, _ := newGenericOIDCProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"error": "invalid_grant"})
	ex := NewOIDC(genericOIDCConfig(fp, now))
	if _, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"}); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

func TestGenericOIDC_Exchange_NoIDToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fp, _ := newGenericOIDCProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"access_token": "at"})
	ex := NewOIDC(genericOIDCConfig(fp, now))
	if _, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"}); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

func TestGenericOIDC_Exchange_BadSignature(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fp, _ := newGenericOIDCProvider(t)
	// Sign with a different key that reuses the served kid so kid lookup
	// succeeds but signature verification fails.
	attacker := newTestKey(t, "oidc-kid")
	idToken := attacker.signIDToken(t, map[string]any{
		"iss": fp.srv.URL, "sub": "s", "aud": "client-1",
		"email": "e@corp.com", "email_verified": true,
		"exp": now.Add(time.Hour), "iat": now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	ex := NewOIDC(genericOIDCConfig(fp, now))
	if _, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"}); !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestGenericOIDC_Exchange_ClaimRejections(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cases := map[string]map[string]any{
		"bad issuer":   {"iss": "https://evil", "sub": "s", "aud": "client-1", "email": "e@c.com", "email_verified": true, "exp": now.Add(time.Hour), "iat": now},
		"bad audience": {"iss": "ISSUER", "sub": "s", "aud": "other", "email": "e@c.com", "email_verified": true, "exp": now.Add(time.Hour), "iat": now},
		"expired":      {"iss": "ISSUER", "sub": "s", "aud": "client-1", "email": "e@c.com", "email_verified": true, "exp": now.Add(-time.Hour), "iat": now.Add(-2 * time.Hour)},
		"missing sub":  {"iss": "ISSUER", "aud": "client-1", "email": "e@c.com", "email_verified": true, "exp": now.Add(time.Hour), "iat": now},
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			fp, key := newGenericOIDCProvider(t)
			if claims["iss"] == "ISSUER" {
				claims["iss"] = fp.srv.URL
			}
			idToken := key.signIDToken(t, claims)
			fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
			ex := NewOIDC(genericOIDCConfig(fp, now))
			if _, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"}); !errors.Is(err, ErrIdentityVerification) {
				t.Fatalf("want ErrIdentityVerification, got %v", err)
			}
		})
	}
}

func TestGenericOIDC_Exchange_MissingEmail(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fp, key := newGenericOIDCProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss": fp.srv.URL, "sub": "s", "aud": "client-1",
		"email_verified": true, "exp": now.Add(time.Hour), "iat": now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	ex := NewOIDC(genericOIDCConfig(fp, now))
	if _, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"}); !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestGenericOIDC_ProviderKeyDefaultsToOIDC(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fp, key := newGenericOIDCProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss": fp.srv.URL, "sub": "s", "aud": "client-1",
		"email": "e@corp.com", "email_verified": true,
		"exp": now.Add(time.Hour), "iat": now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	// No ProviderKey set → defaults to "oidc".
	ex := NewOIDC(GenericOIDCConfig{
		IssuerURL:    fp.srv.URL,
		ClientID:     "client-1",
		ClientSecret: "secret-1",
		HTTPClient:   fp.srv.Client(),
		Now:          nowFunc(now),
	})
	id, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if id.Provider != "oidc" {
		t.Errorf("default provider key = %q, want oidc", id.Provider)
	}
}

// ecTestKey is a P-256 key plus its matching JWK Set, used to sign
// ES256 id_tokens and serve an EC JWKS.
type ecTestKey struct {
	priv    *ecdsa.PrivateKey
	kid     string
	jwksRaw []byte
}

func newECTestKey(t *testing.T, kid string) *ecTestKey {
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
	return &ecTestKey{priv: priv, kid: kid, jwksRaw: raw}
}

func (k *ecTestKey) signIDToken(t *testing.T, claims map[string]any) string {
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

// TestGenericOIDC_Exchange_ES256 proves the provider accepts an
// ES256-signed id_token (not only RS256), exercising the broadened
// asymmetric-algorithm allow-list.
func TestGenericOIDC_Exchange_ES256(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fp := newFakeProvider(t)
	key := newECTestKey(t, "oidc-ec-kid")
	fp.mux.HandleFunc("/.well-known/openid-configuration", oidcDiscoveryHandler(fp))
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.jwksRaw)
	idToken := key.signIDToken(t, map[string]any{
		"iss": fp.srv.URL, "sub": "ec-sub", "aud": "client-1",
		"email": "ec@corp.com", "email_verified": true, "name": "EC User",
		"exp": now.Add(time.Hour), "iat": now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})

	ex := NewOIDC(genericOIDCConfig(fp, now))
	id, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("ES256 exchange: %v", err)
	}
	if id.Email != "ec@corp.com" || id.ProviderUserID != "ec-sub" || !id.EmailVerified {
		t.Errorf("got %+v", id)
	}
}

// TestGenericOIDC_Exchange_Concurrent runs many Exchange calls against a
// single shared exchanger so `go test -race` covers the lazy
// discovery/JWKS initialization for data races.
func TestGenericOIDC_Exchange_Concurrent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fp, key := newGenericOIDCProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss": fp.srv.URL, "sub": "s", "aud": "client-1",
		"email": "e@corp.com", "email_verified": true,
		"exp": now.Add(time.Hour), "iat": now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})

	ex := NewOIDC(genericOIDCConfig(fp, now))
	const goroutines = 24
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent exchange: %v", err)
		}
	}
}

// TestGenericOIDC_DiscoveryCached asserts the discovery document is
// fetched once and reused across AuthorizationURL + repeated Exchange
// calls (within the cache TTL).
func TestGenericOIDC_DiscoveryCached(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fp := newFakeProvider(t)
	key := newTestKey(t, "oidc-kid")
	var discoveryCalls atomic.Int32
	disco := oidcDiscoveryHandler(fp)
	fp.mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discoveryCalls.Add(1)
		disco(w, r)
	})
	fp.mux.HandleFunc("/authorize", func(http.ResponseWriter, *http.Request) {})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)
	idToken := key.signIDToken(t, map[string]any{
		"iss": fp.srv.URL, "sub": "s", "aud": "client-1",
		"email": "e@corp.com", "email_verified": true,
		"exp": now.Add(time.Hour), "iat": now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})

	ex := NewOIDC(genericOIDCConfig(fp, now))
	if _, err := ex.(Authorizer).AuthorizationURL(context.Background(), "https://app/cb", "state", "challenge"); err != nil {
		t.Fatalf("auth url: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"}); err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
	}
	if n := discoveryCalls.Load(); n != 1 {
		t.Errorf("discovery fetched %d times, want 1 (cached)", n)
	}
}

// TestGenericOIDC_Exchange_UserinfoSubMismatch enforces OIDC Core 5.3.2:
// a userinfo response whose sub differs from the id_token sub is rejected.
func TestGenericOIDC_Exchange_UserinfoSubMismatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fp, key := newGenericOIDCProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss": fp.srv.URL, "sub": "real-sub", "aud": "client-1",
		"exp": now.Add(time.Hour), "iat": now,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken, "access_token": "at"})
	verified := true
	fp.mux.HandleFunc("/userinfo", jsonHandler(oidcUserInfo{
		Sub: "other-sub", Email: "e@corp.com", EmailVerified: &verified,
	}))

	ex := NewOIDC(genericOIDCConfig(fp, now))
	if _, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"}); !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

// TestGenericOIDC_DiscoveryIssuerMismatch enforces OIDC Discovery 4.3:
// a discovery document whose issuer differs from the configured issuer is
// rejected before any token exchange.
func TestGenericOIDC_DiscoveryIssuerMismatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fp := newFakeProvider(t)
	key := newTestKey(t, "oidc-kid")
	fp.mux.HandleFunc("/.well-known/openid-configuration", jsonHandler(map[string]any{
		"issuer":                 "https://impostor.example",
		"authorization_endpoint": fp.URL("/authorize"),
		"token_endpoint":         fp.URL("/token"),
		"jwks_uri":               fp.URL("/jwks"),
		"userinfo_endpoint":      fp.URL("/userinfo"),
	}))
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": "x"})

	ex := NewOIDC(genericOIDCConfig(fp, now))
	if _, err := ex.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"}); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}
