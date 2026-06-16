package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
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
	id, err := ex.Exchange(context.Background(), "code", "https://app/cb")
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
	id, err := ex.Exchange(context.Background(), "code", "https://app/cb")
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
	_, err := ex.Exchange(context.Background(), "code", "https://app/cb")
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
	_, err := ex.Exchange(context.Background(), "code", "https://app/cb")
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
