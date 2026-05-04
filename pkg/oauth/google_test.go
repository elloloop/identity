package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGoogle_ExchangeSuccess(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-A")
	fp := newFakeProvider(t)

	const clientID = "google-client-id"

	idToken := key.signIDToken(t, map[string]any{
		"iss":            "https://accounts.test",
		"sub":            "google-sub-1",
		"aud":            clientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "Test User",
		"picture":        "https://pic/u.png",
	})

	fp.tokenHandler = jsonHandler(map[string]any{
		"id_token":     idToken,
		"access_token": "discardable",
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewGoogle(GoogleConfig{
		ClientID:     clientID,
		ClientSecret: "secret",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		Issuer:       "https://accounts.test",
		Now:          nowFunc(now),
	})

	id, err := exch.Exchange(context.Background(), "the-code", "https://app/cb")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Email != "user@example.com" {
		t.Errorf("email = %q", id.Email)
	}
	if id.ProviderUserID != "google-sub-1" {
		t.Errorf("provider id = %q", id.ProviderUserID)
	}
	if !id.EmailVerified {
		t.Error("email_verified must be true")
	}
	if id.Provider != "google" {
		t.Errorf("provider = %q", id.Provider)
	}
}

func TestGoogle_TokenEndpointError(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}
	exch := NewGoogle(GoogleConfig{
		ClientID:     "x",
		ClientSecret: "y",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
	})
	_, err := exch.Exchange(context.Background(), "bad", "https://x")
	if err == nil || !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

func TestGoogle_NetworkError(t *testing.T) {
	t.Parallel()
	exch := NewGoogle(GoogleConfig{
		ClientID:     "x",
		ClientSecret: "y",
		TokenURL:     "http://127.0.0.1:1/", // closed port
		JWKSURL:      "http://127.0.0.1:1/",
		HTTPClient:   &http.Client{Timeout: 50 * time.Millisecond},
	})
	_, err := exch.Exchange(context.Background(), "code", "https://x")
	if err == nil || !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

func TestGoogle_BadSignature(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)

	signing := newTestKey(t, "kid-attacker")
	servingJWKS := newTestKey(t, "kid-server") // a different keypair

	idToken := signing.signIDToken(t, map[string]any{
		"iss": "https://accounts.test",
		"sub": "victim",
		"aud": "client-id",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"email": "v@example.com",
		"email_verified": true,
	})

	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", servingJWKS.JWKJSON)

	exch := NewGoogle(GoogleConfig{
		ClientID:     "client-id",
		ClientSecret: "y",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		Issuer:       "https://accounts.test",
		Now:          nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), "code", "https://x")
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestGoogle_BadIssuer(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-A")
	fp := newFakeProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss":            "https://evil.example",
		"sub":            "x",
		"aud":            "client-id",
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "v@example.com",
		"email_verified": true,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewGoogle(GoogleConfig{
		ClientID:     "client-id",
		ClientSecret: "y",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		Issuer:       "https://accounts.test",
		Now:          nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), "code", "https://x")
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestGoogle_BadAudience(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-A")
	fp := newFakeProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss":            "https://accounts.test",
		"sub":            "x",
		"aud":            "different-audience",
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "v@example.com",
		"email_verified": true,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewGoogle(GoogleConfig{
		ClientID:     "client-id",
		ClientSecret: "y",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		Issuer:       "https://accounts.test",
		Now:          nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), "code", "https://x")
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestGoogle_ExpiredToken(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-A")
	fp := newFakeProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss":            "https://accounts.test",
		"sub":            "x",
		"aud":            "client-id",
		"iat":            now.Add(-2 * time.Hour).Unix(),
		"exp":            now.Add(-1 * time.Hour).Unix(),
		"email":          "v@example.com",
		"email_verified": true,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewGoogle(GoogleConfig{
		ClientID:     "client-id",
		ClientSecret: "y",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		Issuer:       "https://accounts.test",
		Now:          nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), "code", "https://x")
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Logf("unexpected error message: %v", err)
	}
}

func TestGoogle_EmailNotVerified(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-A")
	fp := newFakeProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss":            "https://accounts.test",
		"sub":            "x",
		"aud":            "client-id",
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "u@example.com",
		"email_verified": false,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewGoogle(GoogleConfig{
		ClientID:     "client-id",
		ClientSecret: "y",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		Issuer:       "https://accounts.test",
		Now:          nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), "code", "https://x")
	if err == nil || !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got %v", err)
	}
}

func TestGoogle_JWKSCaching(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-A")
	fp := newFakeProvider(t)
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	const clientID = "client-id"
	makeToken := func() string {
		return key.signIDToken(t, map[string]any{
			"iss":            "https://accounts.test",
			"sub":            "u",
			"aud":            clientID,
			"iat":            now.Unix(),
			"exp":            now.Add(5 * time.Minute).Unix(),
			"email":          "u@example.com",
			"email_verified": true,
		})
	}
	fp.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		jsonHandler(map[string]any{"id_token": makeToken()})(w, r)
	}

	exch := NewGoogle(GoogleConfig{
		ClientID:     clientID,
		ClientSecret: "y",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		Issuer:       "https://accounts.test",
		Now:          nowFunc(now),
		JWKSCacheTTL: time.Hour,
	})

	// Two successful exchanges should hit JWKS only once.
	for i := 0; i < 2; i++ {
		if _, err := exch.Exchange(context.Background(), "code", "https://x"); err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
	}
	if got := fp.jwksCalls.Load(); got != 1 {
		t.Errorf("jwks fetched %d times, want 1", got)
	}
}
