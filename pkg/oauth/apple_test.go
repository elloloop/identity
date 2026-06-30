package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func generateTestECDSAKey(tb testing.TB) string {
	tb.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa generate: %v", err)
	}

	x509Encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		tb.Fatalf("failed to marshal ECDSA key: %v", err)
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509Encoded,
	})

	return string(pemEncoded)
}

func TestApple_ExchangeSuccess(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-A")
	fp := newFakeProvider(t)

	const clientID = "apple-client-id"
	privateKeyPEM := generateTestECDSAKey(t)

	idToken := key.signIDToken(t, map[string]any{
		"iss":            "https://appleid.apple.com",
		"sub":            "apple-sub-1",
		"aud":            clientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "user@example.com",
		"email_verified": true, // standard boolean
	})

	fp.tokenHandler = jsonHandler(map[string]any{
		"id_token":     idToken,
		"access_token": "discardable",
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewApple(AppleConfig{
		ClientID:   clientID,
		TeamID:     "team-123",
		KeyID:      "key-123",
		PrivateKey: privateKeyPEM,
		TokenURL:   fp.URL("/token"),
		JWKSURL:    fp.URL("/jwks"),
		Issuer:     "https://appleid.apple.com",
		Now:        nowFunc(now),
	})

	id, err := exch.Exchange(context.Background(), ExchangeParams{Code: "the-code", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Email != "user@example.com" {
		t.Errorf("email = %q", id.Email)
	}
	if id.ProviderUserID != "apple-sub-1" {
		t.Errorf("provider id = %q", id.ProviderUserID)
	}
	if !id.EmailVerified {
		t.Error("email_verified must be true")
	}
	if id.Provider != "apple" {
		t.Errorf("provider = %q", id.Provider)
	}
}

func TestApple_EmailVerifiedString(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-A")
	fp := newFakeProvider(t)

	const clientID = "apple-client-id"
	privateKeyPEM := generateTestECDSAKey(t)

	idToken := key.signIDToken(t, map[string]any{
		"iss":            "https://appleid.apple.com",
		"sub":            "apple-sub-1",
		"aud":            clientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "user@example.com",
		"email_verified": "true", // Apple string format
	})

	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewApple(AppleConfig{
		ClientID:   clientID,
		TeamID:     "team-123",
		KeyID:      "key-123",
		PrivateKey: privateKeyPEM,
		TokenURL:   fp.URL("/token"),
		JWKSURL:    fp.URL("/jwks"),
		Issuer:     "https://appleid.apple.com",
		Now:        nowFunc(now),
	})

	id, err := exch.Exchange(context.Background(), ExchangeParams{Code: "the-code", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !id.EmailVerified {
		t.Error("email_verified must be true")
	}
}

func TestApple_EmailNotVerifiedString(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-A")
	fp := newFakeProvider(t)

	const clientID = "apple-client-id"
	privateKeyPEM := generateTestECDSAKey(t)

	idToken := key.signIDToken(t, map[string]any{
		"iss":            "https://appleid.apple.com",
		"sub":            "apple-sub-1",
		"aud":            clientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "user@example.com",
		"email_verified": "false", // Apple string format
	})

	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewApple(AppleConfig{
		ClientID:   clientID,
		TeamID:     "team-123",
		KeyID:      "key-123",
		PrivateKey: privateKeyPEM,
		TokenURL:   fp.URL("/token"),
		JWKSURL:    fp.URL("/jwks"),
		Issuer:     "https://appleid.apple.com",
		Now:        nowFunc(now),
	})

	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "the-code", RedirectURI: "https://app/cb"})
	if err == nil || !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got %v", err)
	}
}

func TestApple_MissingEmail(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-A")
	fp := newFakeProvider(t)

	const clientID = "apple-client-id"
	privateKeyPEM := generateTestECDSAKey(t)

	idToken := key.signIDToken(t, map[string]any{
		"iss": "https://appleid.apple.com",
		"sub": "apple-sub-1",
		"aud": clientID,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		// no email or email_verified
	})

	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewApple(AppleConfig{
		ClientID:   clientID,
		TeamID:     "team-123",
		KeyID:      "key-123",
		PrivateKey: privateKeyPEM,
		TokenURL:   fp.URL("/token"),
		JWKSURL:    fp.URL("/jwks"),
		Issuer:     "https://appleid.apple.com",
		Now:        nowFunc(now),
	})

	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "the-code", RedirectURI: "https://app/cb"})
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestApple_TokenEndpointError(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}
	exch := NewApple(AppleConfig{
		ClientID:   "x",
		TeamID:     "team",
		KeyID:      "key",
		PrivateKey: generateTestECDSAKey(t),
		TokenURL:   fp.URL("/token"),
		JWKSURL:    fp.URL("/jwks"),
	})
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "bad", RedirectURI: "https://x"})
	if err == nil || !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

func TestApple_NetworkError(t *testing.T) {
	t.Parallel()
	exch := NewApple(AppleConfig{ //nolint:gosec // dummy config
		ClientID:   "x",
		TeamID:     "team",
		KeyID:      "key",
		PrivateKey: generateTestECDSAKey(t), //nolint:gosec // this is a dummy test key
		TokenURL:   "http://127.0.0.1:1/",   // closed port
		JWKSURL:    "http://127.0.0.1:1/",
		HTTPClient: &http.Client{Timeout: 50 * time.Millisecond},
	})
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err == nil || !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

func TestApple_BadPrivateKey(t *testing.T) {
	t.Parallel()
	exch := NewApple(AppleConfig{
		ClientID:   "x",
		TeamID:     "team",
		KeyID:      "key",
		PrivateKey: "invalid-pem", // will fail to sign secret
	})
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err == nil {
		t.Fatalf("expected error due to invalid private key")
	}
}

func TestApple_BadSignature(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)

	signing := newTestKey(t, "kid-attacker")
	servingJWKS := newTestKey(t, "kid-server") // a different keypair

	idToken := signing.signIDToken(t, map[string]any{
		"iss":            "https://appleid.apple.com",
		"sub":            "victim",
		"aud":            "client-id",
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "v@example.com",
		"email_verified": true,
	})

	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", servingJWKS.JWKJSON)

	exch := NewApple(AppleConfig{
		ClientID:   "client-id",
		TeamID:     "team",
		KeyID:      "key",
		PrivateKey: generateTestECDSAKey(t),
		TokenURL:   fp.URL("/token"),
		JWKSURL:    fp.URL("/jwks"),
		Issuer:     "https://appleid.apple.com",
		Now:        nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestApple_BadIssuer(t *testing.T) {
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

	exch := NewApple(AppleConfig{
		ClientID:   "client-id",
		TeamID:     "team",
		KeyID:      "key",
		PrivateKey: generateTestECDSAKey(t),
		TokenURL:   fp.URL("/token"),
		JWKSURL:    fp.URL("/jwks"),
		Issuer:     "https://appleid.apple.com",
		Now:        nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestApple_BadAudience(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-A")
	fp := newFakeProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss":            "https://appleid.apple.com",
		"sub":            "x",
		"aud":            "different-audience",
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "v@example.com",
		"email_verified": true,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewApple(AppleConfig{
		ClientID:   "client-id",
		TeamID:     "team",
		KeyID:      "key",
		PrivateKey: generateTestECDSAKey(t),
		TokenURL:   fp.URL("/token"),
		JWKSURL:    fp.URL("/jwks"),
		Issuer:     "https://appleid.apple.com",
		Now:        nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestApple_ExpiredToken(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-A")
	fp := newFakeProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss":            "https://appleid.apple.com",
		"sub":            "x",
		"aud":            "client-id",
		"iat":            now.Add(-2 * time.Hour).Unix(),
		"exp":            now.Add(-1 * time.Hour).Unix(),
		"email":          "v@example.com",
		"email_verified": true,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewApple(AppleConfig{
		ClientID:   "client-id",
		TeamID:     "team",
		KeyID:      "key",
		PrivateKey: generateTestECDSAKey(t),
		TokenURL:   fp.URL("/token"),
		JWKSURL:    fp.URL("/jwks"),
		Issuer:     "https://appleid.apple.com",
		Now:        nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Logf("unexpected error message: %v", err)
	}
}

func TestApple_JWKSCaching(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-A")
	fp := newFakeProvider(t)
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	const clientID = "client-id"
	makeToken := func() string {
		return key.signIDToken(t, map[string]any{
			"iss":            "https://appleid.apple.com",
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

	exch := NewApple(AppleConfig{
		ClientID:     clientID,
		TeamID:       "team",
		KeyID:        "key",
		PrivateKey:   generateTestECDSAKey(t),
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		Issuer:       "https://appleid.apple.com",
		Now:          nowFunc(now),
		JWKSCacheTTL: time.Hour,
	})

	for i := 0; i < 2; i++ {
		if _, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"}); err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
	}
	if got := fp.jwksCalls.Load(); got != 1 {
		t.Errorf("jwks fetched %d times, want 1", got)
	}
}

func TestApple_UserPayloadName(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-A")
	fp := newFakeProvider(t)

	const clientID = "apple-client-id"
	privateKeyPEM := generateTestECDSAKey(t)

	idToken := key.signIDToken(t, map[string]any{
		"iss":            "https://appleid.apple.com",
		"sub":            "apple-sub-1",
		"aud":            clientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "user@example.com",
		"email_verified": true,
	})

	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewApple(AppleConfig{
		ClientID:   clientID,
		TeamID:     "team-123",
		KeyID:      "key-123",
		PrivateKey: privateKeyPEM,
		TokenURL:   fp.URL("/token"),
		JWKSURL:    fp.URL("/jwks"),
		Issuer:     "https://appleid.apple.com",
		Now:        nowFunc(now),
	})

	ctx := context.Background()
	id, err := exch.Exchange(ctx, ExchangeParams{
		Code:             "the-code",
		RedirectURI:      "https://app/cb",
		AppleUserPayload: `{"name":{"firstName":"John","lastName":"Doe"}}`,
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Name != "John Doe" {
		t.Errorf("expected Name 'John Doe', got %q", id.Name)
	}
}
