package oauth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

const msTenantID = "tenant-uuid"

func msIssuer() string {
	return "https://login.test/" + msTenantID + "/v2.0"
}

func TestMicrosoft_ExchangeSuccess(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-MS")
	fp := newFakeProvider(t)

	const clientID = "ms-client-id"
	idToken := key.signIDToken(t, map[string]any{
		"iss":                msIssuer(),
		"sub":                "ms-sub-1",
		"oid":                "ms-oid-1",
		"tid":                msTenantID,
		"aud":                clientID,
		"iat":                now.Unix(),
		"exp":                now.Add(5 * time.Minute).Unix(),
		"preferred_username": "alice@contoso.com",
		"name":               "Alice",
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewMicrosoft(MicrosoftConfig{
		ClientID:     clientID,
		ClientSecret: "secret",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		IssuerFormat: "https://login.test/%s/v2.0",
		Now:          nowFunc(now),
	})
	id, err := exch.Exchange(context.Background(), "code", "https://app/cb")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Email != "alice@contoso.com" {
		t.Errorf("email = %q", id.Email)
	}
	if id.ProviderUserID != "ms-oid-1" {
		t.Errorf("provider id = %q", id.ProviderUserID)
	}
	if id.Provider != "microsoft" {
		t.Errorf("provider = %q", id.Provider)
	}
}

func TestMicrosoft_EmailFromUPNFallback(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-MS")
	fp := newFakeProvider(t)

	const clientID = "ms-client-id"
	idToken := key.signIDToken(t, map[string]any{
		"iss": msIssuer(),
		"sub": "s",
		"oid": "o",
		"tid": msTenantID,
		"aud": clientID,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"upn": "bob@contoso.com",
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewMicrosoft(MicrosoftConfig{
		ClientID:     clientID,
		ClientSecret: "x",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		IssuerFormat: "https://login.test/%s/v2.0",
		Now:          nowFunc(now),
	})
	id, err := exch.Exchange(context.Background(), "code", "https://x")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Email != "bob@contoso.com" {
		t.Errorf("email = %q", id.Email)
	}
}

func TestMicrosoft_BadIssuer(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-MS")
	fp := newFakeProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss":                "https://evil/v2.0",
		"sub":                "s",
		"oid":                "o",
		"tid":                msTenantID,
		"aud":                "client-id",
		"iat":                now.Unix(),
		"exp":                now.Add(5 * time.Minute).Unix(),
		"preferred_username": "u@x",
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewMicrosoft(MicrosoftConfig{
		ClientID:     "client-id",
		ClientSecret: "x",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		IssuerFormat: "https://login.test/%s/v2.0",
		Now:          nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), "code", "https://x")
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestMicrosoft_BadAudience(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-MS")
	fp := newFakeProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss":                msIssuer(),
		"sub":                "s",
		"oid":                "o",
		"tid":                msTenantID,
		"aud":                "different-audience",
		"iat":                now.Unix(),
		"exp":                now.Add(5 * time.Minute).Unix(),
		"preferred_username": "u@x",
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewMicrosoft(MicrosoftConfig{
		ClientID:     "client-id",
		ClientSecret: "x",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		IssuerFormat: "https://login.test/%s/v2.0",
		Now:          nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), "code", "https://x")
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestMicrosoft_ExpiredToken(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-MS")
	fp := newFakeProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss":                msIssuer(),
		"sub":                "s",
		"oid":                "o",
		"tid":                msTenantID,
		"aud":                "client-id",
		"iat":                now.Add(-2 * time.Hour).Unix(),
		"exp":                now.Add(-1 * time.Hour).Unix(),
		"preferred_username": "u@x",
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewMicrosoft(MicrosoftConfig{
		ClientID:     "client-id",
		ClientSecret: "x",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		IssuerFormat: "https://login.test/%s/v2.0",
		Now:          nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), "code", "https://x")
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestMicrosoft_VerifiedEmailFalse(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-MS")
	fp := newFakeProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss":                msIssuer(),
		"sub":                "s",
		"oid":                "o",
		"tid":                msTenantID,
		"aud":                "client-id",
		"iat":                now.Unix(),
		"exp":                now.Add(5 * time.Minute).Unix(),
		"preferred_username": "u@x.com",
		"verified_email":     false,
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewMicrosoft(MicrosoftConfig{
		ClientID:     "client-id",
		ClientSecret: "x",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		IssuerFormat: "https://login.test/%s/v2.0",
		Now:          nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), "code", "https://x")
	if err == nil || !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got %v", err)
	}
}

func TestMicrosoft_TokenEndpoint400(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}
	exch := NewMicrosoft(MicrosoftConfig{
		ClientID:     "x",
		ClientSecret: "y",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		IssuerFormat: "https://login.test/%s/v2.0",
	})
	_, err := exch.Exchange(context.Background(), "code", "https://x")
	if err == nil || !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}
