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
		"xms_edov":           true,
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
	id, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"})
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
		"iss":      msIssuer(),
		"sub":      "s",
		"oid":      "o",
		"tid":      msTenantID,
		"aud":      clientID,
		"iat":      now.Unix(),
		"exp":      now.Add(5 * time.Minute).Unix(),
		"upn":      "bob@contoso.com",
		"xms_edov": true,
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
	id, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
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
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
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
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
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
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
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
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err == nil || !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got %v", err)
	}
}

// msExchangeWith mints a Microsoft id_token from claims and runs Exchange
// against an exchanger built from cfgMut (applied over the shared test defaults).
// It returns the resulting Identity and error so a caller asserts the nOAuth
// email-trust outcome.
func msExchangeWith(t *testing.T, claims map[string]any, cfgMut func(*MicrosoftConfig)) (*Identity, error) {
	t.Helper()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-MS")
	fp := newFakeProvider(t)
	const clientID = "ms-client-id"
	base := map[string]any{
		"iss": msIssuer(), "sub": "s", "oid": "o", "tid": msTenantID,
		"aud": clientID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"preferred_username": "victim@contoso.com",
	}
	for k, v := range claims {
		base[k] = v
	}
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": key.signIDToken(t, base)})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	cfg := MicrosoftConfig{
		ClientID:     clientID,
		ClientSecret: "secret",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		IssuerFormat: "https://login.test/%s/v2.0",
		Now:          nowFunc(now),
	}
	if cfgMut != nil {
		cfgMut(&cfg)
	}
	return NewMicrosoft(cfg).Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://app/cb"})
}

// TestMicrosoft_NOAuth_EmailTrust is the hardening matrix: a multi-tenant token
// (no tenant pin) is only trusted when it proves email-domain-owner verification
// (xms_edov) or carries an explicit verified_email; pinning the tenant (single
// id or allow-list) trusts it regardless.
func TestMicrosoft_NOAuth_EmailTrust(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		claims  map[string]any
		cfgMut  func(*MicrosoftConfig)
		wantErr error // nil = success
	}{
		{"xms_edov bool true", map[string]any{"xms_edov": true}, nil, nil},
		{"xms_edov string true", map[string]any{"xms_edov": "true"}, nil, nil},
		{"xms_edov string false", map[string]any{"xms_edov": "false"}, nil, ErrEmailNotVerified},
		{"xms_edov bool false", map[string]any{"xms_edov": false}, nil, ErrEmailNotVerified},
		{"xms_edov absent, no pin", map[string]any{}, nil, ErrEmailNotVerified},
		{"verified_email true", map[string]any{"verified_email": true}, nil, nil},
		{"verified_email false beats xms_edov", map[string]any{"verified_email": false, "xms_edov": true}, nil, ErrEmailNotVerified},
		{
			"tenant pinned trusts without xms_edov",
			map[string]any{},
			func(c *MicrosoftConfig) { c.TenantID = msTenantID },
			nil,
		},
		{
			"tenant pin mismatch rejected",
			map[string]any{},
			func(c *MicrosoftConfig) { c.TenantID = "other-tenant" },
			ErrIdentityVerification,
		},
		{
			"allow-list match trusts without xms_edov",
			map[string]any{},
			func(c *MicrosoftConfig) { c.AllowedTenants = []string{"someone-else", msTenantID} },
			nil,
		},
		{
			"allow-list miss rejected",
			map[string]any{},
			func(c *MicrosoftConfig) { c.AllowedTenants = []string{"someone-else"} },
			ErrIdentityVerification,
		},
		{
			"meta tenant_id common is not a pin",
			map[string]any{},
			func(c *MicrosoftConfig) { c.TenantID = "common" },
			ErrEmailNotVerified,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id, err := msExchangeWith(t, tc.claims, tc.cfgMut)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("want success, got %v", err)
				}
				if id.Email != "victim@contoso.com" || !id.EmailVerified {
					t.Fatalf("bad identity: %+v", id)
				}
				return
			}
			if err == nil || !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
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
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err == nil || !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}
