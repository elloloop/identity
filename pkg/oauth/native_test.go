package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// nativeFixture wires a stub JWKS server + a fixed clock and returns a
// verifier configured with the given native audiences.
type nativeFixture struct {
	key  *testKey
	fp   *fakeProvider
	now  time.Time
	veri *NativeVerifier
}

func newNativeFixture(t *testing.T, googleAuds, appleAuds []string) *nativeFixture {
	t.Helper()
	key := newTestKey(t, "native-kid-1")
	fp := newFakeProvider(t)
	fp.jwksHandler = rawHandler(200, "application/json", key.JWKJSON)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	v := NewNativeVerifier(NativeVerifierConfig{
		GoogleAudiences: googleAuds,
		AppleAudiences:  appleAuds,
		GoogleJWKSURL:   fp.URL("/jwks"),
		AppleJWKSURL:    fp.URL("/jwks"),
		Now:             nowFunc(now),
	})
	return &nativeFixture{key: key, fp: fp, now: now, veri: v}
}

func appleNonceHashHex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func appleNonceHashB64(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestNativeVerifier_Google_Valid(t *testing.T) {
	f := newNativeFixture(t, []string{"web-client.apps.googleusercontent.com", "ios-client.apps.googleusercontent.com"}, nil)
	tok := f.key.signIDToken(t, map[string]any{
		"iss":            "https://accounts.google.com",
		"sub":            "google-sub-123",
		"aud":            "ios-client.apps.googleusercontent.com",
		"exp":            f.now.Add(time.Hour),
		"iat":            f.now,
		"email":          "User@Example.com",
		"email_verified": true,
		"name":           "Ada Lovelace",
		"picture":        "https://pic",
	})
	res, err := f.veri.Verify(context.Background(), "google", tok, "", "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	id := res.Identity
	if id.Provider != "google" || id.ProviderUserID != "google-sub-123" {
		t.Fatalf("bad identity: %+v", id)
	}
	if id.Email != "user@example.com" {
		t.Fatalf("email not lowercased: %q", id.Email)
	}
	if !id.EmailVerified || id.Name != "Ada Lovelace" || id.AvatarURL != "https://pic" {
		t.Fatalf("bad identity fields: %+v", id)
	}
	if res.ReplayKey == "" {
		t.Fatal("verify: empty replay key")
	}
}

func TestNativeVerifier_Google_NonHTTPSIssuerAccepted(t *testing.T) {
	f := newNativeFixture(t, []string{"web-client"}, nil)
	tok := f.key.signIDToken(t, map[string]any{
		"iss":            "accounts.google.com",
		"sub":            "s1",
		"aud":            "web-client",
		"exp":            f.now.Add(time.Hour),
		"iat":            f.now,
		"email":          "a@b.com",
		"email_verified": true,
	})
	if _, err := f.veri.Verify(context.Background(), "google", tok, "", ""); err != nil {
		t.Fatalf("non-https issuer should be accepted: %v", err)
	}
}

func TestNativeVerifier_Google_Rejections(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
	}{
		{"wrong_aud", map[string]any{"iss": "https://accounts.google.com", "sub": "s", "aud": "other-client", "exp": "future", "iat": "now", "email": "a@b.com", "email_verified": true}},
		{"expired", map[string]any{"iss": "https://accounts.google.com", "sub": "s", "aud": "web-client", "exp": "past", "iat": "past", "email": "a@b.com", "email_verified": true}},
		{"bad_iss", map[string]any{"iss": "https://evil.example.com", "sub": "s", "aud": "web-client", "exp": "future", "iat": "now", "email": "a@b.com", "email_verified": true}},
		{"email_unverified", map[string]any{"iss": "https://accounts.google.com", "sub": "s", "aud": "web-client", "exp": "future", "iat": "now", "email": "a@b.com", "email_verified": false}},
		{"missing_email", map[string]any{"iss": "https://accounts.google.com", "sub": "s", "aud": "web-client", "exp": "future", "iat": "now", "email_verified": true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newNativeFixture(t, []string{"web-client"}, nil)
			claims := materializeTimes(tc.claims, f.now)
			tok := f.key.signIDToken(t, claims)
			if _, err := f.veri.Verify(context.Background(), "google", tok, "", ""); err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
		})
	}
}

func TestNativeVerifier_MissingExpRejected(t *testing.T) {
	// Real Google/Apple native ID tokens always carry `exp`. A native token
	// with no `exp` claim must be rejected on both provider paths — the shared
	// time check tolerates a zero `exp` (for the hosted flows), so the native
	// verifier enforces its presence explicitly.
	t.Run("google", func(t *testing.T) {
		f := newNativeFixture(t, []string{"web-client"}, nil)
		tok := f.key.signIDToken(t, map[string]any{
			"iss": "https://accounts.google.com", "sub": "s", "aud": "web-client",
			"iat": f.now, "email": "a@b.com", "email_verified": true,
			// no exp claim
		})
		if _, err := f.veri.Verify(context.Background(), "google", tok, "", ""); !errors.Is(err, ErrIdentityVerification) {
			t.Fatalf("want ErrIdentityVerification for missing exp, got %v", err)
		}
	})
	t.Run("apple", func(t *testing.T) {
		f := newNativeFixture(t, nil, []string{"dev.easyloops.app"})
		tok := f.key.signIDToken(t, map[string]any{
			"iss": appleIssuer, "sub": "s", "aud": "dev.easyloops.app",
			"iat": f.now, "email": "a@b.com", "email_verified": true,
			// no exp claim
		})
		if _, err := f.veri.Verify(context.Background(), "apple", tok, "", ""); !errors.Is(err, ErrIdentityVerification) {
			t.Fatalf("want ErrIdentityVerification for missing exp, got %v", err)
		}
	})
}

func TestNativeVerifier_Google_BadSignature(t *testing.T) {
	f := newNativeFixture(t, []string{"web-client"}, nil)
	// Sign with a DIFFERENT key than the one served by the stub JWKS.
	other := newTestKey(t, "native-kid-1") // same kid, different key material
	tok := other.signIDToken(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": "s", "aud": "web-client",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com", "email_verified": true,
	})
	_, err := f.veri.Verify(context.Background(), "google", tok, "", "")
	if err == nil {
		t.Fatal("expected signature verification failure")
	}
	if !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

func TestNativeVerifier_Apple_ValidWithNonce(t *testing.T) {
	const rawNonce = "raw-nonce-value"
	f := newNativeFixture(t, nil, []string{"app.easyloops.auth.web", "dev.easyloops.app"})
	tok := f.key.signIDToken(t, map[string]any{
		"iss":            appleIssuer,
		"sub":            "apple-sub-1",
		"aud":            "dev.easyloops.app",
		"exp":            f.now.Add(time.Hour),
		"iat":            f.now,
		"email":          "user@icloud.com",
		"email_verified": "true", // Apple sends string
		"nonce":          appleNonceHashHex(rawNonce),
	})
	res, err := f.veri.Verify(context.Background(), "apple", tok, rawNonce, "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	id := res.Identity
	if id.Provider != "apple" || id.ProviderUserID != "apple-sub-1" || id.Email != "user@icloud.com" {
		t.Fatalf("bad identity: %+v", id)
	}
}

func TestNativeVerifier_Apple_NonceBase64Accepted(t *testing.T) {
	const rawNonce = "another-nonce"
	f := newNativeFixture(t, nil, []string{"dev.easyloops.app"})
	tok := f.key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "dev.easyloops.app",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
		"email_verified": true, "nonce": appleNonceHashB64(rawNonce),
	})
	if _, err := f.veri.Verify(context.Background(), "apple", tok, rawNonce, ""); err != nil {
		t.Fatalf("base64url nonce should be accepted: %v", err)
	}
}

func TestNativeVerifier_Apple_NonceMismatch(t *testing.T) {
	f := newNativeFixture(t, nil, []string{"dev.easyloops.app"})
	tok := f.key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "dev.easyloops.app",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
		"email_verified": true, "nonce": appleNonceHashHex("a-different-raw-nonce"),
	})
	if _, err := f.veri.Verify(context.Background(), "apple", tok, "the-expected-raw-nonce", ""); err == nil {
		t.Fatal("expected nonce mismatch rejection")
	}
}

func TestNativeVerifier_Apple_MissingNonceClaimWhenExpected(t *testing.T) {
	f := newNativeFixture(t, nil, []string{"dev.easyloops.app"})
	tok := f.key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "dev.easyloops.app",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
		"email_verified": true,
		// no nonce claim at all
	})
	if _, err := f.veri.Verify(context.Background(), "apple", tok, "expected-raw", ""); err == nil {
		t.Fatal("expected rejection when nonce expected but claim absent")
	}
}

func TestNativeVerifier_Apple_NoNonceProvided_Skipped(t *testing.T) {
	// When the client supplies no raw nonce, the claim is not checked.
	f := newNativeFixture(t, nil, []string{"dev.easyloops.app"})
	tok := f.key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "dev.easyloops.app",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
		"email_verified": true,
	})
	if _, err := f.veri.Verify(context.Background(), "apple", tok, "", ""); err != nil {
		t.Fatalf("verify without nonce should pass: %v", err)
	}
}

func TestNativeVerifier_Apple_HideMyEmailRelay(t *testing.T) {
	f := newNativeFixture(t, nil, []string{"dev.easyloops.app"})
	tok := f.key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "relay-sub", "aud": "dev.easyloops.app",
		"exp": f.now.Add(time.Hour), "iat": f.now,
		"email":            "abc123@privaterelay.appleid.com",
		"email_verified":   true,
		"is_private_email": "true",
	})
	res, err := f.veri.Verify(context.Background(), "apple", tok, "", "")
	if err != nil {
		t.Fatalf("relay address should be accepted: %v", err)
	}
	if res.Identity.Email != "abc123@privaterelay.appleid.com" {
		t.Fatalf("relay email not preserved: %q", res.Identity.Email)
	}
}

func TestNativeVerifier_Apple_EmailVerifiedBoolAndString(t *testing.T) {
	for _, ev := range []any{true, "true"} {
		f := newNativeFixture(t, nil, []string{"dev.easyloops.app"})
		tok := f.key.signIDToken(t, map[string]any{
			"iss": appleIssuer, "sub": "s", "aud": "dev.easyloops.app",
			"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
			"email_verified": ev,
		})
		if _, err := f.veri.Verify(context.Background(), "apple", tok, "", ""); err != nil {
			t.Fatalf("email_verified=%v(%T) should pass: %v", ev, ev, err)
		}
	}
	// Unverified (string "false") must reject.
	f := newNativeFixture(t, nil, []string{"dev.easyloops.app"})
	tok := f.key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "dev.easyloops.app",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
		"email_verified": "false",
	})
	if _, err := f.veri.Verify(context.Background(), "apple", tok, "", ""); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got %v", err)
	}
}

func TestNativeVerifier_Apple_WrongAud(t *testing.T) {
	f := newNativeFixture(t, nil, []string{"dev.easyloops.app"})
	tok := f.key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "com.someone.else",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
		"email_verified": true,
	})
	if _, err := f.veri.Verify(context.Background(), "apple", tok, "", ""); err == nil {
		t.Fatal("expected wrong-aud rejection")
	}
}

func TestNativeVerifier_UnsupportedProvider(t *testing.T) {
	f := newNativeFixture(t, []string{"web-client"}, nil)
	if _, err := f.veri.Verify(context.Background(), "microsoft", "x", "", ""); err == nil {
		t.Fatal("expected unsupported provider error")
	}
}

func TestNativeVerifier_ProviderNotConfigured(t *testing.T) {
	// Google configured, Apple not: an apple token is rejected.
	f := newNativeFixture(t, []string{"web-client"}, nil)
	tok := f.key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "dev.easyloops.app",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
		"email_verified": true,
	})
	if _, err := f.veri.Verify(context.Background(), "apple", tok, "", ""); err == nil {
		t.Fatal("expected rejection: apple not configured")
	}
}

func TestNativeVerifier_Google_KidNotFound_RetriesAndFails(t *testing.T) {
	// The stub JWKS serves a key with a DIFFERENT kid than the token's, so the
	// signing key is never found; the verifier invalidates the cache, refetches,
	// and still fails — exercising the rotation-retry branch.
	signKey := newTestKey(t, "rotated-kid")
	servedKey := newTestKey(t, "stale-kid")
	fp := newFakeProvider(t)
	fp.jwksHandler = rawHandler(200, "application/json", servedKey.JWKJSON)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	v := NewNativeVerifier(NativeVerifierConfig{
		GoogleAudiences: []string{"web-client"},
		GoogleJWKSURL:   fp.URL("/jwks"),
		Now:             nowFunc(now),
	})
	tok := signKey.signIDToken(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": "s", "aud": "web-client",
		"exp": now.Add(time.Hour), "iat": now, "email": "a@b.com", "email_verified": true,
	})
	_, err := v.Verify(context.Background(), "google", tok, "", "")
	if err == nil {
		t.Fatal("expected failure when signing kid is absent from JWKS")
	}
	if !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
	// JWKS was fetched at least twice: initial + post-invalidation refetch.
	if got := fp.jwksCalls.Load(); got < 2 {
		t.Fatalf("expected >=2 jwks fetches (rotation retry), got %d", got)
	}
}

func TestNativeVerifier_JWKSFetchFailure(t *testing.T) {
	fp := newFakeProvider(t)
	fp.jwksHandler = rawHandler(500, "text/plain", []byte("boom"))
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "k")
	v := NewNativeVerifier(NativeVerifierConfig{
		AppleAudiences: []string{"dev.easyloops.app"},
		AppleJWKSURL:   fp.URL("/jwks"),
		Now:            nowFunc(now),
	})
	tok := key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "dev.easyloops.app",
		"exp": now.Add(time.Hour), "iat": now, "email": "a@b.com", "email_verified": true,
	})
	if _, err := v.Verify(context.Background(), "apple", tok, "", ""); !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification on jwks fetch failure, got %v", err)
	}
}

func TestNewNativeVerifier_DefaultsAndIssuerOverrides(t *testing.T) {
	// Exercises the default-URL and issuer-override branches of the constructor.
	def := NewNativeVerifier(NativeVerifierConfig{GoogleAudiences: []string{"x"}})
	if def == nil || len(def.googleIssuers) == 0 || def.appleIssuer != appleIssuer {
		t.Fatalf("defaults not applied: %+v", def)
	}
	over := NewNativeVerifier(NativeVerifierConfig{
		GoogleAudiences: []string{"x"},
		AppleAudiences:  []string{"y"},
		GoogleIssuer:    "https://issuer.test/google",
		AppleIssuer:     "https://issuer.test/apple",
	})
	if len(over.googleIssuers) != 1 || over.googleIssuers[0] != "https://issuer.test/google" {
		t.Fatalf("google issuer override not applied: %v", over.googleIssuers)
	}
	if over.appleIssuer != "https://issuer.test/apple" {
		t.Fatalf("apple issuer override not applied: %q", over.appleIssuer)
	}
}

func TestNativeVerifier_Google_NotConfigured(t *testing.T) {
	// Apple-only verifier rejects a google token (google audiences empty).
	f := newNativeFixture(t, nil, []string{"dev.easyloops.app"})
	tok := f.key.signIDToken(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": "s", "aud": "web-client",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com", "email_verified": true,
	})
	if _, err := f.veri.Verify(context.Background(), "google", tok, "", ""); err == nil {
		t.Fatal("expected rejection: google not configured")
	}
}

func TestNativeVerifier_Apple_EmailVerifiedUnexpectedType(t *testing.T) {
	// A numeric email_verified is treated as unverified (default branch).
	f := newNativeFixture(t, nil, []string{"dev.easyloops.app"})
	tok := f.key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "dev.easyloops.app",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
		"email_verified": 1,
	})
	if _, err := f.veri.Verify(context.Background(), "apple", tok, "", ""); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified for non-bool/string, got %v", err)
	}
}

// newNativeFixtureCfg builds a fixture whose verifier is configured by mutate,
// with the stub JWKS URLs and fixed clock already wired. It lets a test set
// per-product audience maps that newNativeFixture (global-only) cannot.
func newNativeFixtureCfg(t *testing.T, mutate func(*NativeVerifierConfig)) *nativeFixture {
	t.Helper()
	key := newTestKey(t, "native-kid-1")
	fp := newFakeProvider(t)
	fp.jwksHandler = rawHandler(200, "application/json", key.JWKJSON)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	cfg := NativeVerifierConfig{
		GoogleJWKSURL: fp.URL("/jwks"),
		AppleJWKSURL:  fp.URL("/jwks"),
		Now:           nowFunc(now),
	}
	mutate(&cfg)
	return &nativeFixture{key: key, fp: fp, now: now, veri: NewNativeVerifier(cfg)}
}

func TestNativeVerifier_Google_PerProductAudienceScoping(t *testing.T) {
	// productA accepts only audA, productB only audB — audB is also globally
	// valid. A token minted for audB must be rejected when presented as
	// productA (cross-product replay) and accepted as productB.
	f := newNativeFixtureCfg(t, func(c *NativeVerifierConfig) {
		c.GoogleAudiences = []string{"audA", "audB"} // globally allowed
		c.GoogleAudiencesByProduct = map[string][]string{
			"producta": {"audA"},
			"productb": {"audB"},
		}
	})
	tok := f.key.signIDToken(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": "s", "aud": "audB",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com", "email_verified": true,
	})
	// (a) token for product B rejected when presented as product A (case-insensitive key).
	if _, err := f.veri.Verify(context.Background(), "google", tok, "", "productA"); err == nil {
		t.Fatal("expected rejection: audB is not in productA's audience set")
	}
	// (b) correct product still succeeds.
	if _, err := f.veri.Verify(context.Background(), "google", tok, "", "productB"); err != nil {
		t.Fatalf("productB should accept its own audience: %v", err)
	}
}

func TestNativeVerifier_Apple_PerProductAudienceScoping(t *testing.T) {
	f := newNativeFixtureCfg(t, func(c *NativeVerifierConfig) {
		c.AppleAudiencesByProduct = map[string][]string{
			"producta": {"com.a.app"},
			"productb": {"com.b.app"},
		}
	})
	tok := f.key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "com.b.app",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com", "email_verified": true,
	})
	if _, err := f.veri.Verify(context.Background(), "apple", tok, "", "productA"); err == nil {
		t.Fatal("expected rejection: com.b.app is not in productA's audience set")
	}
	if _, err := f.veri.Verify(context.Background(), "apple", tok, "", "productB"); err != nil {
		t.Fatalf("productB should accept its own audience: %v", err)
	}
}

func TestNativeVerifier_Google_GlobalFallbackForUnlistedProduct(t *testing.T) {
	// A product with a per-product set accepts ONLY that set; a product with no
	// entry falls back to the global audiences (backward-compatible path).
	f := newNativeFixtureCfg(t, func(c *NativeVerifierConfig) {
		c.GoogleAudiences = []string{"global-aud"}
		c.GoogleAudiencesByProduct = map[string][]string{"producta": {"audA"}}
	})
	tok := f.key.signIDToken(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": "s", "aud": "global-aud",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com", "email_verified": true,
	})
	// (c) unlisted product → global set accepts the token.
	if _, err := f.veri.Verify(context.Background(), "google", tok, "", "unlisted"); err != nil {
		t.Fatalf("unlisted product should fall back to global audiences: %v", err)
	}
	// A listed product does NOT merge the global set: global-aud is rejected for productA.
	if _, err := f.veri.Verify(context.Background(), "google", tok, "", "productA"); err == nil {
		t.Fatal("expected rejection: global-aud is not in productA's exclusive set")
	}
}

func TestNativeVerifier_Google_PerProductOnly_NoGlobal(t *testing.T) {
	// With no global audiences at all, a per-product entry still enables its
	// product; an unlisted product has no audiences and is rejected.
	f := newNativeFixtureCfg(t, func(c *NativeVerifierConfig) {
		c.GoogleAudiencesByProduct = map[string][]string{"producta": {"audA"}}
	})
	tok := f.key.signIDToken(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": "s", "aud": "audA",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com", "email_verified": true,
	})
	if _, err := f.veri.Verify(context.Background(), "google", tok, "", "productA"); err != nil {
		t.Fatalf("productA should verify from its per-product set: %v", err)
	}
	if _, err := f.veri.Verify(context.Background(), "google", tok, "", "unlisted"); err == nil {
		t.Fatal("expected rejection: unlisted product has no audiences (no global fallback)")
	}
}

// materializeTimes converts the sentinel string time markers in a claims map
// ("future"/"past"/"now") into concrete times relative to now.
func materializeTimes(in map[string]any, now time.Time) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if (k == "exp" || k == "iat") && v != nil {
			switch v {
			case "future":
				out[k] = now.Add(time.Hour)
			case "past":
				out[k] = now.Add(-time.Hour)
			case "now":
				out[k] = now
			default:
				out[k] = v
			}
			continue
		}
		out[k] = v
	}
	return out
}

// ── Replay-key derivation (issue #299 item 2) ────────────────────────────

func TestNativeVerifier_ReplayKey_UsesJTIWhenPresent(t *testing.T) {
	f := newNativeFixture(t, []string{"aud-1"}, nil)
	tok := f.key.signIDToken(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": "s", "aud": "aud-1",
		"exp": f.now.Add(time.Hour), "iat": f.now,
		"email": "a@b.com", "email_verified": true,
		"jti": "unique-token-id-1",
	})
	res, err := f.veri.Verify(context.Background(), "google", tok, "", "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if want := "google|jti|unique-token-id-1"; res.ReplayKey != want {
		t.Fatalf("ReplayKey = %q, want %q", res.ReplayKey, want)
	}
}

func TestNativeVerifier_ReplayKey_DigestWhenNoJTI(t *testing.T) {
	f := newNativeFixture(t, []string{"aud-1"}, nil)
	mk := func(sub string, iat time.Time) *NativeVerification {
		tok := f.key.signIDToken(t, map[string]any{
			"iss": "https://accounts.google.com", "sub": sub, "aud": "aud-1",
			"exp": iat.Add(time.Hour), "iat": iat,
			"email": "a@b.com", "email_verified": true,
		})
		res, err := f.veri.Verify(context.Background(), "google", tok, "", "")
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		return res
	}
	// No jti -> a stable digest key, prefixed by provider.
	a := mk("sub-1", f.now)
	if !strings.HasPrefix(a.ReplayKey, "google|d|") {
		t.Fatalf("digest key should be provider-prefixed, got %q", a.ReplayKey)
	}
	// The SAME token (same claims) yields the SAME key — a replay is detectable.
	aAgain := mk("sub-1", f.now)
	if a.ReplayKey != aAgain.ReplayKey {
		t.Fatalf("identical claims produced different keys: %q vs %q", a.ReplayKey, aAgain.ReplayKey)
	}
	// A different subject is a DIFFERENT token -> different key.
	if b := mk("sub-2", f.now); a.ReplayKey == b.ReplayKey {
		t.Fatal("distinct subjects must yield distinct replay keys")
	}
	// A re-issued token for the same subject differs in iat -> different key.
	if c := mk("sub-1", f.now.Add(time.Second)); a.ReplayKey == c.ReplayKey {
		t.Fatal("distinct iat must yield distinct replay keys")
	}
}

func TestNativeVerifier_ReplayExpiry_CappedAtMax(t *testing.T) {
	f := newNativeFixture(t, []string{"aud-1"}, nil)
	// exp far in the future (10h) must be capped at now + maxNativeReplayTTL.
	tok := f.key.signIDToken(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": "s", "aud": "aud-1",
		"exp": f.now.Add(10 * time.Hour), "iat": f.now,
		"email": "a@b.com", "email_verified": true,
	})
	res, err := f.veri.Verify(context.Background(), "google", tok, "", "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if want := f.now.Add(maxNativeReplayTTL).UnixMilli(); res.ExpiresAtMs != want {
		t.Fatalf("ExpiresAtMs = %d, want capped %d", res.ExpiresAtMs, want)
	}
}

func TestNativeVerifier_ReplayExpiry_UsesTokenExpWhenWithinCap(t *testing.T) {
	f := newNativeFixture(t, []string{"aud-1"}, nil)
	exp := f.now.Add(15 * time.Minute)
	tok := f.key.signIDToken(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": "s", "aud": "aud-1",
		"exp": exp, "iat": f.now,
		"email": "a@b.com", "email_verified": true,
	})
	res, err := f.veri.Verify(context.Background(), "google", tok, "", "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.ExpiresAtMs != exp.UnixMilli() {
		t.Fatalf("ExpiresAtMs = %d, want token exp %d", res.ExpiresAtMs, exp.UnixMilli())
	}
}
