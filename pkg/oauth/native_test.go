package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
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
	id, err := f.veri.Verify(context.Background(), "google", tok, "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Provider != "google" || id.ProviderUserID != "google-sub-123" {
		t.Fatalf("bad identity: %+v", id)
	}
	if id.Email != "user@example.com" {
		t.Fatalf("email not lowercased: %q", id.Email)
	}
	if !id.EmailVerified || id.Name != "Ada Lovelace" || id.AvatarURL != "https://pic" {
		t.Fatalf("bad identity fields: %+v", id)
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
	if _, err := f.veri.Verify(context.Background(), "google", tok, ""); err != nil {
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
			if _, err := f.veri.Verify(context.Background(), "google", tok, ""); err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
		})
	}
}

func TestNativeVerifier_Google_BadSignature(t *testing.T) {
	f := newNativeFixture(t, []string{"web-client"}, nil)
	// Sign with a DIFFERENT key than the one served by the stub JWKS.
	other := newTestKey(t, "native-kid-1") // same kid, different key material
	tok := other.signIDToken(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": "s", "aud": "web-client",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com", "email_verified": true,
	})
	_, err := f.veri.Verify(context.Background(), "google", tok, "")
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
	id, err := f.veri.Verify(context.Background(), "apple", tok, rawNonce)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
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
	if _, err := f.veri.Verify(context.Background(), "apple", tok, rawNonce); err != nil {
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
	if _, err := f.veri.Verify(context.Background(), "apple", tok, "the-expected-raw-nonce"); err == nil {
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
	if _, err := f.veri.Verify(context.Background(), "apple", tok, "expected-raw"); err == nil {
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
	if _, err := f.veri.Verify(context.Background(), "apple", tok, ""); err != nil {
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
	id, err := f.veri.Verify(context.Background(), "apple", tok, "")
	if err != nil {
		t.Fatalf("relay address should be accepted: %v", err)
	}
	if id.Email != "abc123@privaterelay.appleid.com" {
		t.Fatalf("relay email not preserved: %q", id.Email)
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
		if _, err := f.veri.Verify(context.Background(), "apple", tok, ""); err != nil {
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
	if _, err := f.veri.Verify(context.Background(), "apple", tok, ""); !errors.Is(err, ErrEmailNotVerified) {
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
	if _, err := f.veri.Verify(context.Background(), "apple", tok, ""); err == nil {
		t.Fatal("expected wrong-aud rejection")
	}
}

func TestNativeVerifier_UnsupportedProvider(t *testing.T) {
	f := newNativeFixture(t, []string{"web-client"}, nil)
	if _, err := f.veri.Verify(context.Background(), "microsoft", "x", ""); err == nil {
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
	if _, err := f.veri.Verify(context.Background(), "apple", tok, ""); err == nil {
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
	_, err := v.Verify(context.Background(), "google", tok, "")
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
	if _, err := v.Verify(context.Background(), "apple", tok, ""); !errors.Is(err, ErrIdentityVerification) {
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
	if _, err := f.veri.Verify(context.Background(), "google", tok, ""); err == nil {
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
	if _, err := f.veri.Verify(context.Background(), "apple", tok, ""); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified for non-bool/string, got %v", err)
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
