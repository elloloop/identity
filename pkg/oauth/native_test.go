package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// nativeFixture wires a stub JWKS server + a fixed clock and holds the
// per-provider audiences a test presents through Verify. Audiences are supplied
// per-request now (resolved from the project scope in production), so the
// fixture threads them into NativeVerifyParams via its verify helper.
type nativeFixture struct {
	key        *testKey
	fp         *fakeProvider
	now        time.Time
	veri       *NativeVerifier
	googleAuds []string
	appleAuds  []string
}

func newNativeFixture(t *testing.T, googleAuds, appleAuds []string) *nativeFixture {
	t.Helper()
	key := newTestKey(t, "native-kid-1")
	fp := newFakeProvider(t)
	fp.jwksHandler = rawHandler(200, "application/json", key.JWKJSON)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	v := NewNativeVerifier(NativeVerifierConfig{
		GoogleJWKSURL:    fp.URL("/jwks"),
		AppleJWKSURL:     fp.URL("/jwks"),
		MicrosoftJWKSURL: fp.URL("/jwks"),
		Now:              nowFunc(now),
	})
	return &nativeFixture{key: key, fp: fp, now: now, veri: v, googleAuds: googleAuds, appleAuds: appleAuds}
}

func (f *nativeFixture) audsFor(provider string) []string {
	switch provider {
	case "google":
		return f.googleAuds
	case "apple":
		return f.appleAuds
	}
	return nil
}

// verify runs Verify with the fixture's configured audiences for the provider.
func (f *nativeFixture) verify(ctx context.Context, provider, idToken, rawNonce string) (*NativeVerification, error) {
	return f.veri.Verify(ctx, NativeVerifyParams{
		Provider:  provider,
		IDToken:   idToken,
		RawNonce:  rawNonce,
		Audiences: f.audsFor(provider),
	})
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
	res, err := f.verify(context.Background(), "google", tok, "")
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
	if _, err := f.verify(context.Background(), "google", tok, ""); err != nil {
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
			if _, err := f.verify(context.Background(), "google", tok, ""); err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
		})
	}
}

func TestNativeVerifier_MissingExpRejected(t *testing.T) {
	// Real Google/Apple/Microsoft native ID tokens always carry `exp`. A native
	// token with no `exp` claim must be rejected on every provider path — the
	// shared time check tolerates a zero `exp` (for the hosted flows), so the
	// native verifier enforces its presence explicitly.
	t.Run("google", func(t *testing.T) {
		f := newNativeFixture(t, []string{"web-client"}, nil)
		tok := f.key.signIDToken(t, map[string]any{
			"iss": "https://accounts.google.com", "sub": "s", "aud": "web-client",
			"iat": f.now, "email": "a@b.com", "email_verified": true,
			// no exp claim
		})
		if _, err := f.verify(context.Background(), "google", tok, ""); !errors.Is(err, ErrIdentityVerification) {
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
		if _, err := f.verify(context.Background(), "apple", tok, ""); !errors.Is(err, ErrIdentityVerification) {
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
	_, err := f.verify(context.Background(), "google", tok, "")
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
	res, err := f.verify(context.Background(), "apple", tok, rawNonce)
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
	if _, err := f.verify(context.Background(), "apple", tok, rawNonce); err != nil {
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
	if _, err := f.verify(context.Background(), "apple", tok, "the-expected-raw-nonce"); err == nil {
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
	if _, err := f.verify(context.Background(), "apple", tok, "expected-raw"); err == nil {
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
	if _, err := f.verify(context.Background(), "apple", tok, ""); err != nil {
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
	res, err := f.verify(context.Background(), "apple", tok, "")
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
		if _, err := f.verify(context.Background(), "apple", tok, ""); err != nil {
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
	if _, err := f.verify(context.Background(), "apple", tok, ""); !errors.Is(err, ErrEmailNotVerified) {
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
	if _, err := f.verify(context.Background(), "apple", tok, ""); err == nil {
		t.Fatal("expected wrong-aud rejection")
	}
}

func TestNativeVerifier_UnsupportedProvider(t *testing.T) {
	f := newNativeFixture(t, []string{"web-client"}, nil)
	if _, err := f.veri.Verify(context.Background(), NativeVerifyParams{
		Provider: "github", IDToken: "x", Audiences: []string{"web-client"},
	}); err == nil {
		t.Fatal("expected unsupported provider error")
	}
}

func TestNativeVerifier_ProviderNotConfigured(t *testing.T) {
	// Google configured, Apple not (empty apple audiences): an apple token is
	// rejected because no audience set is supplied for it.
	f := newNativeFixture(t, []string{"web-client"}, nil)
	tok := f.key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "dev.easyloops.app",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
		"email_verified": true,
	})
	if _, err := f.verify(context.Background(), "apple", tok, ""); err == nil {
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
		GoogleJWKSURL: fp.URL("/jwks"),
		Now:           nowFunc(now),
	})
	tok := signKey.signIDToken(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": "s", "aud": "web-client",
		"exp": now.Add(time.Hour), "iat": now, "email": "a@b.com", "email_verified": true,
	})
	_, err := v.Verify(context.Background(), NativeVerifyParams{
		Provider: "google", IDToken: tok, Audiences: []string{"web-client"},
	})
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
		AppleJWKSURL: fp.URL("/jwks"),
		Now:          nowFunc(now),
	})
	tok := key.signIDToken(t, map[string]any{
		"iss": appleIssuer, "sub": "s", "aud": "dev.easyloops.app",
		"exp": now.Add(time.Hour), "iat": now, "email": "a@b.com", "email_verified": true,
	})
	if _, err := v.Verify(context.Background(), NativeVerifyParams{
		Provider: "apple", IDToken: tok, Audiences: []string{"dev.easyloops.app"},
	}); !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification on jwks fetch failure, got %v", err)
	}
}

func TestNewNativeVerifier_DefaultsAndIssuerOverrides(t *testing.T) {
	// Exercises the default-URL and issuer-override branches of the constructor.
	def := NewNativeVerifier(NativeVerifierConfig{})
	if def == nil || len(def.googleIssuers) == 0 || def.appleIssuer != appleIssuer {
		t.Fatalf("defaults not applied: %+v", def)
	}
	over := NewNativeVerifier(NativeVerifierConfig{
		GoogleIssuer: "https://issuer.test/google",
		AppleIssuer:  "https://issuer.test/apple",
	})
	if len(over.googleIssuers) != 1 || over.googleIssuers[0] != "https://issuer.test/google" {
		t.Fatalf("google issuer override not applied: %v", over.googleIssuers)
	}
	if over.appleIssuer != "https://issuer.test/apple" {
		t.Fatalf("apple issuer override not applied: %q", over.appleIssuer)
	}
}

func TestNativeVerifier_Google_NotConfigured(t *testing.T) {
	// Apple-only fixture rejects a google token (no google audiences supplied).
	f := newNativeFixture(t, nil, []string{"dev.easyloops.app"})
	tok := f.key.signIDToken(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": "s", "aud": "web-client",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com", "email_verified": true,
	})
	if _, err := f.verify(context.Background(), "google", tok, ""); err == nil {
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
	if _, err := f.verify(context.Background(), "apple", tok, ""); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified for non-bool/string, got %v", err)
	}
}

// ── Native Microsoft ─────────────────────────────────────────────────────

const msTestIssuerFormat = "https://login.microsoftonline.com/%s/v2.0"

// msFixture is a native fixture specialised for Microsoft tokens: it carries the
// accepted audiences and the tenant/issuer pinning threaded into each request.
type msFixture struct {
	key *testKey
	now time.Time
	v   *NativeVerifier
}

func newMSFixture(t *testing.T) *msFixture {
	t.Helper()
	key := newTestKey(t, "ms-kid-1")
	fp := newFakeProvider(t)
	fp.jwksHandler = rawHandler(200, "application/json", key.JWKJSON)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	v := NewNativeVerifier(NativeVerifierConfig{
		MicrosoftJWKSURL: fp.URL("/jwks"),
		Now:              nowFunc(now),
	})
	return &msFixture{key: key, now: now, v: v}
}

func msTestIssuer(tid string) string { return fmt.Sprintf(msTestIssuerFormat, tid) }

func (f *msFixture) verify(p NativeVerifyParams) (*NativeVerification, error) {
	p.Provider = "microsoft"
	if p.MicrosoftIssuerFormat == "" {
		p.MicrosoftIssuerFormat = msTestIssuerFormat
	}
	return f.v.Verify(context.Background(), p)
}

func TestNativeVerifier_Microsoft_Valid(t *testing.T) {
	f := newMSFixture(t)
	const tid = "tenant-abc"
	tok := f.key.signIDToken(t, map[string]any{
		"iss": msTestIssuer(tid), "tid": tid, "aud": "ms-client-app",
		"oid": "oid-123", "sub": "sub-456",
		"exp": f.now.Add(time.Hour), "iat": f.now,
		"email": "User@Contoso.com", "name": "Msft User", "picture": "https://av",
		"xms_edov": true,
	})
	res, err := f.verify(NativeVerifyParams{IDToken: tok, Audiences: []string{"ms-client-app"}})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	id := res.Identity
	if id.Provider != "microsoft" {
		t.Fatalf("provider = %q", id.Provider)
	}
	if id.ProviderUserID != "oid-123" {
		t.Fatalf("subject should prefer oid: %q", id.ProviderUserID)
	}
	if id.Email != "user@contoso.com" {
		t.Fatalf("email not lowercased: %q", id.Email)
	}
	if id.Name != "Msft User" || id.AvatarURL != "https://av" || !id.EmailVerified {
		t.Fatalf("bad identity fields: %+v", id)
	}
}

func TestNativeVerifier_Microsoft_SubjectFallsBackToSub(t *testing.T) {
	f := newMSFixture(t)
	const tid = "tenant-abc"
	tok := f.key.signIDToken(t, map[string]any{
		"iss": msTestIssuer(tid), "tid": tid, "aud": "ms-client-app", "sub": "only-sub",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com", "xms_edov": true,
	})
	res, err := f.verify(NativeVerifyParams{IDToken: tok, Audiences: []string{"ms-client-app"}})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Identity.ProviderUserID != "only-sub" {
		t.Fatalf("subject should fall back to sub: %q", res.Identity.ProviderUserID)
	}
}

func TestNativeVerifier_Microsoft_EmailCoalesce(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"email", map[string]any{"email": "e@x.com"}, "e@x.com"},
		{"preferred_username", map[string]any{"preferred_username": "pu@x.com"}, "pu@x.com"},
		{"upn", map[string]any{"upn": "upn@x.com"}, "upn@x.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMSFixture(t)
			const tid = "t1"
			claims := map[string]any{
				"iss": msTestIssuer(tid), "tid": tid, "aud": "app", "sub": "s",
				"exp": f.now.Add(time.Hour), "iat": f.now, "xms_edov": true,
			}
			for k, v := range tc.claims {
				claims[k] = v
			}
			res, err := f.verify(NativeVerifyParams{IDToken: f.key.signIDToken(t, claims), Audiences: []string{"app"}})
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if res.Identity.Email != tc.want {
				t.Fatalf("email = %q, want %q", res.Identity.Email, tc.want)
			}
		})
	}
}

func TestNativeVerifier_Microsoft_MissingEmail(t *testing.T) {
	f := newMSFixture(t)
	const tid = "t1"
	tok := f.key.signIDToken(t, map[string]any{
		"iss": msTestIssuer(tid), "tid": tid, "aud": "app", "sub": "s",
		"exp": f.now.Add(time.Hour), "iat": f.now,
		// no email/preferred_username/upn
	})
	if _, err := f.verify(NativeVerifyParams{IDToken: tok, Audiences: []string{"app"}}); !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification for missing email, got %v", err)
	}
}

func TestNativeVerifier_Microsoft_VerifiedEmailFalseRejected(t *testing.T) {
	f := newMSFixture(t)
	const tid = "t1"
	tok := f.key.signIDToken(t, map[string]any{
		"iss": msTestIssuer(tid), "tid": tid, "aud": "app", "sub": "s",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
		"verified_email": false,
	})
	if _, err := f.verify(NativeVerifyParams{IDToken: tok, Audiences: []string{"app"}}); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got %v", err)
	}
}

func TestNativeVerifier_Microsoft_BadAud(t *testing.T) {
	f := newMSFixture(t)
	const tid = "t1"
	tok := f.key.signIDToken(t, map[string]any{
		"iss": msTestIssuer(tid), "tid": tid, "aud": "some-other-app", "sub": "s",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
	})
	if _, err := f.verify(NativeVerifyParams{IDToken: tok, Audiences: []string{"app"}}); err == nil {
		t.Fatal("expected bad-aud rejection")
	}
}

func TestNativeVerifier_Microsoft_MissingTID(t *testing.T) {
	f := newMSFixture(t)
	tok := f.key.signIDToken(t, map[string]any{
		"iss": msTestIssuer("t1"), "aud": "app", "sub": "s",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
		// no tid
	})
	if _, err := f.verify(NativeVerifyParams{IDToken: tok, Audiences: []string{"app"}}); !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification for missing tid, got %v", err)
	}
}

func TestNativeVerifier_Microsoft_WrongIssuer(t *testing.T) {
	f := newMSFixture(t)
	const tid = "t1"
	// Issuer stamped for a DIFFERENT tenant than tid → derived issuer mismatch.
	tok := f.key.signIDToken(t, map[string]any{
		"iss": msTestIssuer("other-tenant"), "tid": tid, "aud": "app", "sub": "s",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
	})
	if _, err := f.verify(NativeVerifyParams{IDToken: tok, Audiences: []string{"app"}}); err == nil {
		t.Fatal("expected wrong-issuer rejection")
	}
}

func TestNativeVerifier_Microsoft_TenantPinning(t *testing.T) {
	f := newMSFixture(t)
	// A single-tenant project pins tenant "t-pinned"; a token from another tenant
	// is rejected even though its issuer is internally consistent.
	tok := f.key.signIDToken(t, map[string]any{
		"iss": msTestIssuer("t-other"), "tid": "t-other", "aud": "app", "sub": "s",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
	})
	if _, err := f.verify(NativeVerifyParams{IDToken: tok, Audiences: []string{"app"}, MicrosoftTenantID: "t-pinned"}); err == nil {
		t.Fatal("expected tenant-mismatch rejection")
	}
	// The matching tenant is accepted.
	ok := f.key.signIDToken(t, map[string]any{
		"iss": msTestIssuer("t-pinned"), "tid": "t-pinned", "aud": "app", "sub": "s",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
	})
	if _, err := f.verify(NativeVerifyParams{IDToken: ok, Audiences: []string{"app"}, MicrosoftTenantID: "t-pinned"}); err != nil {
		t.Fatalf("pinned tenant token should verify: %v", err)
	}
}

// TestNativeVerifier_Microsoft_NOAuth is the native counterpart to the hosted
// matrix: a multi-tenant token (no pin) is trusted only when xms_edov proves
// domain-owner verification; pinning the tenant (single id or allow-list) trusts
// it regardless, and an allow-list miss is rejected.
func TestNativeVerifier_Microsoft_NOAuth(t *testing.T) {
	const tid = "tenant-noauth"
	cases := []struct {
		name    string
		edov    any // nil = claim omitted
		params  NativeVerifyParams
		wantErr error // nil = success
	}{
		{"xms_edov bool true, no pin", true, NativeVerifyParams{}, nil},
		{"xms_edov string true, no pin", "true", NativeVerifyParams{}, nil},
		{"xms_edov absent, no pin rejected", nil, NativeVerifyParams{}, ErrEmailNotVerified},
		{"xms_edov false, no pin rejected", false, NativeVerifyParams{}, ErrEmailNotVerified},
		{"tenant pin trusts without xms_edov", nil, NativeVerifyParams{MicrosoftTenantID: tid}, nil},
		{"allow-list match trusts without xms_edov", nil, NativeVerifyParams{MicrosoftAllowedTenants: []string{"nope", tid}}, nil},
		{"allow-list miss rejected", nil, NativeVerifyParams{MicrosoftAllowedTenants: []string{"nope"}}, ErrIdentityVerification},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMSFixture(t)
			claims := map[string]any{
				"iss": msTestIssuer(tid), "tid": tid, "aud": "app", "sub": "s",
				"exp": f.now.Add(time.Hour), "iat": f.now, "email": "victim@contoso.com",
			}
			if tc.edov != nil {
				claims["xms_edov"] = tc.edov
			}
			p := tc.params
			p.IDToken = f.key.signIDToken(t, claims)
			p.Audiences = []string{"app"}
			res, err := f.verify(p)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("want success, got %v", err)
				}
				if res.Identity.Email != "victim@contoso.com" || !res.Identity.EmailVerified {
					t.Fatalf("bad identity: %+v", res.Identity)
				}
				return
			}
			if err == nil || !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestNativeVerifier_Microsoft_MissingExpRejected(t *testing.T) {
	f := newMSFixture(t)
	const tid = "t1"
	tok := f.key.signIDToken(t, map[string]any{
		"iss": msTestIssuer(tid), "tid": tid, "aud": "app", "sub": "s",
		"iat": f.now, "email": "a@b.com",
		// no exp
	})
	if _, err := f.verify(NativeVerifyParams{IDToken: tok, Audiences: []string{"app"}}); !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification for missing exp, got %v", err)
	}
}

func TestNativeVerifier_Microsoft_VerbatimNonce(t *testing.T) {
	f := newMSFixture(t)
	const tid = "t1"
	const rawNonce = "verbatim-nonce-123"
	// Microsoft echoes the nonce VERBATIM (not hashed like Apple).
	tok := f.key.signIDToken(t, map[string]any{
		"iss": msTestIssuer(tid), "tid": tid, "aud": "app", "sub": "s",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
		"nonce": rawNonce, "xms_edov": true,
	})
	if _, err := f.verify(NativeVerifyParams{IDToken: tok, Audiences: []string{"app"}, RawNonce: rawNonce}); err != nil {
		t.Fatalf("verbatim nonce should match: %v", err)
	}
	// A hashed value must NOT match (proves verbatim, not digest, comparison).
	hashed := f.key.signIDToken(t, map[string]any{
		"iss": msTestIssuer(tid), "tid": tid, "aud": "app", "sub": "s",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
		"nonce": appleNonceHashHex(rawNonce), "xms_edov": true,
	})
	if _, err := f.verify(NativeVerifyParams{IDToken: hashed, Audiences: []string{"app"}, RawNonce: rawNonce}); err == nil {
		t.Fatal("expected nonce mismatch: microsoft compares verbatim")
	}
}

func TestNativeVerifier_Microsoft_NoNonceProvided_Skipped(t *testing.T) {
	f := newMSFixture(t)
	const tid = "t1"
	tok := f.key.signIDToken(t, map[string]any{
		"iss": msTestIssuer(tid), "tid": tid, "aud": "app", "sub": "s",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
		"nonce": "some-server-nonce", "xms_edov": true,
	})
	if _, err := f.verify(NativeVerifyParams{IDToken: tok, Audiences: []string{"app"}}); err != nil {
		t.Fatalf("no client nonce should skip the check: %v", err)
	}
}

func TestNativeVerifier_Microsoft_NotConfigured(t *testing.T) {
	f := newMSFixture(t)
	const tid = "t1"
	tok := f.key.signIDToken(t, map[string]any{
		"iss": msTestIssuer(tid), "tid": tid, "aud": "app", "sub": "s",
		"exp": f.now.Add(time.Hour), "iat": f.now, "email": "a@b.com",
	})
	if _, err := f.verify(NativeVerifyParams{IDToken: tok, Audiences: nil}); err == nil {
		t.Fatal("expected rejection: no microsoft audiences configured")
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

// ── Replay-key derivation ────────────────────────────────────────────────

func TestNativeVerifier_ReplayKey_UsesJTIWhenPresent(t *testing.T) {
	f := newNativeFixture(t, []string{"aud-1"}, nil)
	tok := f.key.signIDToken(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": "s", "aud": "aud-1",
		"exp": f.now.Add(time.Hour), "iat": f.now,
		"email": "a@b.com", "email_verified": true,
		"jti": "unique-token-id-1",
	})
	res, err := f.verify(context.Background(), "google", tok, "")
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
		res, err := f.verify(context.Background(), "google", tok, "")
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
	res, err := f.verify(context.Background(), "google", tok, "")
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
	res, err := f.verify(context.Background(), "google", tok, "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.ExpiresAtMs != exp.UnixMilli() {
		t.Fatalf("ExpiresAtMs = %d, want token exp %d", res.ExpiresAtMs, exp.UnixMilli())
	}
}
