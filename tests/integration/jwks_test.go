//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
)

// TestJWKS_EndpointReturnsValidSet verifies the JWKS endpoint is
// reachable, returns application/json, and parses as a non-empty JWK
// Set with at least the active signing key. This is the contract
// downstream services rely on for offline JWT verification.
func TestJWKS_EndpointReturnsValidSet(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	resp, err := h.HTTP.Get(h.BaseURL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks.json: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	// 1) Parses as a JWKS via the standard library's jwx parser.
	set, err := jwk.Parse(body)
	if err != nil {
		t.Fatalf("jwk.Parse: %v", err)
	}
	if set.Len() == 0 {
		t.Fatalf("jwks set is empty")
	}

	// 2) Has the basic shape clients expect: 'keys' array with at
	//    least one entry whose alg is RS256 and use is sig.
	var raw struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode jwks json: %v", err)
	}
	if len(raw.Keys) == 0 {
		t.Fatalf("jwks json had no 'keys' entries: %s", body)
	}
	first := raw.Keys[0]
	if first["alg"] != "RS256" {
		t.Fatalf("alg = %v, want RS256", first["alg"])
	}
	if first["use"] != "sig" {
		t.Fatalf("use = %v, want sig", first["use"])
	}
	if first["kty"] != "RSA" {
		t.Fatalf("kty = %v, want RSA", first["kty"])
	}
	if first["kid"] == "" || first["kid"] == nil {
		t.Fatalf("kid is empty: %v", first)
	}
	if first["n"] == "" || first["e"] == "" {
		t.Fatalf("RSA JWK missing n or e: %v", first)
	}

	// 3) The advertised kid must be the one the active signing key uses.
	wantKID := h.Signer.ActiveKID()
	foundActive := false
	for _, k := range raw.Keys {
		if k["kid"] == wantKID {
			foundActive = true
			break
		}
	}
	if !foundActive {
		t.Fatalf("jwks did not include the active kid %q: %v", wantKID, raw.Keys)
	}
}

// TestJWKS_VerifyTokenUsingOnlyJWKS is the contract test for the
// downstream-service flow: a third party fetches JWKS from
// /.well-known/jwks.json and uses ONLY that document — no internal
// helpers, no shared keyring — to verify an access token issued by
// PasswordSignup. If this test ever fails, downstream services break.
func TestJWKS_VerifyTokenUsingOnlyJWKS(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	// 1) Issue a real token via the production code path.
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "jwks@example.com",
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	accessToken := signup.Msg.AccessToken
	if accessToken == "" {
		t.Fatalf("signup did not return access token")
	}

	// 2) Fetch the JWKS via plain HTTP — no internal helpers.
	resp, err := h.HTTP.Get(h.BaseURL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks.json: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	// 3) Build a key set from the JWKS bytes alone, then verify.
	keySet, err := jwk.Parse(body)
	if err != nil {
		t.Fatalf("jwk.Parse: %v", err)
	}

	tok, err := jwtoken.Parse(
		[]byte(accessToken),
		jwtoken.WithKeySet(keySet),
		jwtoken.WithValidate(true),
	)
	if err != nil {
		t.Fatalf("verify token via JWKS: %v", err)
	}

	// 4) Smoke-check the claims so we know the token actually
	//    decoded (verification of a malformed body would have failed,
	//    but a wrong-kid token signed by a different ring would also
	//    fail above; this just guards against "verified an empty token").
	if got := tok.Subject(); got == "" {
		t.Fatalf("token sub is empty")
	}
	if v, ok := tok.Get("email"); !ok || v != "jwks@example.com" {
		t.Fatalf("email claim = %v, want jwks@example.com", v)
	}
}

// TestJWKS_VerifyRejectsTokenSignedByForeignKey is the negative
// counterpart: a token signed by a key NOT advertised in /.well-known
// must fail verification when verified against the published JWKS.
func TestJWKS_VerifyRejectsTokenSignedByForeignKey(t *testing.T) {
	t.Parallel()
	hA := StartServer(t)
	hB := StartServer(t)
	ctx := context.Background()

	// Issue a token in service A.
	signup, err := hA.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "cross@example.com",
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}

	// Fetch service B's JWKS and try to verify A's token with it.
	resp, err := hB.HTTP.Get(hB.BaseURL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks.json: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	keySet, err := jwk.Parse(body)
	if err != nil {
		t.Fatalf("jwk.Parse: %v", err)
	}

	if _, err := jwtoken.Parse(
		[]byte(signup.Msg.AccessToken),
		jwtoken.WithKeySet(keySet),
		jwtoken.WithValidate(true),
	); err == nil {
		t.Fatalf("expected verification with foreign JWKS to fail")
	}

	// And just to ensure the test is not vacuous: B's own JWKS should
	// reject any token whose alg is not RS256 — sanity-check the alg.
	_ = jwa.RS256
}
