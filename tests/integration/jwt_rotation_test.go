//go:build integration && !realentdb && !realpostgres

// This test builds a memory-backed stack directly (NewMemRepo +
// newIssue3DB) rather than going through StartServer, because it needs
// to drive a custom file-backed signer through a key rotation — control
// StartServer's backend harnesses don't expose. The rotation contract
// lives entirely in the signer + JWKS endpoint and is independent of the
// repository backend, so there is nothing to gain from running it
// against entdb/postgres. The memory-only build constraint matches the
// helpers it depends on (issue3_harness.go); without it the test is
// pulled into the nightly's -tags=integration,realentdb build, where
// newIssue3DB does not exist and the whole package fails to compile.
package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	identityjwt "github.com/elloloop/identity/pkg/jwt"
	jwtfile "github.com/elloloop/identity/pkg/jwt/file"
	"github.com/elloloop/identity/pkg/passkeys"
)

// TestJWTSigner_FileRotation_TokenAStillValidatesAfterRotateToB is the
// rotation contract test required by issue #90:
//
//	"issue token signed with key A → rotate to key B → A-signed token
//	 still validates until its natural expiry; new tokens signed with B."
//
// It exercises the full HTTP stack (PasswordSignup → reload signer →
// JWKS endpoint → GetCurrentUser) against the production file-backed
// signer, then drops kA and confirms downstream verifiers can no longer
// accept the A-signed token.
func TestJWTSigner_FileRotation_TokenAStillValidatesAfterRotateToB(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keysPath := filepath.Join(dir, "keys.json")

	keyA := genRotationRSAKey(t)
	keyB := genRotationRSAKey(t)

	now := time.Now().UTC()
	writeRotationKeysJSON(t, keysPath, []rotationKey{
		{KID: "kA", NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(48 * time.Hour), Priv: keyA},
	})

	signer, err := jwtfile.New(keysPath, jwtfile.Options{})
	if err != nil {
		t.Fatalf("jwtfile.New: %v", err)
	}
	if got := signer.ActiveKID(); got != "kA" {
		t.Fatalf("pre-rotation active = %q, want kA", got)
	}

	cfg := newRotationCfg()
	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		t.Fatalf("passkeys: %v", err)
	}

	repo := NewMemRepo()
	auditDB := NewRecordingDB()
	dbAdapter := newIssue3DB(repo, auditDB)
	mailer := NewRecordingMailer()

	built, err := app.New(app.Deps{
		Config:             cfg,
		Logger:             zap.NewNop(),
		Signer:             signer,
		Repo:               repo,
		DB:                 dbAdapter,
		Passkeys:           pkSvc,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		EmailTransport:     mailer,
	})
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	built.Start()
	handler := built.Handler
	t.Cleanup(built.Stop)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client := identityconnectgen.NewIdentityServiceClient(srv.Client(), srv.URL)
	ctx := context.Background()

	// 1. Mint a token signed with key A.
	signupA, err := client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "rotateA@example.com",
		Password: rotationStrongPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup A: %v", err)
	}
	tokenA := signupA.Msg.AccessToken
	if tokenA == "" {
		t.Fatalf("signup A returned empty token")
	}
	if kid := tokenKID(t, tokenA); kid != "kA" {
		t.Fatalf("token A kid = %q, want kA", kid)
	}

	// 2. Rewrite the keys file with both keys, B as the new active.
	writeRotationKeysJSON(t, keysPath, []rotationKey{
		{KID: "kA", NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(48 * time.Hour), Priv: keyA},
		{KID: "kB", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(72 * time.Hour), Priv: keyB},
	})
	if err := signer.Reload(); err != nil {
		t.Fatalf("signer.Reload: %v", err)
	}
	if got := signer.ActiveKID(); got != "kB" {
		t.Fatalf("post-rotation active = %q, want kB", got)
	}

	// 3. Mint another token — must be signed with B.
	signupB, err := client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "rotateB@example.com",
		Password: rotationStrongPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup B: %v", err)
	}
	if kid := tokenKID(t, signupB.Msg.AccessToken); kid != "kB" {
		t.Fatalf("token B kid = %q, want kB", kid)
	}

	// 4. JWKS publishes both kids during the overlap.
	jwksKIDs := jwksKIDSet(t, srv.URL)
	if !jwksKIDs["kA"] {
		t.Fatalf("JWKS missing kA: %v", jwksKIDs)
	}
	if !jwksKIDs["kB"] {
		t.Fatalf("JWKS missing kB: %v", jwksKIDs)
	}

	// 5. The A-signed token still authenticates against the running
	//    service.
	req := connect.NewRequest(&identitypb.GetCurrentUserRequest{})
	req.Header().Set("Authorization", "Bearer "+tokenA)
	if _, err := client.GetCurrentUser(ctx, req); err != nil {
		t.Fatalf("A-signed token rejected after rotation: %v", err)
	}

	// 6. And verifies directly against the signer's KeyProvider
	//    surface, mirroring what a downstream service does after
	//    fetching JWKS.
	if _, err := identityjwt.VerifyAccessToken(tokenA, signer, "", "", false); err != nil {
		t.Fatalf("verify A token via KeyProvider: %v", err)
	}

	// 7. Retire kA — drop it from the file and reload.
	writeRotationKeysJSON(t, keysPath, []rotationKey{
		{KID: "kB", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(72 * time.Hour), Priv: keyB},
	})
	if err := signer.Reload(); err != nil {
		t.Fatalf("signer.Reload (retire A): %v", err)
	}

	// 8. JWKS no longer publishes kA and the A-signed token is now
	//    rejected.
	jwksKIDs = jwksKIDSet(t, srv.URL)
	if jwksKIDs["kA"] {
		t.Fatalf("JWKS still publishes kA after retirement: %v", jwksKIDs)
	}
	if _, err := identityjwt.VerifyAccessToken(tokenA, signer, "", "", false); err == nil {
		t.Fatalf("expected A-signed token to fail verification after kA retired")
	}
}

// ── helpers (kept private to this file) ─────────────────────────────

type rotationKey struct {
	KID       string
	NotBefore time.Time
	ExpiresAt time.Time
	Priv      *rsa.PrivateKey
}

type rotationKeyFile struct {
	Keys []rotationKeyEntry `json:"keys"`
}

type rotationKeyEntry struct {
	KID           string `json:"kid"`
	NotBefore     string `json:"not_before,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	PrivateKeyPEM string `json:"private_key_pem"`
}

func writeRotationKeysJSON(t *testing.T, path string, entries []rotationKey) {
	t.Helper()
	doc := rotationKeyFile{Keys: make([]rotationKeyEntry, 0, len(entries))}
	for _, e := range entries {
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(e.Priv),
		})
		entry := rotationKeyEntry{
			KID:           e.KID,
			PrivateKeyPEM: string(pemBytes),
		}
		if !e.NotBefore.IsZero() {
			entry.NotBefore = e.NotBefore.UTC().Format(time.RFC3339)
		}
		if !e.ExpiresAt.IsZero() {
			entry.ExpiresAt = e.ExpiresAt.UTC().Format(time.RFC3339)
		}
		doc.Keys = append(doc.Keys, entry)
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal keys file: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write keys file: %v", err)
	}
}

func genRotationRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return priv
}

// tokenKID extracts the JWS "kid" from the protected header of a
// compact JWS token, without verifying the signature.
func tokenKID(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not compact JWS: parts=%d", len(parts))
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(hdrBytes, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return h.KID
}

// jwksKIDSet fetches /.well-known/jwks.json and returns the set of kids.
func jwksKIDSet(t *testing.T, baseURL string) map[string]bool {
	t.Helper()
	resp, err := http.Get(baseURL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read jwks body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d", resp.StatusCode)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	out := map[string]bool{}
	for _, k := range doc.Keys {
		if s, ok := k["kid"].(string); ok {
			out[s] = true
		}
	}
	return out
}

// newRotationCfg returns a config sufficient for the rotation test.
func newRotationCfg() *config.Config {
	return &config.Config{
		DefaultTenantID:               "rotation",
		AuthAllowLocal:                true,
		PasswordSignupEnabled:         true,
		PasswordResetEnabled:          true,
		AllowedOrigins:                "http://localhost:9002",
		JWTExpirySeconds:              900,
		RefreshExpirySeconds:          604800,
		LoginMaxFailedAttempts:        5,
		LoginLockoutSeconds:           900,
		LoginChallengeExpirySeconds:   300,
		PasskeyRPID:                   "localhost",
		PasskeyRPName:                 "Rotation Test",
		PasskeyOrigin:                 "http://localhost:9002",
		PasskeyChallengeExpirySeconds: 300,
		QRLoginBaseURL:                "http://localhost:9002",
		QRLoginExpirySeconds:          300,
		TOTPIssuer:                    "Rotation Test",
		PasswordResetExpirySeconds:    3600,
		HTTPMaxBodyBytes:              1 << 20,
		TrustedProxies:                "127.0.0.1/32,::1/128",
	}
}

// rotationStrongPassword satisfies pkg/passwords.Validate.
const rotationStrongPassword = "Rotate-Password-1!aA"
