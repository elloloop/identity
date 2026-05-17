package file

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/jwt"
)

func TestSigner_LoadsKeysAndSigns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")

	priv := mustGenKey(t)
	writeKeys(t, path, []keysEntryFixture{
		{kid: "k1", priv: priv, notBeforeOff: -time.Minute, expiresAtOff: time.Hour},
	})

	s, err := New(path, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.ActiveKID(); got != "k1" {
		t.Fatalf("ActiveKID = %q, want k1", got)
	}

	tok, err := s.SignAccessToken(context.Background(), jwt.Claims{
		Sub:    "user-1",
		Email:  "u@example.com",
		Tenant: "t1",
	}, 15*time.Minute)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	if tok == "" {
		t.Fatalf("SignAccessToken returned empty string")
	}

	claims, err := jwt.VerifyAccessToken(tok, s, "t1", "", false)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Sub != "user-1" {
		t.Fatalf("sub = %q, want user-1", claims.Sub)
	}
}

func TestSigner_RotationAOldTokenStillVerifies(t *testing.T) {
	// The integration-level rotation contract: token issued by key A
	// must still verify after the file is reloaded with key B added
	// AND key A retained inside its expiry window. Tokens minted after
	// reload are signed with B.
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")

	keyA := mustGenKey(t)
	keyB := mustGenKey(t)

	// Snapshot 1: only key A.
	writeKeys(t, path, []keysEntryFixture{
		{kid: "kA", priv: keyA, notBeforeOff: -time.Hour, expiresAtOff: 24 * time.Hour},
	})
	s, err := New(path, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	aToken, err := s.SignAccessToken(context.Background(), jwt.Claims{
		Sub:    "user-1",
		Tenant: "t",
	}, time.Hour)
	if err != nil {
		t.Fatalf("SignAccessToken A: %v", err)
	}

	// Snapshot 2: key A retained + key B added with later NotBefore.
	writeKeys(t, path, []keysEntryFixture{
		{kid: "kA", priv: keyA, notBeforeOff: -time.Hour, expiresAtOff: 24 * time.Hour},
		{kid: "kB", priv: keyB, notBeforeOff: -time.Minute, expiresAtOff: 48 * time.Hour},
	})
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := s.ActiveKID(); got != "kB" {
		t.Fatalf("post-rotation active kid = %q, want kB", got)
	}

	// Pre-rotation token still verifies because kA is still in the
	// provider.
	if _, err := jwt.VerifyAccessToken(aToken, s, "t", "", false); err != nil {
		t.Fatalf("pre-rotation token failed to verify post-rotation: %v", err)
	}

	// Newly minted token must be signed by B.
	bToken, err := s.SignAccessToken(context.Background(), jwt.Claims{
		Sub:    "user-2",
		Tenant: "t",
	}, time.Hour)
	if err != nil {
		t.Fatalf("SignAccessToken B: %v", err)
	}
	if claims, err := jwt.VerifyAccessToken(bToken, s, "t", "", false); err != nil {
		t.Fatalf("post-rotation token verify: %v", err)
	} else if claims.Sub != "user-2" {
		t.Fatalf("post-rotation token sub = %q, want user-2", claims.Sub)
	}

	// Snapshot 3: drop key A entirely (simulates "old tokens expired,
	// retire key A").
	writeKeys(t, path, []keysEntryFixture{
		{kid: "kB", priv: keyB, notBeforeOff: -time.Minute, expiresAtOff: 48 * time.Hour},
	})
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload after retire: %v", err)
	}

	// Now the old kA token must fail.
	if _, err := jwt.VerifyAccessToken(aToken, s, "t", "", false); err == nil {
		t.Fatalf("expected pre-rotation token to fail after kA retired")
	}
}

func TestSigner_ExpiredKeyTokensStillVerifyUntilTokenExpiry(t *testing.T) {
	// Specifically: a key past its ExpiresAt but still present in the
	// file remains usable for verification. This is the grace window
	// during which in-flight tokens drain.
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")

	keyA := mustGenKey(t)

	// File at signing time: key A is active.
	now := time.Now().UTC()
	signSnapshot := keysFile{Keys: []fileEntry{
		{
			KID:           "kA",
			NotBefore:     now.Add(-time.Hour).Format(time.RFC3339),
			ExpiresAt:     now.Add(time.Hour).Format(time.RFC3339),
			PrivateKeyPEM: pemForKey(keyA),
		},
	}}
	writeRaw(t, path, signSnapshot)

	s, err := New(path, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok, err := s.SignAccessToken(context.Background(), jwt.Claims{Sub: "u", Tenant: "t"}, 12*time.Hour)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Pretend wall-clock advanced: simulate by reloading with a Now()
	// that's past key A's ExpiresAt, but we keep kA in the file plus
	// add an active kB so the snapshot has a valid signer.
	future := now.Add(2 * time.Hour)
	keyB := mustGenKey(t)
	postExpire := keysFile{Keys: []fileEntry{
		{
			KID:           "kA",
			NotBefore:     now.Add(-time.Hour).Format(time.RFC3339),
			ExpiresAt:     now.Add(time.Hour).Format(time.RFC3339),
			PrivateKeyPEM: pemForKey(keyA),
		},
		{
			KID:           "kB",
			NotBefore:     future.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAt:     future.Add(24 * time.Hour).Format(time.RFC3339),
			PrivateKeyPEM: pemForKey(keyB),
		},
	}}
	writeRaw(t, path, postExpire)
	s.now = func() time.Time { return future }
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := s.ActiveKID(); got != "kB" {
		t.Fatalf("active = %q, want kB", got)
	}

	// kA-signed token must still verify (kA's public key is still in
	// the provider). Token expiry has not yet been reached.
	if _, err := jwt.VerifyAccessToken(tok, s, "t", "", false); err != nil {
		t.Fatalf("verify after kA expiry: %v", err)
	}
}

func TestSigner_ErrorsOnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	writeRaw(t, path, keysFile{Keys: nil})
	if _, err := New(path, Options{}); err == nil {
		t.Fatalf("expected error for empty keys file")
	}
}

func TestSigner_ErrorsOnDuplicateKID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	priv := mustGenKey(t)
	writeKeys(t, path, []keysEntryFixture{
		{kid: "same", priv: priv, notBeforeOff: -time.Minute, expiresAtOff: time.Hour},
		{kid: "same", priv: priv, notBeforeOff: -time.Minute, expiresAtOff: time.Hour},
	})
	_, err := New(path, Options{})
	if err == nil {
		t.Fatalf("expected error for duplicate kid")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error = %v, want 'duplicate'", err)
	}
}

func TestSigner_ErrorsWhenAllKeysInactive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	priv := mustGenKey(t)
	// One expired key, one not-yet-valid: no key is currently active.
	writeKeys(t, path, []keysEntryFixture{
		{kid: "old", priv: priv, notBeforeOff: -24 * time.Hour, expiresAtOff: -time.Hour},
		{kid: "future", priv: priv, notBeforeOff: time.Hour, expiresAtOff: 24 * time.Hour},
	})
	_, err := New(path, Options{})
	if err == nil {
		t.Fatalf("expected error when no key is active")
	}
}

func TestSigner_ReloadIsAtomic(t *testing.T) {
	// Replacing the file with garbage must not corrupt the running
	// snapshot: the signer keeps signing with the previous snapshot
	// and Reload returns an error.
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	priv := mustGenKey(t)
	writeKeys(t, path, []keysEntryFixture{
		{kid: "k1", priv: priv, notBeforeOff: -time.Minute, expiresAtOff: time.Hour},
	})

	s, err := New(path, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Trash the file.
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("corrupt file: %v", err)
	}
	if err := s.Reload(); err == nil {
		t.Fatalf("expected Reload to fail on bad JSON")
	}

	if got := s.ActiveKID(); got != "k1" {
		t.Fatalf("ActiveKID after failed reload = %q, want k1 (unchanged)", got)
	}
	if _, err := s.SignAccessToken(context.Background(), jwt.Claims{Sub: "u", Tenant: "t"}, time.Minute); err != nil {
		t.Fatalf("signing after failed reload: %v", err)
	}
}

// TestSigner_KeysPublishesEveryEntry asserts the Keys() snapshot matches
// what the signer was constructed with — used by the JWKS endpoint to
// publish every public key.
func TestSigner_KeysPublishesEveryEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	a := mustGenKey(t)
	b := mustGenKey(t)
	writeKeys(t, path, []keysEntryFixture{
		{kid: "a", priv: a, notBeforeOff: -time.Hour, expiresAtOff: time.Hour},
		{kid: "b", priv: b, notBeforeOff: -time.Minute, expiresAtOff: 24 * time.Hour},
	})
	s, err := New(path, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pubs := s.Keys()
	if len(pubs) != 2 {
		t.Fatalf("Keys = %d, want 2", len(pubs))
	}
	seen := map[string]bool{}
	for _, p := range pubs {
		seen[p.KID] = true
		if p.Key == nil {
			t.Fatalf("Keys returned nil key for %q", p.KID)
		}
	}
	if !seen["a"] || !seen["b"] {
		t.Fatalf("Keys missing entries: %v", seen)
	}

	// JWKS rendering must succeed.
	jwksBytes, err := jwt.JWKS(s)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(jwksBytes) == 0 {
		t.Fatalf("JWKS empty")
	}

	// Get returns the right key.
	if pub, ok := s.Get("a"); !ok || pub == nil {
		t.Fatalf("Get(a) = %v %v", pub, ok)
	}
	if _, ok := s.Get("nonexistent"); ok {
		t.Fatalf("Get(nonexistent) = true")
	}
}

// TestSigner_KeysEmptyWhenNotLoaded covers the early-return branch of
// Keys/Get when the snapshot pointer is nil.
func TestSigner_KeysEmptyWhenNotLoaded(t *testing.T) {
	s := &Signer{}
	if got := s.Keys(); len(got) != 0 {
		t.Fatalf("Keys (empty signer) = %v", got)
	}
	if _, ok := s.Get("x"); ok {
		t.Fatalf("Get on empty signer returned ok")
	}
	if got := s.ActiveKID(); got != "" {
		t.Fatalf("ActiveKID (empty) = %q", got)
	}
}

func TestParsePEMPrivateKey_BadInputs(t *testing.T) {
	if _, err := parsePEMPrivateKey(""); err == nil {
		t.Fatalf("expected error for empty input")
	}
	if _, err := parsePEMPrivateKey("not a pem"); err == nil {
		t.Fatalf("expected error for non-PEM input")
	}
	// Valid PEM but not a private key (random bytes inside).
	bad := "-----BEGIN RSA PRIVATE KEY-----\nbm90IGEga2V5\n-----END RSA PRIVATE KEY-----\n" // #nosec G101 -- malformed test fixture, not a real key
	if _, err := parsePEMPrivateKey(bad); err == nil {
		t.Fatalf("expected error for malformed key bytes")
	}
}

func TestParsePEMPrivateKey_PKCS8(t *testing.T) {
	priv := mustGenKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	pkcs8PEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	got, err := parsePEMPrivateKey(pkcs8PEM)
	if err != nil {
		t.Fatalf("parsePEMPrivateKey PKCS8: %v", err)
	}
	if got.N.Cmp(priv.N) != 0 {
		t.Fatalf("modulus mismatch")
	}
}

func TestSigner_RejectsMissingKID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	priv := mustGenKey(t)
	doc := keysFile{Keys: []fileEntry{
		{KID: "", PrivateKeyPEM: pemForKey(priv)},
	}}
	writeRaw(t, path, doc)
	if _, err := New(path, Options{}); err == nil {
		t.Fatalf("expected error for missing kid")
	}
}

func TestSigner_RejectsBadNotBefore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	priv := mustGenKey(t)
	doc := keysFile{Keys: []fileEntry{
		{
			KID:           "k",
			NotBefore:     "not-a-timestamp",
			PrivateKeyPEM: pemForKey(priv),
		},
	}}
	writeRaw(t, path, doc)
	if _, err := New(path, Options{}); err == nil {
		t.Fatalf("expected error for bad not_before")
	}
}

func TestSigner_RejectsBadExpiresAt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	priv := mustGenKey(t)
	doc := keysFile{Keys: []fileEntry{
		{
			KID:           "k",
			NotBefore:     time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
			ExpiresAt:     "not-a-timestamp",
			PrivateKeyPEM: pemForKey(priv),
		},
	}}
	writeRaw(t, path, doc)
	if _, err := New(path, Options{}); err == nil {
		t.Fatalf("expected error for bad expires_at")
	}
}

func TestSigner_LogsReloadWhenLoggerProvided(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	priv := mustGenKey(t)
	writeKeys(t, path, []keysEntryFixture{
		{kid: "k1", priv: priv, notBeforeOff: -time.Minute, expiresAtOff: time.Hour},
	})

	var logs []string
	s, err := New(path, Options{
		Logf: func(format string, args ...any) {
			logs = append(logs, format)
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.ActiveKID(); got != "k1" {
		t.Fatalf("active = %q", got)
	}
	if len(logs) == 0 {
		t.Fatalf("expected at least one log line")
	}
}

func TestSigner_ReloadMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	priv := mustGenKey(t)
	writeKeys(t, path, []keysEntryFixture{
		{kid: "k1", priv: priv, notBeforeOff: -time.Minute, expiresAtOff: time.Hour},
	})
	s, err := New(path, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := s.Reload(); err == nil {
		t.Fatalf("expected error on missing file")
	}
	// Previous snapshot intact.
	if got := s.ActiveKID(); got != "k1" {
		t.Fatalf("active after failed reload = %q", got)
	}
}

func TestSigner_SignWithoutSnapshotFails(t *testing.T) {
	s := &Signer{now: time.Now}
	if _, err := s.SignAccessToken(context.Background(), jwt.Claims{Sub: "u"}, time.Minute); err == nil {
		t.Fatalf("expected error from uninitialized signer")
	}
}

func TestGenerateInMemory(t *testing.T) {
	s, err := GenerateInMemory("dev", time.Hour, Options{})
	if err != nil {
		t.Fatalf("GenerateInMemory: %v", err)
	}
	if got := s.ActiveKID(); got != "dev" {
		t.Fatalf("ActiveKID = %q, want dev", got)
	}
	tok, err := s.SignAccessToken(context.Background(), jwt.Claims{Sub: "u", Tenant: "t"}, time.Minute)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	if _, err := jwt.VerifyAccessToken(tok, s, "t", "", false); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestGenerateAndWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	s, err := GenerateAndWrite(path, "dev", 365*24*time.Hour, Options{})
	if err != nil {
		t.Fatalf("GenerateAndWrite: %v", err)
	}
	if got := s.ActiveKID(); got != "dev" {
		t.Fatalf("ActiveKID = %q, want dev", got)
	}
	// File must exist with 0600.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o, want 0600", got)
	}
}

func TestSigner_RejectsExpiresBeforeNotBefore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	priv := mustGenKey(t)
	doc := keysFile{Keys: []fileEntry{
		{
			KID:           "k",
			NotBefore:     time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
			ExpiresAt:     time.Now().UTC().Format(time.RFC3339),
			PrivateKeyPEM: pemForKey(priv),
		},
	}}
	writeRaw(t, path, doc)
	if _, err := New(path, Options{}); err == nil {
		t.Fatalf("expected error for ExpiresAt <= NotBefore")
	}
}

func TestWatchSIGHUP_ReloadsOnSignal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")

	keyA := mustGenKey(t)
	keyB := mustGenKey(t)

	writeKeys(t, path, []keysEntryFixture{
		{kid: "kA", priv: keyA, notBeforeOff: -time.Minute, expiresAtOff: time.Hour},
	})
	s, err := New(path, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.ActiveKID(); got != "kA" {
		t.Fatalf("initial active = %q, want kA", got)
	}

	var reloadOK atomic.Bool
	stop := WatchSIGHUP(s, func(err error) {
		t.Errorf("unexpected reload error: %v", err)
	})
	defer stop()

	// Re-render the file with kB as the active key, then SIGHUP.
	writeKeys(t, path, []keysEntryFixture{
		{kid: "kA", priv: keyA, notBeforeOff: -time.Minute, expiresAtOff: time.Hour},
		{kid: "kB", priv: keyB, notBeforeOff: -time.Second, expiresAtOff: 24 * time.Hour},
	})

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.ActiveKID() == "kB" {
			reloadOK.Store(true)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !reloadOK.Load() {
		t.Fatalf("active kid did not change to kB within deadline; got %q", s.ActiveKID())
	}
}

// ── helpers ─────────────────────────────────────────────────────────

type keysEntryFixture struct {
	kid          string
	priv         *rsa.PrivateKey
	notBeforeOff time.Duration
	expiresAtOff time.Duration
}

func writeKeys(t *testing.T, path string, entries []keysEntryFixture) {
	t.Helper()
	now := time.Now().UTC()
	doc := keysFile{Keys: make([]fileEntry, 0, len(entries))}
	for _, e := range entries {
		entry := fileEntry{
			KID:           e.kid,
			PrivateKeyPEM: pemForKey(e.priv),
		}
		if e.notBeforeOff != 0 {
			entry.NotBefore = now.Add(e.notBeforeOff).Format(time.RFC3339)
		}
		if e.expiresAtOff != 0 {
			entry.ExpiresAt = now.Add(e.expiresAtOff).Format(time.RFC3339)
		}
		doc.Keys = append(doc.Keys, entry)
	}
	writeRaw(t, path, doc)
}

func writeRaw(t *testing.T, path string, doc keysFile) {
	t.Helper()
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal keys doc: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write keys file: %v", err)
	}
}

func mustGenKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func pemForKey(priv *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}))
}
