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
