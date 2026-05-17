package file

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/elloloop/identity/pkg/jwt"
)

// keysFile is the on-disk JSON document format.
//
//	{
//	  "keys": [
//	    {
//	      "kid": "k1",
//	      "not_before": "2026-05-01T00:00:00Z",
//	      "expires_at": "2026-08-01T00:00:00Z",
//	      "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----..."
//	    },
//	    {
//	      "kid": "k2",
//	      "not_before": "2026-07-15T00:00:00Z",
//	      "expires_at": "2026-10-15T00:00:00Z",
//	      "private_key_pem": "..."
//	    }
//	  ]
//	}
//
// not_before / expires_at are RFC 3339 timestamps; "" means "no bound".
// The active signing key is the entry with the latest not_before that
// is currently in force; ties break by file order.
type keysFile struct {
	Keys []fileEntry `json:"keys"`
}

type fileEntry struct {
	KID           string `json:"kid"`
	NotBefore     string `json:"not_before,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	PrivateKeyPEM string `json:"private_key_pem"`
}

// keySnapshot is the parsed, RSA-decoded set of keys the Signer
// currently sees. Replaced atomically by Reload.
type keySnapshot struct {
	keys      []parsedKey
	byKID     map[string]parsedKey
	activeKID string
}

type parsedKey struct {
	pub jwt.PublicKey

	// priv is the RSA private key. Always non-nil — keys without a
	// private key cannot sign and would never be written to this
	// store; the parser rejects them.
	priv *rsa.PrivateKey

	// signKey is the jwx jwk.Key precomputed with kid + RS256 headers
	// so SignAccessToken / SignClaims don't pay the FromRaw conversion
	// per request.
	signKey jwk.Key
}

// Signer is the file-backed implementation of [jwt.Signer]. It is safe
// for concurrent use; Reload swaps the snapshot atomically.
type Signer struct {
	path string

	snap atomic.Pointer[keySnapshot]

	now    func() time.Time
	mu     sync.Mutex // serialises Reload calls
	logger func(format string, args ...any)
}

// Options tunes how the Signer reads the file. Zero values give the
// production defaults.
type Options struct {
	// Now overrides time.Now() for tests. Production wiring leaves
	// this nil; the signer falls back to time.Now().UTC().
	Now func() time.Time

	// Logf is a hook for logging Reload outcomes. nil disables logging.
	Logf func(format string, args ...any)
}

// New constructs a Signer by reading the keys file at path. Returns an
// error when the file is missing, unparseable, or contains no usable
// active key. The caller wires up reload triggers separately (see
// [WatchSIGHUP]).
func New(path string, opts Options) (*Signer, error) {
	s := &Signer{
		path:   path,
		now:    opts.Now,
		logger: opts.Logf,
	}
	if s.now == nil {
		s.now = func() time.Time { return time.Now().UTC() }
	}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload re-reads the keys file and atomically swaps the in-memory
// snapshot. Existing in-flight signing operations continue to use the
// previous snapshot; new operations after Reload returns use the new
// one. Returns an error without changing state when the new file
// cannot be parsed or has no active key.
func (s *Signer) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("reading keys file %s: %w", s.path, err)
	}

	var doc keysFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parsing keys file %s: %w", s.path, err)
	}

	snap, err := parseSnapshot(doc, s.now())
	if err != nil {
		return fmt.Errorf("loading keys from %s: %w", s.path, err)
	}

	s.snap.Store(snap)
	if s.logger != nil {
		kids := make([]string, 0, len(snap.keys))
		for _, k := range snap.keys {
			kids = append(kids, k.pub.KID)
		}
		s.logger("file_signer_reloaded path=%s active=%s kids=%v", s.path, snap.activeKID, kids)
	}
	return nil
}

// ActiveKID returns the kid the signer will stamp on new tokens.
func (s *Signer) ActiveKID() string {
	snap := s.snap.Load()
	if snap == nil {
		return ""
	}
	return snap.activeKID
}

// Keys returns every public key the signer currently advertises,
// including keys past their ExpiresAt. The slice is freshly allocated;
// callers may modify it.
func (s *Signer) Keys() []jwt.PublicKey {
	snap := s.snap.Load()
	if snap == nil {
		return []jwt.PublicKey{}
	}
	out := make([]jwt.PublicKey, 0, len(snap.keys))
	for _, k := range snap.keys {
		out = append(out, k.pub)
	}
	return out
}

// Get returns the public key for the supplied kid, or false.
func (s *Signer) Get(kid string) (*rsa.PublicKey, bool) {
	snap := s.snap.Load()
	if snap == nil {
		return nil, false
	}
	k, ok := snap.byKID[kid]
	if !ok {
		return nil, false
	}
	return k.pub.Key, true
}

// SignAccessToken builds and signs an access-token JWT.
func (s *Signer) SignAccessToken(ctx context.Context, claims jwt.Claims, expiry time.Duration) (string, error) {
	return s.SignClaims(ctx, claims.ClaimsMap(s.now(), expiry))
}

// SignClaims is the generic JWT-signing primitive.
func (s *Signer) SignClaims(_ context.Context, claims map[string]any) (string, error) {
	snap := s.snap.Load()
	if snap == nil {
		return "", errors.New("file signer not initialized")
	}
	active, ok := snap.byKID[snap.activeKID]
	if !ok {
		return "", fmt.Errorf("file signer has no active key (kid=%q)", snap.activeKID)
	}

	builder := jwtoken.NewBuilder()
	for k, v := range claims {
		builder = builder.Claim(k, v)
	}
	tok, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("building token: %w", err)
	}

	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, active.signKey))
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}
	return string(signed), nil
}

// GenerateInMemory constructs a Signer with a freshly-generated RSA
// key. The key never touches disk. This is the dev-fallback path
// cmd/identity uses when no keys file is configured — the scratch
// Docker image has no /tmp to write to, and a deployer who hasn't
// set GATEWAY_JWT_KEYS_FILE never wanted persistent keys anyway.
//
// Production deployments always set GATEWAY_JWT_KEYS_FILE; this
// fallback exists only so a freshly-pulled binary boots cleanly.
func GenerateInMemory(kid string, validFor time.Duration, opts Options) (*Signer, error) {
	if kid == "" {
		return nil, errors.New("kid is required")
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}

	now := time.Now().UTC()
	notBefore := now.Add(-time.Minute)
	var expiresAt time.Time
	if validFor > 0 {
		expiresAt = now.Add(validFor)
	}

	signKey, err := jwk.FromRaw(priv)
	if err != nil {
		return nil, fmt.Errorf("convert to jwk: %w", err)
	}
	if err := signKey.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("set kid: %w", err)
	}
	if err := signKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, fmt.Errorf("set alg: %w", err)
	}

	pk := parsedKey{
		pub: jwt.PublicKey{
			KID:       kid,
			Key:       &priv.PublicKey,
			NotBefore: notBefore,
			ExpiresAt: expiresAt,
		},
		priv:    priv,
		signKey: signKey,
	}
	snap := &keySnapshot{
		keys:      []parsedKey{pk},
		byKID:     map[string]parsedKey{kid: pk},
		activeKID: kid,
	}

	s := &Signer{
		now:    opts.Now,
		logger: opts.Logf,
	}
	if s.now == nil {
		s.now = func() time.Time { return time.Now().UTC() }
	}
	s.snap.Store(snap)
	return s, nil
}

// GenerateAndWrite is a convenience used by tests when they specifically
// want a keys.json file on disk: it creates a fresh RSA-2048 key,
// writes a one-entry keys file at path, and returns the resulting
// Signer. Production deployments always ship their own keys file.
func GenerateAndWrite(path, kid string, validFor time.Duration, opts Options) (*Signer, error) {
	if kid == "" {
		return nil, errors.New("kid is required")
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	now := time.Now().UTC()
	entry := fileEntry{
		KID:           kid,
		NotBefore:     now.Add(-time.Minute).Format(time.RFC3339),
		PrivateKeyPEM: string(privPEM),
	}
	if validFor > 0 {
		entry.ExpiresAt = now.Add(validFor).Format(time.RFC3339)
	}
	doc := keysFile{Keys: []fileEntry{entry}}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding keys file: %w", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return nil, fmt.Errorf("writing keys file %s: %w", path, err)
	}
	return New(path, opts)
}

// parseSnapshot decodes the on-disk document, validates every entry,
// and picks the active key.
func parseSnapshot(doc keysFile, now time.Time) (*keySnapshot, error) {
	if len(doc.Keys) == 0 {
		return nil, errors.New("keys file is empty")
	}

	snap := &keySnapshot{
		byKID: make(map[string]parsedKey, len(doc.Keys)),
	}

	for _, entry := range doc.Keys {
		if entry.KID == "" {
			return nil, errors.New("key entry missing kid")
		}
		if _, dup := snap.byKID[entry.KID]; dup {
			return nil, fmt.Errorf("duplicate kid %q", entry.KID)
		}

		priv, err := parsePEMPrivateKey(entry.PrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("kid=%s: %w", entry.KID, err)
		}

		var notBefore, expiresAt time.Time
		if entry.NotBefore != "" {
			notBefore, err = time.Parse(time.RFC3339, entry.NotBefore)
			if err != nil {
				return nil, fmt.Errorf("kid=%s: parsing not_before: %w", entry.KID, err)
			}
			notBefore = notBefore.UTC()
		}
		if entry.ExpiresAt != "" {
			expiresAt, err = time.Parse(time.RFC3339, entry.ExpiresAt)
			if err != nil {
				return nil, fmt.Errorf("kid=%s: parsing expires_at: %w", entry.KID, err)
			}
			expiresAt = expiresAt.UTC()
		}
		if !notBefore.IsZero() && !expiresAt.IsZero() && !expiresAt.After(notBefore) {
			return nil, fmt.Errorf("kid=%s: expires_at must be after not_before", entry.KID)
		}

		signKey, err := jwk.FromRaw(priv)
		if err != nil {
			return nil, fmt.Errorf("kid=%s: converting to jwk: %w", entry.KID, err)
		}
		if err := signKey.Set(jwk.KeyIDKey, entry.KID); err != nil {
			return nil, fmt.Errorf("kid=%s: setting kid header: %w", entry.KID, err)
		}
		if err := signKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
			return nil, fmt.Errorf("kid=%s: setting alg header: %w", entry.KID, err)
		}

		pk := parsedKey{
			pub: jwt.PublicKey{
				KID:       entry.KID,
				Key:       &priv.PublicKey,
				NotBefore: notBefore,
				ExpiresAt: expiresAt,
			},
			priv:    priv,
			signKey: signKey,
		}
		snap.byKID[entry.KID] = pk
		snap.keys = append(snap.keys, pk)
	}

	// Active key = the in-force key with the latest NotBefore (file
	// order breaks ties). This means deployers rotate by appending a
	// new entry with a fresh NotBefore that has just passed; the new
	// key takes over the moment the file is loaded after that instant.
	sort.SliceStable(snap.keys, func(i, j int) bool {
		ni := snap.keys[i].pub.NotBefore
		nj := snap.keys[j].pub.NotBefore
		if ni.Equal(nj) {
			return false
		}
		if ni.IsZero() {
			return true
		}
		if nj.IsZero() {
			return false
		}
		return ni.Before(nj)
	})

	for i := len(snap.keys) - 1; i >= 0; i-- {
		if snap.keys[i].pub.IsActive(now) {
			snap.activeKID = snap.keys[i].pub.KID
			break
		}
	}
	if snap.activeKID == "" {
		return nil, fmt.Errorf("no active signing key at %s (every entry is expired or not-yet-valid)", now.Format(time.RFC3339))
	}

	return snap, nil
}

// parsePEMPrivateKey decodes a PEM-encoded RSA private key (PKCS#1 or
// PKCS#8). Other key types are rejected because the identity service
// uses RS256 only.
func parsePEMPrivateKey(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	any, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	rsaKey, ok := any.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rsaKey, nil
}
