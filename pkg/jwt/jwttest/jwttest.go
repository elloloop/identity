// Package jwttest provides an in-process [jwt.Signer] for tests. It
// generates RSA keys on the fly and never touches disk or external
// services. Production code MUST NOT import this package.
package jwttest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/elloloop/identity/pkg/jwt"
)

// Signer is an in-memory [jwt.Signer] for tests. All operations are
// goroutine-safe; AddKey / SetActive / DropKey may be called
// concurrently with Sign / Verify.
type Signer struct {
	mu        sync.RWMutex
	keys      []*signedKey
	byKID     map[string]*signedKey
	activeKID string
}

type signedKey struct {
	pub jwt.PublicKey
	jwk jwk.Key
}

// NewSigner constructs a Signer with a single key (the active one).
// Subsequent keys are added with AddKey.
func NewSigner(tb testing.TB, kid string) *Signer {
	tb.Helper()
	s := &Signer{byKID: make(map[string]*signedKey)}
	s.AddKey(tb, kid)
	s.SetActive(kid)
	return s
}

// AddKey generates a fresh RSA-2048 key and registers it under kid.
func (s *Signer) AddKey(tb testing.TB, kid string) {
	tb.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("jwttest: GenerateKey: %v", err)
	}
	signKey, err := jwk.FromRaw(priv)
	if err != nil {
		tb.Fatalf("jwttest: jwk.FromRaw: %v", err)
	}
	_ = signKey.Set(jwk.KeyIDKey, kid)
	_ = signKey.Set(jwk.AlgorithmKey, jwa.RS256)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byKID[kid]; exists {
		tb.Fatalf("jwttest: duplicate kid %q", kid)
	}
	mk := &signedKey{
		pub: jwt.PublicKey{KID: kid, Key: &priv.PublicKey},
		jwk: signKey,
	}
	s.keys = append(s.keys, mk)
	s.byKID[kid] = mk
}

// SetActive marks the kid as the active signing key.
func (s *Signer) SetActive(kid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byKID[kid]; !ok {
		panic(fmt.Sprintf("jwttest: SetActive: unknown kid %q", kid))
	}
	s.activeKID = kid
}

// DropKey removes a key entirely. Tokens signed with that kid will no
// longer verify.
func (s *Signer) DropKey(kid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byKID, kid)
	out := s.keys[:0]
	for _, k := range s.keys {
		if k.pub.KID != kid {
			out = append(out, k)
		}
	}
	s.keys = out
}

// ActiveKID returns the kid stamped on new tokens.
func (s *Signer) ActiveKID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeKID
}

// Keys returns the snapshot of public keys.
func (s *Signer) Keys() []jwt.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]jwt.PublicKey, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, k.pub)
	}
	return out
}

// Get returns the public key for the supplied kid.
func (s *Signer) Get(kid string) (*rsa.PublicKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.byKID[kid]
	if !ok {
		return nil, false
	}
	return k.pub.Key, true
}

// SignAccessToken signs an access-token JWT.
func (s *Signer) SignAccessToken(ctx context.Context, claims jwt.Claims, expiry time.Duration) (string, error) {
	return s.SignClaims(ctx, claims.ClaimsMap(time.Now().UTC(), expiry))
}

// SignClaims signs a generic claim map.
func (s *Signer) SignClaims(_ context.Context, claims map[string]any) (string, error) {
	s.mu.RLock()
	k, ok := s.byKID[s.activeKID]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("jwttest: active kid %q not present", s.activeKID)
	}
	b := jwtoken.NewBuilder()
	for n, v := range claims {
		b = b.Claim(n, v)
	}
	tok, err := b.Build()
	if err != nil {
		return "", err
	}
	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, k.jwk))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}
