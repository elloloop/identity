// Package jwt provides RS256 JWT signing, verification, and JWKS publishing
// with key rotation support.
//
// RS256 only. The active key in the supplied [KeyRing] signs new tokens.
// Verification looks up the key by the mandatory "kid" header. The JWKS
// endpoint publishes all public keys so third-party services can verify
// tokens without sharing a secret.
//
// Rotation procedure:
//  1. Add new key with Active=false to the key set.
//  2. Deploy — all instances now recognize the new key for verification.
//  3. Flip the new key to Active=true (and old key to Active=false).
//  4. Deploy — new tokens signed with new key, old tokens still verify.
//  5. Wait access_token lifetime (15 min) for all old tokens to expire.
//  6. Remove old key from set.
//  7. Deploy.
package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// SigningKey holds an RSA key pair for JWT signing.
type SigningKey struct {
	KID        string
	PrivateKey *rsa.PrivateKey // for signing
	PublicKey  *rsa.PublicKey  // for verification + JWKS
	Active     bool
}

// KeyRing manages multiple signing keys for rotation. Exactly one key is
// "active" and used to sign new tokens. All keys remain available for
// verification of previously-issued tokens.
type KeyRing struct {
	keys   map[string]SigningKey
	order  []string // insertion order for AllKIDs
	active SigningKey
}

// GenerateKey creates a fresh RSA 2048-bit key pair and returns it as a
// [SigningKey]. The key is in-memory only.
func GenerateKey(kid string) (SigningKey, error) {
	if kid == "" {
		return SigningKey{}, errors.New("kid is required")
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return SigningKey{}, fmt.Errorf("generating RSA key: %w", err)
	}
	return SigningKey{
		KID:        kid,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Active:     true,
	}, nil
}

// NewKeyRing creates a KeyRing from the given keys. Exactly one key must be
// marked Active. If no key is marked Active, the last key in the slice becomes
// active. If multiple keys are marked Active, an error is returned. An empty
// slice also returns an error.
func NewKeyRing(keys []SigningKey) (*KeyRing, error) {
	if len(keys) == 0 {
		return nil, errors.New("KeyRing requires at least one key")
	}

	kr := &KeyRing{
		keys:  make(map[string]SigningKey, len(keys)),
		order: make([]string, 0, len(keys)),
	}

	var activeKeys []string
	for _, k := range keys {
		if k.KID == "" {
			return nil, errors.New("all keys must have a non-empty KID")
		}
		if _, exists := kr.keys[k.KID]; exists {
			return nil, fmt.Errorf("duplicate kid: %s", k.KID)
		}
		kr.keys[k.KID] = k
		kr.order = append(kr.order, k.KID)
		if k.Active {
			activeKeys = append(activeKeys, k.KID)
		}
	}

	if len(activeKeys) > 1 {
		return nil, fmt.Errorf("multiple active JWT keys: %v", activeKeys)
	}

	if len(activeKeys) == 1 {
		kr.active = kr.keys[activeKeys[0]]
	} else {
		// Default to the last key if none marked active.
		last := keys[len(keys)-1]
		last.Active = true
		kr.keys[last.KID] = last
		kr.active = last
	}

	return kr, nil
}

// Active returns the key used to sign new tokens.
func (kr *KeyRing) Active() SigningKey {
	return kr.active
}

// Get returns the key with the given kid and true, or the zero value and false
// if not found.
func (kr *KeyRing) Get(kid string) (SigningKey, bool) {
	k, ok := kr.keys[kid]
	return k, ok
}

// AllKIDs returns the key IDs of every key in the ring, in insertion order.
func (kr *KeyRing) AllKIDs() []string {
	out := make([]string, len(kr.order))
	copy(out, kr.order)
	return out
}

// JWKS returns the JSON-encoded JWKS document (RFC 7517) containing every
// RSA public key in the ring. Suitable for serving at /.well-known/jwks.json.
func (kr *KeyRing) JWKS() ([]byte, error) {
	set := jwk.NewSet()
	for _, kid := range kr.order {
		sk := kr.keys[kid]
		key, err := jwk.FromRaw(sk.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("converting public key for kid=%s: %w", kid, err)
		}
		if err := key.Set(jwk.KeyIDKey, kid); err != nil {
			return nil, fmt.Errorf("setting kid: %w", err)
		}
		if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
			return nil, fmt.Errorf("setting alg: %w", err)
		}
		if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
			return nil, fmt.Errorf("setting use: %w", err)
		}
		if err := set.AddKey(key); err != nil {
			return nil, fmt.Errorf("adding key to set: %w", err)
		}
	}
	return json.Marshal(set)
}
