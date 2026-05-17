// Package jwt provides RS256 JWT signing, verification, and JWKS
// publishing. It defines the pluggable [Signer] / [KeyProvider]
// interfaces that the identity service uses for access tokens, plus
// access-token claim types and a verifier that consumes any
// [KeyProvider].
//
// Concrete backends live in subpackages:
//
//   - [pkg/jwt/file] — file-backed signer (default). Reads a JSON keys
//     file at startup, reloads on SIGHUP. Suitable for any deployment
//     that does not require an external KMS.
//   - [pkg/jwt/kmsaws] — AWS KMS-backed signer. Delegates the signing
//     operation to AWS KMS; private key material never leaves KMS.
//
// Adding a new backend (GCP KMS, HashiCorp Vault, hardware HSM, …) is
// a matter of implementing [Signer]. The verifier, the JWKS HTTP
// handler, and every caller in this repo speak only to the interface.
package jwt

import (
	"context"
	"crypto/rsa"
	"time"
)

// PublicKey describes one signing key's public half plus its rotation
// metadata. Returned by [KeyProvider] so the JWKS endpoint can publish
// every key whose tokens may still be in flight.
type PublicKey struct {
	// KID is the JWS "kid" header value stamped on tokens this key signs.
	KID string

	// Key is the RSA public key. Always non-nil for keys returned from
	// [KeyProvider.Keys].
	Key *rsa.PublicKey

	// NotBefore is the earliest moment this key is allowed to sign new
	// tokens. Zero means "no lower bound".
	NotBefore time.Time

	// ExpiresAt is the moment after which the key must no longer sign
	// new tokens. Zero means "never expires". A key past its ExpiresAt
	// still participates in verification (so tokens minted before
	// expiry remain valid until their own [Claims.ExpiresAt]) until the
	// key is removed from the provider entirely.
	ExpiresAt time.Time
}

// IsExpired reports whether the key's ExpiresAt has passed at the
// supplied time. Keys with a zero ExpiresAt are never expired.
func (k PublicKey) IsExpired(now time.Time) bool {
	if k.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(k.ExpiresAt)
}

// IsActive reports whether the key may sign new tokens at the supplied
// time: NotBefore has elapsed (or is zero) and ExpiresAt has not yet
// arrived.
func (k PublicKey) IsActive(now time.Time) bool {
	if !k.NotBefore.IsZero() && now.Before(k.NotBefore) {
		return false
	}
	return !k.IsExpired(now)
}

// KeyProvider exposes the public-key view of a signer's key store. It
// is the surface used by the verifier and by the JWKS HTTP handler.
type KeyProvider interface {
	// Keys returns every public key the provider currently advertises,
	// including keys past their ExpiresAt (so in-flight tokens still
	// verify). The slice MUST NOT be nil; it MAY be empty during
	// rotation only if the provider has no usable keys (which the
	// caller treats as a fatal condition at startup).
	//
	// Order is implementation-defined but stable for a given snapshot.
	Keys() []PublicKey

	// Get returns the public key for the supplied kid, or false when
	// no such key is published. Includes expired-but-not-yet-removed
	// keys, so the verifier can still validate tokens minted before
	// rotation completed.
	Get(kid string) (*rsa.PublicKey, bool)
}

// Signer issues RS256-signed JWTs using the active key in whatever key
// store the deployer wired up. Implementations MUST also expose the
// [KeyProvider] surface so that signing and verification stay in sync
// without per-backend branches in the HTTP handler.
type Signer interface {
	KeyProvider

	// ActiveKID returns the kid the signer stamps on new tokens. It is
	// the kid of the currently-active key. Empty result indicates a
	// misconfigured signer (no usable active key); callers must treat
	// this as a fatal condition at startup.
	ActiveKID() string

	// SignAccessToken builds a standard access-token JWT from claims,
	// stamps iat/exp, signs with the active key, and returns the
	// compact-serialized JWS string.
	SignAccessToken(ctx context.Context, claims Claims, expiry time.Duration) (string, error)

	// SignClaims is the generic primitive: serialize the supplied claim
	// map as a JWT, sign with the active key, return the compact JWS.
	// Use this for non-access-token JWTs (e.g. OAuth state tokens).
	// Claim names follow the standard JWT/JWS conventions ("iat",
	// "exp", custom names).
	SignClaims(ctx context.Context, claims map[string]any) (string, error)
}
