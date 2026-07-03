package oauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// This file is the single home for the security-sensitive ID-token
// verification rules shared by every provider (the hosted Exchangers —
// Google/Apple/Microsoft/generic OIDC — and the native mobile-SDK
// verifier). Each rule is defined ONCE here so a change (e.g. clock-skew
// tolerance, key-rotation handling, alg pinning) applies uniformly.

var errKeyNotFound = errors.New("key not found in jwks")

// verifyJWS verifies the signature on a compact JWS using the provided JWK
// set (matching kid → key), restricting the accepted signature algorithm to
// RS256 (what Google + Microsoft + Apple sign ID tokens with). Returns the
// decoded payload bytes on success.
func verifyJWS(raw string, set jwk.Set) ([]byte, error) {
	return verifyJWSWithAlgs(raw, set, jwa.RS256)
}

// verifyJWSWithAlgs verifies the signature on a compact JWS using the
// provided JWK set, restricting the accepted signature algorithm to one of
// allowedAlgs. Pinning the algorithm prevents alg-substitution attacks (e.g.
// forging an HS256 token using the public key as the secret). Returns the
// decoded payload bytes on success.
func verifyJWSWithAlgs(raw string, set jwk.Set, allowedAlgs ...jwa.SignatureAlgorithm) ([]byte, error) {
	// Parse the message header to find the kid.
	msg, err := jws.Parse([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("parse jws: %w", err)
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, errors.New("jws has no signatures")
	}
	hdr := sigs[0].ProtectedHeaders()
	kid := hdr.KeyID()
	alg := hdr.Algorithm()
	if alg == "" {
		return nil, errors.New("jws missing alg")
	}
	algAllowed := false
	for _, a := range allowedAlgs {
		if alg == a {
			algAllowed = true
			break
		}
	}
	if !algAllowed {
		return nil, fmt.Errorf("unexpected jws alg: %s", alg)
	}
	var key jwk.Key
	if kid != "" {
		k, ok := set.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("%w: kid=%q", errKeyNotFound, kid)
		}
		key = k
	} else {
		// No kid — try the first key.
		if set.Len() == 0 {
			return nil, fmt.Errorf("%w: empty", errKeyNotFound)
		}
		k, ok := set.Key(0)
		if !ok {
			return nil, fmt.Errorf("%w: first key missing", errKeyNotFound)
		}
		key = k
	}
	verified, err := jws.Verify([]byte(raw), jws.WithKey(alg, key))
	if err != nil {
		return nil, fmt.Errorf("verify jws: %w", err)
	}
	return verified, nil
}

// verifyJWSWithRotation verifies a compact JWS against a JWKS cache,
// restricting the signature to one of algs, and retrying once after a cache
// invalidation if the signing key was not found (handles provider key
// rotation). It is the single definition of the "fetch keys, verify
// signature, retry on rotation" rule used by every ID-token verifier. Errors
// wrap ErrIdentityVerification so callers can map any failure to one safe
// Unauthenticated response.
func verifyJWSWithRotation(ctx context.Context, cache *jwksCache, raw string, algs ...jwa.SignatureAlgorithm) ([]byte, error) {
	set, err := cache.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: jwks: %w", ErrIdentityVerification, err)
	}
	payload, err := verifyJWSWithAlgs(raw, set, algs...)
	if err != nil && errors.Is(err, errKeyNotFound) {
		// A signing key we don't know about may indicate a rotation;
		// invalidate the cache and retry once with fresh keys.
		cache.Invalidate()
		set2, fErr := cache.Get(ctx)
		if fErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrIdentityVerification, err)
		}
		payload, err = verifyJWSWithAlgs(raw, set2, algs...)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIdentityVerification, err)
	}
	return payload, nil
}

// checkTokenTimes enforces exp (not in the past) and iat (not in the future,
// allowing 2 minutes of clock skew) against now. A zero exp or iat is
// tolerated — a provider that treats either as REQUIRED must check its
// presence separately before calling this. Errors wrap ErrIdentityVerification.
func checkTokenTimes(tok jwt.Token, now time.Time) error {
	if exp := tok.Expiration(); !exp.IsZero() && now.After(exp) {
		return fmt.Errorf("%w: token expired", ErrIdentityVerification)
	}
	if iat := tok.IssuedAt(); !iat.IsZero() && iat.After(now.Add(2*time.Minute)) {
		return fmt.Errorf("%w: iat in the future", ErrIdentityVerification)
	}
	return nil
}

// claimIsTrue collapses a polymorphic boolean JSON claim — emitted by some
// providers as a real bool and by others as the string "true"/"false" — to a
// Go bool. Microsoft is the worst offender (email_verified and xms_edov both
// arrive either way depending on the flow); Apple's email_verified is the same
// shape. Every provider path normalizes such a claim through this one helper so
// the bool-vs-string handling can never diverge between them.
func claimIsTrue(v interface{}) bool {
	switch ev := v.(type) {
	case bool:
		return ev
	case string:
		return ev == "true"
	default:
		return false
	}
}
