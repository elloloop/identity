// Package kmsaws implements a [jwt.Signer] that delegates the
// signature operation to AWS KMS. Private key material never leaves
// KMS; rotation is performed by switching the active key ARN in the
// signer's configuration (typically: create a new asymmetric KMS key,
// add it to the active set with the new kid as primary, wait for the
// access-token TTL, drop the old key).
//
// AWS KMS is the in-tree KMS reference for this server. We picked AWS
// over GCP KMS because (a) it has the smaller transitive dependency
// footprint in `go list -deps` and the fewer required IAM auxiliary
// services for a single-key deployment, and (b) the SDK's
// RSASSA_PKCS1_V1_5_SHA_256 + DIGEST signing flow maps 1:1 onto RS256
// without an extra envelope. Adding a GCP-KMS or Vault backend is a
// matter of implementing [jwt.Signer] in a sibling package — the
// verifier, JWKS handler, and every caller in the identity service
// already speak only to the interface.
//
// CI: the KMS backend is exercised against an in-process fake KMS
// client because real AWS credentials are not available in identity's
// CI matrix. A nightly / pre-release smoke against a real KMS key
// must run out-of-band before deploying this backend in production;
// see docs/key-rotation.md.
package kmsaws

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/elloloop/identity/pkg/jwt"
)

// API is the subset of the AWS KMS client surface this signer uses.
// Exposed so tests can plug a fake; the production wiring passes a
// real *kms.Client.
type API interface {
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// KeyRef identifies one KMS key entry in the signer's configuration.
type KeyRef struct {
	// KID is the JWS "kid" header value advertised in the JWKS
	// document. Stable across rotations of the same logical key; new
	// KMS key versions get fresh kids so verifiers can distinguish.
	KID string

	// KeyARN is the KMS key identifier (ARN, key ID, alias name, or
	// alias ARN — anything KMS accepts as KeyId).
	KeyARN string

	// NotBefore / ExpiresAt control rotation windows on the signer
	// side. Same semantics as [jwt.PublicKey].
	NotBefore time.Time
	ExpiresAt time.Time
}

// Config wires up a KMS-backed signer.
type Config struct {
	// Keys is the list of KMS-managed signing keys. Must contain at
	// least one in-force entry at New time.
	Keys []KeyRef

	// API is the AWS KMS client. Production callers pass a real
	// *kms.Client (constructed from aws-sdk-go-v2/config); tests pass
	// a stub.
	API API

	// Now overrides time.Now() for tests.
	Now func() time.Time
}

// Signer implements [jwt.Signer] against AWS KMS.
type Signer struct {
	cfg Config
	now func() time.Time

	mu        sync.RWMutex
	keys      []resolvedKey // sorted by NotBefore ascending
	byKID     map[string]resolvedKey
	activeKID string
}

type resolvedKey struct {
	ref KeyRef
	pub *rsa.PublicKey
}

// New constructs a Signer. It fetches every key's public half via
// GetPublicKey so the signer can publish JWKS without round-tripping
// to KMS per JWKS request. Returns an error when no in-force key is
// present or when any GetPublicKey call fails.
func New(ctx context.Context, cfg Config) (*Signer, error) {
	if cfg.API == nil {
		return nil, errors.New("kmsaws: API is required")
	}
	if len(cfg.Keys) == 0 {
		return nil, errors.New("kmsaws: at least one KeyRef is required")
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}

	s := &Signer{
		cfg: cfg,
		now: now,
	}
	if err := s.loadKeys(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Signer) loadKeys(ctx context.Context) error {
	seen := make(map[string]struct{}, len(s.cfg.Keys))
	keys := make([]resolvedKey, 0, len(s.cfg.Keys))
	for _, ref := range s.cfg.Keys {
		if ref.KID == "" {
			return errors.New("kmsaws: KeyRef missing kid")
		}
		if ref.KeyARN == "" {
			return fmt.Errorf("kmsaws: kid=%s missing key arn", ref.KID)
		}
		if _, dup := seen[ref.KID]; dup {
			return fmt.Errorf("kmsaws: duplicate kid %q", ref.KID)
		}
		seen[ref.KID] = struct{}{}

		out, err := s.cfg.API.GetPublicKey(ctx, &kms.GetPublicKeyInput{
			KeyId: aws.String(ref.KeyARN),
		})
		if err != nil {
			return fmt.Errorf("kmsaws: GetPublicKey kid=%s arn=%s: %w", ref.KID, ref.KeyARN, err)
		}
		if err := validateKMSKey(out); err != nil {
			return fmt.Errorf("kmsaws: kid=%s: %w", ref.KID, err)
		}
		pubAny, err := x509.ParsePKIXPublicKey(out.PublicKey)
		if err != nil {
			return fmt.Errorf("kmsaws: parsing public key kid=%s: %w", ref.KID, err)
		}
		rsaPub, ok := pubAny.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("kmsaws: kid=%s public key is not RSA (got %T)", ref.KID, pubAny)
		}
		keys = append(keys, resolvedKey{ref: ref, pub: rsaPub})
	}

	sort.SliceStable(keys, func(i, j int) bool {
		ni := keys[i].ref.NotBefore
		nj := keys[j].ref.NotBefore
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

	now := s.now()
	var activeKID string
	for i := len(keys) - 1; i >= 0; i-- {
		pk := jwt.PublicKey{
			KID:       keys[i].ref.KID,
			Key:       keys[i].pub,
			NotBefore: keys[i].ref.NotBefore,
			ExpiresAt: keys[i].ref.ExpiresAt,
		}
		if pk.IsActive(now) {
			activeKID = keys[i].ref.KID
			break
		}
	}
	if activeKID == "" {
		return fmt.Errorf("kmsaws: no active key at %s", now.Format(time.RFC3339))
	}

	byKID := make(map[string]resolvedKey, len(keys))
	for _, k := range keys {
		byKID[k.ref.KID] = k
	}

	s.mu.Lock()
	s.keys = keys
	s.byKID = byKID
	s.activeKID = activeKID
	s.mu.Unlock()
	return nil
}

func validateKMSKey(out *kms.GetPublicKeyOutput) error {
	if out == nil {
		return errors.New("nil GetPublicKey response")
	}
	if out.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
		return fmt.Errorf("KMS key usage must be SIGN_VERIFY, got %v", out.KeyUsage)
	}
	hasRSA := false
	for _, alg := range out.SigningAlgorithms {
		if alg == kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256 {
			hasRSA = true
			break
		}
	}
	if !hasRSA {
		return fmt.Errorf("KMS key does not advertise RSASSA_PKCS1_V1_5_SHA_256 (got %v)", out.SigningAlgorithms)
	}
	return nil
}

// ActiveKID returns the kid the signer stamps on new tokens.
func (s *Signer) ActiveKID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeKID
}

// Keys returns the current set of public keys.
func (s *Signer) Keys() []jwt.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]jwt.PublicKey, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, jwt.PublicKey{
			KID:       k.ref.KID,
			Key:       k.pub,
			NotBefore: k.ref.NotBefore,
			ExpiresAt: k.ref.ExpiresAt,
		})
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
	return k.pub, true
}

// SignAccessToken builds an access-token JWT and signs it via KMS.
func (s *Signer) SignAccessToken(ctx context.Context, claims jwt.Claims, expiry time.Duration) (string, error) {
	return s.SignClaims(ctx, claims.ClaimsMap(s.now(), expiry))
}

// SignClaims is the generic primitive: serialize claims, build the
// JWS signing input, send the SHA-256 digest to KMS, assemble the
// compact JWS.
func (s *Signer) SignClaims(ctx context.Context, claims map[string]any) (string, error) {
	s.mu.RLock()
	active, ok := s.byKID[s.activeKID]
	s.mu.RUnlock()
	if !ok {
		return "", errors.New("kmsaws: no active key")
	}

	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": active.ref.KID,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("kmsaws: encoding header: %w", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("kmsaws: encoding payload: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	digest := sha256.Sum256([]byte(signingInput))

	signOut, err := s.cfg.API.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(active.ref.KeyARN),
		Message:          digest[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return "", fmt.Errorf("kmsaws: KMS Sign: %w", err)
	}
	if len(signOut.Signature) == 0 {
		return "", errors.New("kmsaws: KMS Sign returned empty signature")
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(signOut.Signature)
	return signingInput + "." + sigB64, nil
}

// ARNFromConfig is a small helper for cmd/identity: parse the
// CSV-format key configuration into a []KeyRef.
//
// Format: "kid=ARN[,kid=ARN,...]". The single-key form
// "kid=ARN" or just "ARN" (with kid defaulting to a fingerprint of
// the ARN) is also accepted. NotBefore / ExpiresAt are not exposed
// via this helper — deployers wanting per-key rotation windows wire
// the config struct directly.
func ARNFromConfig(s string) ([]KeyRef, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty kms key config")
	}
	parts := strings.Split(s, ",")
	out := make([]KeyRef, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ref := KeyRef{}
		if i := strings.Index(p, "="); i > 0 {
			ref.KID = strings.TrimSpace(p[:i])
			ref.KeyARN = strings.TrimSpace(p[i+1:])
		} else {
			ref.KeyARN = p
			ref.KID = fingerprint(p)
		}
		if ref.KID == "" || ref.KeyARN == "" {
			return nil, fmt.Errorf("kms key entry %q missing kid or arn", p)
		}
		out = append(out, ref)
	}
	if len(out) == 0 {
		return nil, errors.New("no kms keys parsed")
	}
	return out, nil
}

// fingerprint derives a stable short kid from an ARN/alias when the
// deployer does not specify one explicitly. The kid carries no
// security significance — it only needs to be stable and unique
// across the active key set.
func fingerprint(s string) string {
	h := sha256.Sum256([]byte(s))
	return "k-" + base64.RawURLEncoding.EncodeToString(h[:6])
}
