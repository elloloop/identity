package service

import "errors"

// ErrCounterStale is returned by UpdateAttestedDeviceCounter when the
// compare-and-swap loses: the stored sign count no longer matches the
// caller's expected value because a concurrent assertion advanced it.
// Distinct from ErrNotFound so a caller can tell a racing (possibly
// cloned) device from a deleted one — a lost CAS on a hardware-backed
// counter is exactly the signal App Attest's replay protection exists
// to surface.
var ErrCounterStale = errors.New("attested device counter stale")

// AttestedDeviceRecord is a hardware-attested client key: the durable
// outcome of a verified App Attest attestation. The public key and sign
// counter are replayed into assertion verification on every assurance
// refresh; the record carries NO user identity by design (assurance is
// about the client, not who is signed in).
type AttestedDeviceRecord struct {
	NodeID   string
	Platform string // "ios" (App Attest); platforms with persistent hardware keys only
	// KeyID is the attestation key identifier (standard-base64 SHA-256 of
	// the public key). Unique per project: one hardware key, one record.
	KeyID string
	// PublicKeySPKI is the attested public key, standard-base64 of the
	// DER (PKIX/SPKI) encoding.
	PublicKeySPKI string
	// SignCount is the last accepted assertion counter. Strictly
	// increasing; advanced only through UpdateAttestedDeviceCounter's CAS.
	SignCount int64
	// Environment is the attestation environment ("production" or
	// "development"), kept for audit.
	Environment string
	CreatedAt   int64 // epoch ms
	LastUsedAt  int64 // epoch ms
}

// AssuranceChallengeRecord is a one-time nonce issued to a client about
// to present attestation evidence. Consumed atomically exactly once;
// never bound to a user.
type AssuranceChallengeRecord struct {
	NodeID    string
	Challenge string // base64url nonce
	// Platform records which client surface requested the challenge
	// ("ios", "android"); informational.
	Platform  string
	ExpiresAt int64 // epoch ms
	CreatedAt int64 // epoch ms
}
