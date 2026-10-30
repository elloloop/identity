package service

import (
	"context"
	"errors"
	"time"
)

const (
	TeammateKeyECDSAP256 = "ecdsa_p256"

	TeammateKeyReleased  = "released"
	TeammateKeyReclaimed = "reclaimed"
	TeammateKeyRemoved   = "removed"
	TeammateKeyDrifted   = "drifted"

	MaxTeammateKeyChallenges = 16
)

// TeammateKey is one claim's registered public key. ClaimID is unique in a
// project, and so is PublicKey: one key per claim, for life. RevokedAtMs is
// when the key stops working, which a revocation with a deadline sets in the
// future; zero means never. OwnerUserID is the person whose hire grant
// (GrantID) the key was registered with.
type TeammateKey struct {
	ID               string
	ClaimID          string
	TeammateID       string
	CompanyID        string
	WorkstationID    string
	PublicKey        []byte
	Algorithm        string
	GrantID          string
	OwnerUserID      string
	CreatedAtMs      int64
	RevokedAtMs      int64
	RevocationReason string
}

func (k *TeammateKey) revokedBy(nowMs int64) bool {
	return k.RevokedAtMs != 0 && k.RevokedAtMs <= nowMs
}

// TeammateKeyChallenge is a single-use challenge for one teammate key.
type TeammateKeyChallenge struct {
	ID          string
	KeyID       string
	Message     string
	CreatedAtMs int64
	ExpiresAtMs int64
}

// HireGrant is a person's single-use permission to register a key for one
// teammate in one placement for one company.
type HireGrant struct {
	ID          string
	OwnerUserID string
	TeammateID  string
	PlacementID string
	CompanyID   string
	CreatedAtMs int64
	ExpiresAtMs int64
}

var (
	ErrTeammateKeyChallengeLimit = errors.New("too many pending teammate key challenges")
	ErrHireGrantRefused          = errors.New("hire grant refused")
)

// TeammateKeyRepository stores teammate keys, their challenges and the hire
// grants they are registered with, in one project.
//
// RegisterTeammateKey returns the claim's stored key when it already has
// one, and otherwise inserts key in the same transaction that consumes its
// GrantID: the grant must be unused, unexpired at key.CreatedAtMs and name
// key's teammate and company and placementID; the stored key's OwnerUserID
// is the grant's. A grant that does not qualify, for a claim with no key, is
// ErrHireGrantRefused; a public key already stored for another claim is
// ErrAlreadyExists.
//
// RevokeTeammateKey makes the claim's key stop working at atMs unless it
// already stops at or before it, deletes the key's pending challenges when
// atMs is not after nowMs, and returns when the key stops working and
// whether this call changed it; zero when the claim has no key. A challenge
// that commits alongside the revocation stays until the sweeper removes it,
// and can never be consumed. CreateTeammateKeyChallenge refuses a key that
// is unknown or no longer working with ErrUnauthenticated, and
// ConsumeTeammateKeyChallenge consumes a challenge only while it is
// unexpired and its key still working, and returns when the key stops
// working as of that consumption, so a deadline set during the exchange is
// not missed.
type TeammateKeyRepository interface {
	CreateHireGrant(context.Context, *HireGrant) error
	RegisterTeammateKey(ctx context.Context, key *TeammateKey, placementID string) (*TeammateKey, error)
	GetTeammateKey(context.Context, string) (*TeammateKey, error)
	RevokeTeammateKey(ctx context.Context, claimID, reason string, atMs, nowMs int64) (int64, bool, error)
	CreateTeammateKeyChallenge(context.Context, *TeammateKeyChallenge) error
	GetTeammateKeyChallenge(context.Context, string) (*TeammateKeyChallenge, error)
	ConsumeTeammateKeyChallenge(ctx context.Context, challengeID, keyID string, nowMs int64) (bool, int64, error)
	DeleteExpiredTeammateKeyChallenges(context.Context, int64, int) error
	DeleteTeammateKeysRevokedBefore(context.Context, int64, int) error
	DeleteHireGrantsExpiredBefore(context.Context, int64, int) error
}

const (
	// TeammateKeyRetention is how long a revoked key is kept before the
	// sweeper deletes it.
	TeammateKeyRetention = 365 * 24 * time.Hour
	// HireGrantLifetime is how long a hire grant can be used. It covers a
	// claim waiting for a workstation; once used, a retried registration of
	// the same claim needs no live grant.
	HireGrantLifetime = 24 * time.Hour
	// MaxTeammateKeyDrain is how far ahead a revocation deadline may be.
	MaxTeammateKeyDrain = time.Hour
)
