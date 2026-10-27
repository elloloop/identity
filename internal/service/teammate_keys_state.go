package service

import (
	"context"
	"errors"
)

const (
	TeammateKeyEd25519   = "ed25519"
	TeammateKeyECDSAP256 = "ecdsa_p256"

	TeammateKeyReleased  = "released"
	TeammateKeyReclaimed = "reclaimed"
	TeammateKeyRemoved   = "removed"
	TeammateKeyDrifted   = "drifted"

	MaxTeammateKeyChallenges = 16
)

// TeammateKey is one claim's registered public key. ClaimID is unique in a
// project, and so is PublicKey: one key per claim, for life.
type TeammateKey struct {
	ID               string
	ClaimID          string
	TeammateID       string
	CompanyID        string
	WorkstationID    string
	PublicKey        []byte
	Algorithm        string
	CreatedAtMs      int64
	RevokedAtMs      int64
	RevocationReason string
}

// TeammateKeyChallenge is a single-use challenge for one teammate key.
type TeammateKeyChallenge struct {
	ID          string
	KeyID       string
	Message     string
	CreatedAtMs int64
	ExpiresAtMs int64
}

var ErrTeammateKeyChallengeLimit = errors.New("too many pending teammate key challenges")

// TeammateKeyRepository stores teammate keys and their challenges in one
// project. RegisterTeammateKey inserts the key unless its claim already has
// one, and returns the claim's stored key either way. A public key already
// stored for another claim is ErrAlreadyExists. RevokeTeammateKey reports
// whether this call revoked the claim's key; it deletes the key's pending
// challenges. CreateTeammateKeyChallenge refuses a revoked or unknown key with
// ErrUnauthenticated, and ConsumeTeammateKeyChallenge consumes a challenge
// only while it is unexpired and its key unrevoked.
type TeammateKeyRepository interface {
	RegisterTeammateKey(context.Context, *TeammateKey) (*TeammateKey, error)
	GetTeammateKey(context.Context, string) (*TeammateKey, error)
	RevokeTeammateKey(context.Context, string, string, int64) (bool, error)
	CreateTeammateKeyChallenge(context.Context, *TeammateKeyChallenge) error
	GetTeammateKeyChallenge(context.Context, string) (*TeammateKeyChallenge, error)
	ConsumeTeammateKeyChallenge(context.Context, string, string, int64) (bool, error)
	DeleteExpiredTeammateKeyChallenges(context.Context, int64, int) error
	DeleteTeammateKeysRevokedBefore(context.Context, int64, int) error
}
