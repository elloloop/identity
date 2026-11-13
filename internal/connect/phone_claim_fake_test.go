package connect

import (
	"context"
	"errors"
	"fmt"

	"github.com/elloloop/identity/internal/service"
)

// ── Phone number claims ───────────────────────────────────────────────

func (r *fakeRepo) ClaimPhoneNumber(_ context.Context, userID, phoneNumber string, atMs, takeOverBeforeMs int64) (string, error) {
	if userID == "" || phoneNumber == "" {
		return "", errors.New("fake: ClaimPhoneNumber: missing user id or phone number")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return "", fmt.Errorf("fake: ClaimPhoneNumber: %w", service.ErrNotFound)
	}
	previous := ""
	if claim, held := r.phoneClaims[phoneNumber]; held && claim.userID != userID {
		if claim.claimedAt >= takeOverBeforeMs {
			return "", service.ErrPhoneNumberTaken
		}
		previous = claim.userID
		if prev, ok := r.users[previous]; ok && prev.PhoneNumber == phoneNumber {
			prev.PhoneNumber, prev.PhoneVerified, prev.PhoneVerifiedAt = "", false, 0
		}
	}
	for number, claim := range r.phoneClaims {
		if claim.userID == userID && number != phoneNumber {
			delete(r.phoneClaims, number)
		}
	}
	if claim, held := r.phoneClaims[phoneNumber]; !held || claim.userID != userID {
		r.phoneClaims[phoneNumber] = phoneClaim{userID: userID, claimedAt: atMs}
	}
	u.PhoneNumber, u.PhoneVerified, u.PhoneVerifiedAt = phoneNumber, true, atMs
	return previous, nil
}

func (r *fakeRepo) ReleasePhoneNumber(_ context.Context, userID string, _ int64) error {
	if userID == "" {
		return errors.New("fake: ReleasePhoneNumber: missing user id")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if u, ok := r.users[userID]; ok {
		u.PhoneNumber, u.PhoneVerified, u.PhoneVerifiedAt = "", false, 0
	}
	r.releasePhoneClaimsLocked(userID)
	return nil
}

// releasePhoneClaimsLocked deletes every claim userID holds. The caller
// holds r.mu.
func (r *fakeRepo) releasePhoneClaimsLocked(userID string) {
	for number, claim := range r.phoneClaims {
		if claim.userID == userID {
			delete(r.phoneClaims, number)
		}
	}
}

// phoneClaim is which account holds a verified phone number, and since when.
type phoneClaim struct {
	userID    string
	claimedAt int64
}

// mergePhoneClaimsLocked gives the survivor the retired account's phone
// claim when the merge moves the phone, and releases it otherwise. The
// caller holds r.mu.
func (r *fakeRepo) mergePhoneClaimsLocked(m service.AccountMerge) {
	for number, claim := range r.phoneClaims {
		switch {
		case claim.userID != m.OtherID:
		case m.MovePhone:
			r.phoneClaims[number] = phoneClaim{userID: m.SurvivorID, claimedAt: claim.claimedAt}
		default:
			delete(r.phoneClaims, number)
		}
	}
}
