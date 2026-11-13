package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// ── Recovery emails ───────────────────────────────────────────────────

// recoveryEmailHeldLocked reports whether any account holds email as a
// recovery email, under FoldEmail. The caller holds r.mu.
func (r *fakeRepo) recoveryEmailHeldLocked(email string) bool {
	fold := FoldEmail(email)
	for _, list := range r.recoveryEmails {
		for _, e := range list {
			if FoldEmail(e.Email) == fold {
				return true
			}
		}
	}
	return false
}

func (r *fakeRepo) UpsertRecoveryEmailCode(_ context.Context, rec *RecoveryEmailCodeRecord) (string, error) {
	if rec == nil {
		return "", errors.New("fake: UpsertRecoveryEmailCode: nil record")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rec.NodeID = nextNodeID()
	cp := *rec
	r.recoveryEmailCodes[rec.UserID] = &cp
	return rec.NodeID, nil
}

func (r *fakeRepo) CountRecoveryEmailCodeAttempt(_ context.Context, userID string, atMs int64) (*RecoveryEmailCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.recoveryEmailCodes[userID]
	if !ok || c.ConsumedAt != 0 || c.ExpiresAt <= atMs || (c.MaxAttempts > 0 && c.AttemptCount >= c.MaxAttempts) {
		return nil, nil
	}
	c.AttemptCount++
	cp := *c
	return &cp, nil
}

func (r *fakeRepo) ConsumeRecoveryEmailCode(_ context.Context, userID string, atMs int64) (*RecoveryEmailCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.recoveryEmailCodes[userID]
	if !ok || c.ConsumedAt != 0 || c.ExpiresAt <= atMs {
		return nil, ErrRecoveryEmailCodeInvalid
	}
	c.ConsumedAt = atMs
	cp := *c
	return &cp, nil
}

func (r *fakeRepo) AddRecoveryEmail(_ context.Context, e *RecoveryEmail, max int) error {
	if e == nil || e.UserID == "" || e.Email == "" {
		return errors.New("fake: AddRecoveryEmail: missing user id or email")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[e.UserID]; !ok {
		return fmt.Errorf("fake: AddRecoveryEmail: %w", ErrNotFound)
	}
	fold := FoldEmail(e.Email)
	for _, u := range r.users {
		if u.Email != "" && FoldEmail(u.Email) == fold {
			return ErrRecoveryEmailTaken
		}
	}
	for userID, list := range r.recoveryEmails {
		for _, held := range list {
			if FoldEmail(held.Email) != fold {
				continue
			}
			if userID == e.UserID {
				return nil
			}
			return ErrRecoveryEmailTaken
		}
	}
	if len(r.recoveryEmails[e.UserID]) >= max {
		return ErrRecoveryEmailLimit
	}
	cp := *e
	cp.ID = nextNodeID()
	r.recoveryEmails[e.UserID] = append(r.recoveryEmails[e.UserID], &cp)
	return nil
}

func (r *fakeRepo) ListRecoveryEmails(_ context.Context, userID string) ([]*RecoveryEmail, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*RecoveryEmail
	for _, e := range r.recoveryEmails[userID] {
		cp := *e
		out = append(out, &cp)
	}
	return out, nil
}

// heldRecoveryEmailLocked is the index among userID's recovery emails of the
// one match accepts, or -1. The caller holds r.mu.
func (r *fakeRepo) heldRecoveryEmailLocked(userID string, match func(*RecoveryEmail) bool) int {
	return slices.IndexFunc(r.recoveryEmails[userID], match)
}

func recoveryEmailAt(email string) func(*RecoveryEmail) bool {
	fold := FoldEmail(email)
	return func(e *RecoveryEmail) bool { return FoldEmail(e.Email) == fold }
}

func recoveryEmailWithID(id string) func(*RecoveryEmail) bool {
	return func(e *RecoveryEmail) bool { return e.ID == id }
}

func (r *fakeRepo) RemoveRecoveryEmail(_ context.Context, userID, email string, atMs int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.heldRecoveryEmailLocked(userID, recoveryEmailAt(email))
	if i < 0 {
		return 0, fmt.Errorf("fake: RemoveRecoveryEmail: %w", ErrNotFound)
	}
	list := r.recoveryEmails[userID]
	removed := list[i].ID
	r.recoveryEmails[userID] = append(list[:i:i], list[i+1:]...)
	ended := 0
	for id, t := range r.refreshTokens {
		if t.UserID != userID || t.RecoveryEmailID != removed {
			continue
		}
		if t.ConsumedAtMs == 0 {
			ended++
		}
		for _, s := range r.sessions {
			if t.SID != "" && s.SID == t.SID && s.RevokedAtMs == 0 {
				s.RevokedAtMs = atMs
			}
		}
		delete(r.refreshTokens, id)
	}
	return ended, nil
}

func (r *fakeRepo) DeleteExpiredRecoveryEmailCodes(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("fake: DeleteExpiredRecoveryEmailCodes: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for userID, c := range r.recoveryEmailCodes {
		if n >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.recoveryEmailCodes, userID)
			n++
		}
	}
	return nil
}

func (r *fakeRepo) FindRecoveryEmailHolder(_ context.Context, email string) (*RecoveryEmail, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fold := FoldEmail(email)
	for _, list := range r.recoveryEmails {
		for _, e := range list {
			if FoldEmail(e.Email) == fold {
				cp := *e
				return &cp, nil
			}
		}
	}
	return nil, nil
}

func (r *fakeRepo) MarkRecoveryEmailSignIn(_ context.Context, userID, id string, atMs, holdMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.heldRecoveryEmailLocked(userID, recoveryEmailWithID(id))
	if i < 0 {
		return fmt.Errorf("fake: MarkRecoveryEmailSignIn: %w", ErrNotFound)
	}
	if e := r.recoveryEmails[userID][i]; e.LastSignInAt <= atMs-holdMs {
		e.LastSignInAt = atMs
	}
	return nil
}
