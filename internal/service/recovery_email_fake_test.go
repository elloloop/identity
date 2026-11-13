package service

import (
	"context"
	"errors"
	"fmt"
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

func (r *fakeRepo) FindRecoveryEmailCodeByUser(_ context.Context, userID string) (*RecoveryEmailCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.recoveryEmailCodes[userID]
	if !ok {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}

func (r *fakeRepo) IncrementRecoveryEmailCodeAttempts(_ context.Context, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.recoveryEmailCodes {
		if c.NodeID == nodeID {
			c.AttemptCount++
			return nil
		}
	}
	return fmt.Errorf("fake: IncrementRecoveryEmailCodeAttempts: %s not found", nodeID)
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

func (r *fakeRepo) RemoveRecoveryEmail(_ context.Context, userID, email string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fold := FoldEmail(email)
	list := r.recoveryEmails[userID]
	for i, e := range list {
		if FoldEmail(e.Email) == fold {
			r.recoveryEmails[userID] = append(list[:i:i], list[i+1:]...)
			return true, nil
		}
	}
	return false, nil
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

func (r *fakeRepo) MarkRecoveryEmailSignIn(_ context.Context, userID, email string, atMs, holdMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	fold := FoldEmail(email)
	for _, e := range r.recoveryEmails[userID] {
		if FoldEmail(e.Email) == fold {
			if e.LastSignInAt <= atMs-holdMs {
				e.LastSignInAt = atMs
			}
			return nil
		}
	}
	return fmt.Errorf("fake: MarkRecoveryEmailSignIn: %w", ErrNotFound)
}
