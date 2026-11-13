//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"

	"github.com/elloloop/identity/internal/service"
)

// ── Recovery emails ───────────────────────────────────────────────────

// recoveryEmailHeldLocked reports whether any account holds email as a
// recovery email, under FoldEmail. The caller holds r.mu.
func (r *MemRepo) recoveryEmailHeldLocked(email string) bool {
	fold := service.FoldEmail(email)
	for _, list := range r.recoveryEmails {
		for _, e := range list {
			if service.FoldEmail(e.Email) == fold {
				return true
			}
		}
	}
	return false
}

func (r *MemRepo) UpsertRecoveryEmailCode(_ context.Context, rec *service.RecoveryEmailCodeRecord) (string, error) {
	if rec == nil {
		return "", errors.New("integration: UpsertRecoveryEmailCode: nil record")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rec.NodeID = r.nextID()
	cp := *rec
	r.recoveryEmailCodes[rec.UserID] = &cp
	return rec.NodeID, nil
}

func (r *MemRepo) CountRecoveryEmailCodeAttempt(_ context.Context, userID string, atMs int64) (*service.RecoveryEmailCodeRecord, error) {
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

func (r *MemRepo) ConsumeRecoveryEmailCode(_ context.Context, userID string, atMs int64) (*service.RecoveryEmailCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.recoveryEmailCodes[userID]
	if !ok || c.ConsumedAt != 0 || c.ExpiresAt <= atMs {
		return nil, service.ErrRecoveryEmailCodeInvalid
	}
	c.ConsumedAt = atMs
	cp := *c
	return &cp, nil
}

func (r *MemRepo) AddRecoveryEmail(_ context.Context, e *service.RecoveryEmail, max int) error {
	if e == nil || e.UserID == "" || e.Email == "" {
		return errors.New("integration: AddRecoveryEmail: missing user id or email")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[e.UserID]; !ok {
		return fmt.Errorf("integration: AddRecoveryEmail: %w", service.ErrNotFound)
	}
	fold := service.FoldEmail(e.Email)
	for _, u := range r.users {
		if u.Email != "" && service.FoldEmail(u.Email) == fold {
			return service.ErrRecoveryEmailTaken
		}
	}
	for userID, list := range r.recoveryEmails {
		for _, held := range list {
			if service.FoldEmail(held.Email) != fold {
				continue
			}
			if userID == e.UserID {
				return nil
			}
			return service.ErrRecoveryEmailTaken
		}
	}
	if len(r.recoveryEmails[e.UserID]) >= max {
		return service.ErrRecoveryEmailLimit
	}
	cp := *e
	r.recoveryEmails[e.UserID] = append(r.recoveryEmails[e.UserID], &cp)
	return nil
}

func (r *MemRepo) ListRecoveryEmails(_ context.Context, userID string) ([]*service.RecoveryEmail, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*service.RecoveryEmail
	for _, e := range r.recoveryEmails[userID] {
		cp := *e
		out = append(out, &cp)
	}
	return out, nil
}

func (r *MemRepo) RemoveRecoveryEmail(_ context.Context, userID, email string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fold := service.FoldEmail(email)
	list := r.recoveryEmails[userID]
	for i, e := range list {
		if service.FoldEmail(e.Email) == fold {
			r.recoveryEmails[userID] = append(list[:i:i], list[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

func (r *MemRepo) DeleteExpiredRecoveryEmailCodes(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("integration: DeleteExpiredRecoveryEmailCodes: limit must be > 0, got %d", limit)
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

func (r *MemRepo) FindRecoveryEmailHolder(_ context.Context, email string) (*service.RecoveryEmail, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fold := service.FoldEmail(email)
	for _, list := range r.recoveryEmails {
		for _, e := range list {
			if service.FoldEmail(e.Email) == fold {
				cp := *e
				return &cp, nil
			}
		}
	}
	return nil, nil
}

func (r *MemRepo) MarkRecoveryEmailSignIn(_ context.Context, userID, email string, atMs, holdMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	fold := service.FoldEmail(email)
	for _, e := range r.recoveryEmails[userID] {
		if service.FoldEmail(e.Email) == fold {
			if e.LastSignInAt <= atMs-holdMs {
				e.LastSignInAt = atMs
			}
			return nil
		}
	}
	return fmt.Errorf("integration: MarkRecoveryEmailSignIn: %w", service.ErrNotFound)
}
