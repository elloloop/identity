package memory

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/elloloop/identity/internal/service"
)

// ── Recovery emails ───────────────────────────────────────────────────

// recoveryEmailHeldLocked reports whether any account holds email as a
// recovery email, under FoldEmail. The caller holds r.mu.
func (r *Repo) recoveryEmailHeldLocked(email string) bool {
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

func (r *Repo) UpsertRecoveryEmailCode(_ context.Context, rec *service.RecoveryEmailCodeRecord) (string, error) {
	if rec == nil {
		return "", errors.New("memory: UpsertRecoveryEmailCode: nil record")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rec.NodeID = r.nextID()
	cp := *rec
	r.recoveryEmailCodes[rec.UserID] = &cp
	return rec.NodeID, nil
}

func (r *Repo) CountRecoveryEmailCodeAttempt(_ context.Context, userID string, atMs int64) (*service.RecoveryEmailCodeRecord, error) {
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

func (r *Repo) ConsumeRecoveryEmailCode(_ context.Context, userID string, atMs int64) (*service.RecoveryEmailCodeRecord, error) {
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

func (r *Repo) AddRecoveryEmail(_ context.Context, e *service.RecoveryEmail, max int) error {
	if e == nil || e.UserID == "" || e.Email == "" {
		return errors.New("memory: AddRecoveryEmail: missing user id or email")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[e.UserID]; !ok {
		return fmt.Errorf("memory: AddRecoveryEmail: %w", service.ErrNotFound)
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

func (r *Repo) ListRecoveryEmails(_ context.Context, userID string) ([]*service.RecoveryEmail, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*service.RecoveryEmail
	for _, e := range r.recoveryEmails[userID] {
		cp := *e
		out = append(out, &cp)
	}
	return out, nil
}

// heldRecoveryEmailLocked is the index of email (under FoldEmail) among
// userID's recovery emails, or -1. The caller holds r.mu.
func (r *Repo) heldRecoveryEmailLocked(userID, email string) int {
	fold := service.FoldEmail(email)
	return slices.IndexFunc(r.recoveryEmails[userID], func(e *service.RecoveryEmail) bool {
		return service.FoldEmail(e.Email) == fold
	})
}

func (r *Repo) RemoveRecoveryEmail(_ context.Context, userID, email string, atMs int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.heldRecoveryEmailLocked(userID, email)
	if i < 0 {
		return 0, fmt.Errorf("memory: RemoveRecoveryEmail: %w", service.ErrNotFound)
	}
	list := r.recoveryEmails[userID]
	r.recoveryEmails[userID] = append(list[:i:i], list[i+1:]...)
	fold := service.FoldEmail(email)
	ended := 0
	for id, t := range r.refreshTokens {
		if t.UserID != userID || t.RecoveryEmail == "" || service.FoldEmail(t.RecoveryEmail) != fold {
			continue
		}
		if t.ConsumedAtMs == 0 {
			ended++
		}
		r.revokeSessionLocked(t.SID, atMs)
		delete(r.refreshTokens, id)
	}
	return ended, nil
}

func (r *Repo) DeleteExpiredRecoveryEmailCodes(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteExpiredRecoveryEmailCodes: limit must be > 0, got %d", limit)
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

func (r *Repo) FindRecoveryEmailHolder(_ context.Context, email string) (*service.RecoveryEmail, error) {
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

func (r *Repo) MarkRecoveryEmailSignIn(_ context.Context, userID, email string, atMs, holdMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.heldRecoveryEmailLocked(userID, email)
	if i < 0 {
		return fmt.Errorf("memory: MarkRecoveryEmailSignIn: %w", service.ErrNotFound)
	}
	if e := r.recoveryEmails[userID][i]; e.LastSignInAt <= atMs-holdMs {
		e.LastSignInAt = atMs
	}
	return nil
}
