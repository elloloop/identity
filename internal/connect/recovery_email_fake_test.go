package connect

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/elloloop/identity/internal/service"
)

// ── Recovery emails ───────────────────────────────────────────────────

func (r *fakeRepo) UpsertRecoveryEmailCode(_ context.Context, rec *service.RecoveryEmailCodeRecord) (string, error) {
	if rec == nil {
		return "", errors.New("fake: UpsertRecoveryEmailCode: nil record")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rec.NodeID = nextID()
	cp := *rec
	r.recoveryEmailCodes[rec.UserID] = &cp
	return rec.NodeID, nil
}

func (r *fakeRepo) CountRecoveryEmailCodeAttempt(_ context.Context, userID string, atMs int64) (*service.RecoveryEmailCodeRecord, error) {
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

func (r *fakeRepo) ConsumeRecoveryEmailCode(_ context.Context, userID string, atMs int64) (*service.RecoveryEmailCodeRecord, error) {
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

func (r *fakeRepo) AddRecoveryEmail(_ context.Context, e *service.RecoveryEmail, max int) error {
	if e == nil || e.UserID == "" || e.Email == "" {
		return errors.New("fake: AddRecoveryEmail: missing user id or email")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[e.UserID]; !ok {
		return fmt.Errorf("fake: AddRecoveryEmail: %w", service.ErrNotFound)
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
	r.recoveryEmails[e.UserID] = append(r.recoveryEmails[e.UserID], &service.RecoveryEmail{
		ID: nextID(), UserID: e.UserID, Email: e.Email, VerifiedAt: e.VerifiedAt,
	})
	return nil
}

func (r *fakeRepo) ListRecoveryEmails(_ context.Context, userID string) ([]*service.RecoveryEmail, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*service.RecoveryEmail
	for _, e := range r.recoveryEmails[userID] {
		cp := *e
		out = append(out, &cp)
	}
	return out, nil
}

// heldRecoveryEmailLocked is the index among userID's recovery emails of the
// one match accepts, or -1. The caller holds r.mu.
func (r *fakeRepo) heldRecoveryEmailLocked(userID string, match func(*service.RecoveryEmail) bool) int {
	return slices.IndexFunc(r.recoveryEmails[userID], match)
}

func recoveryEmailAt(email string) func(*service.RecoveryEmail) bool {
	fold := service.FoldEmail(email)
	return func(e *service.RecoveryEmail) bool { return service.FoldEmail(e.Email) == fold }
}

func recoveryEmailWithID(id string) func(*service.RecoveryEmail) bool {
	return func(e *service.RecoveryEmail) bool { return e.ID == id }
}

func (r *fakeRepo) RemoveRecoveryEmail(_ context.Context, userID, email string, atMs int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.heldRecoveryEmailLocked(userID, recoveryEmailAt(email))
	if i < 0 {
		return 0, fmt.Errorf("fake: RemoveRecoveryEmail: %w", service.ErrNotFound)
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

func (r *fakeRepo) FindRecoveryEmailHolder(_ context.Context, email string) (*service.RecoveryEmail, error) {
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

func (r *fakeRepo) MarkRecoveryEmailSignIn(_ context.Context, userID, id string, atMs, holdMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.heldRecoveryEmailLocked(userID, recoveryEmailWithID(id))
	if i < 0 {
		return fmt.Errorf("fake: MarkRecoveryEmailSignIn: %w", service.ErrNotFound)
	}
	e := r.recoveryEmails[userID][i]
	e.LastSignInAt = atMs
	if e.HoldStartedAt <= atMs-holdMs {
		e.HoldStartedAt = atMs
	}
	return nil
}
