package entdb

import (
	"context"
	"errors"
	"fmt"

	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
	"github.com/elloloop/identity/internal/service"
)

// ── Phone verification codes (SMS OTP) ─────────────────────────────

func phoneVerificationCodeFromProto(id string, p *schemapb.PhoneVerificationCode) *service.PhoneVerificationCodeRecord {
	if p == nil {
		return nil
	}
	return &service.PhoneVerificationCodeRecord{
		NodeID:       id,
		UserID:       p.GetUserId(),
		PhoneNumber:  p.GetPhoneNumber(),
		CodeHash:     p.GetCodeHash(),
		ExpiresAt:    p.GetExpiresAt(),
		CreatedAt:    p.GetCreatedAt(),
		ConsumedAt:   p.GetConsumedAt(),
		AttemptCount: p.GetAttemptCount(),
		MaxAttempts:  p.GetMaxAttempts(),
	}
}

// findPhoneCodeNodeByUser returns the live code row + node id for a user,
// or (nil, "", nil) when none exists. The code is keyed by user_id
// (indexed, not unique) so this goes through the user-scoped query path
// rather than findByKey.
func (r *entRepository) findPhoneCodeNodeByUser(ctx context.Context, userID string) (*schemapb.PhoneVerificationCode, string, error) {
	rows, err := r.client.query(ctx, systemActor, &schemapb.PhoneVerificationCode{}, map[string]any{"user_id": userID})
	if err != nil {
		return nil, "", err
	}
	if len(rows) == 0 {
		return nil, "", nil
	}
	return rows[0].Message.(*schemapb.PhoneVerificationCode), rows[0].NodeID, nil
}

// UpsertPhoneVerificationCode replaces any existing code for the user so
// at most one is live per user. The SDK has no upsert primitive, so this
// deletes the prior row (if any) then creates the fresh one.
func (r *entRepository) UpsertPhoneVerificationCode(ctx context.Context, c *service.PhoneVerificationCodeRecord) (string, error) {
	if c == nil {
		return "", errors.New("repo: UpsertPhoneVerificationCode: nil record")
	}
	_, prevID, err := r.findPhoneCodeNodeByUser(ctx, c.UserID)
	if err != nil {
		return "", fmt.Errorf("repo: UpsertPhoneVerificationCode: %w", err)
	}
	if prevID != "" {
		if delErr := r.client.delete(ctx, systemActor, &schemapb.PhoneVerificationCode{}, prevID); delErr != nil &&
			!errors.Is(delErr, errNotFound) {
			return "", fmt.Errorf("repo: UpsertPhoneVerificationCode: replace: %w", delErr)
		}
	}

	msg := &schemapb.PhoneVerificationCode{
		UserId:       c.UserID,
		PhoneNumber:  c.PhoneNumber,
		CodeHash:     c.CodeHash,
		ExpiresAt:    c.ExpiresAt,
		CreatedAt:    c.CreatedAt,
		ConsumedAt:   c.ConsumedAt,
		AttemptCount: c.AttemptCount,
		MaxAttempts:  c.MaxAttempts,
	}
	id, err := r.client.create(ctx, actorStr(c.UserID), msg)
	if err != nil {
		return "", fmt.Errorf("repo: UpsertPhoneVerificationCode: %w", err)
	}
	c.NodeID = id
	return id, nil
}

func (r *entRepository) FindPhoneVerificationCodeByUser(ctx context.Context, userID string) (*service.PhoneVerificationCodeRecord, error) {
	if userID == "" {
		return nil, nil
	}
	msg, id, err := r.findPhoneCodeNodeByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("repo: FindPhoneVerificationCodeByUser: %w", err)
	}
	if id == "" {
		return nil, nil
	}
	return phoneVerificationCodeFromProto(id, msg), nil
}

func (r *entRepository) IncrementPhoneVerificationCodeAttempts(ctx context.Context, nodeID string) error {
	dst := &schemapb.PhoneVerificationCode{}
	if err := r.client.get(ctx, systemActor, dst, nodeID); err != nil {
		if errors.Is(err, errNotFound) {
			return fmt.Errorf("repo: IncrementPhoneVerificationCodeAttempts: %w", errNotFound)
		}
		return fmt.Errorf("repo: IncrementPhoneVerificationCodeAttempts: %w", err)
	}
	patch := &schemapb.PhoneVerificationCode{AttemptCount: dst.GetAttemptCount() + 1}
	if err := r.client.update(ctx, systemActor, nodeID, patch); err != nil {
		return fmt.Errorf("repo: IncrementPhoneVerificationCodeAttempts: %w", err)
	}
	return nil
}

// ConsumePhoneVerificationCode resolves the user's code, rejects an
// already-consumed or expired code, then flips consumed_at via the SDK's
// UpdateIf compare-and-set gated on consumed_at == 0. Two replicas racing
// the same user resolve to exactly one winner; the loser sees
// ErrPhoneCodeInvalid.
func (r *entRepository) ConsumePhoneVerificationCode(ctx context.Context, userID string, atMs int64) (*service.PhoneVerificationCodeRecord, error) {
	if userID == "" {
		return nil, service.ErrPhoneCodeInvalid
	}
	msg, id, err := r.findPhoneCodeNodeByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("repo: ConsumePhoneVerificationCode: %w", err)
	}
	if id == "" {
		return nil, service.ErrPhoneCodeInvalid
	}
	if msg.GetConsumedAt() != 0 || msg.GetExpiresAt() <= atMs {
		return nil, service.ErrPhoneCodeInvalid
	}

	patch := &schemapb.PhoneVerificationCode{ConsumedAt: atMs}
	err = r.client.updateIf(ctx, systemActor, id, patch, "consumed_at", nil)
	if errors.Is(err, errPreconditionFailed) {
		return nil, service.ErrPhoneCodeInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("repo: ConsumePhoneVerificationCode: %w", err)
	}

	rec := phoneVerificationCodeFromProto(id, msg)
	rec.ConsumedAt = atMs
	return rec, nil
}
