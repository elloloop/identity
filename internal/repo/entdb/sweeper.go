package entdb

import (
	"context"
	"fmt"

	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
)

// The five DeleteExpired* sweepers drop up to limit rows whose
// expires_at is strictly less than beforeMs. Each one dispatches
// through entClient.deleteExpired, which handles the typed query
// + batched OpDeleteNode atomic-commit pair against the raw
// transport. The schema declares expires_at indexed on every
// affected node type so the underlying scan stays on a B-tree
// expression index.

func (r *entRepository) DeleteExpiredWebAuthnChallenges(ctx context.Context, beforeMs int64, limit int) (int, error) {
	n, err := r.client.deleteExpired(ctx, systemActor, &schemapb.PasskeyChallenge{}, beforeMs, limit)
	if err != nil {
		return 0, fmt.Errorf("repo: DeleteExpiredWebAuthnChallenges: %w", err)
	}
	return n, nil
}

func (r *entRepository) DeleteExpiredEmailVerificationTokens(ctx context.Context, beforeMs int64, limit int) (int, error) {
	n, err := r.client.deleteExpired(ctx, systemActor, &schemapb.EmailVerificationToken{}, beforeMs, limit)
	if err != nil {
		return 0, fmt.Errorf("repo: DeleteExpiredEmailVerificationTokens: %w", err)
	}
	return n, nil
}

func (r *entRepository) DeleteExpiredPasswordResetTokens(ctx context.Context, beforeMs int64, limit int) (int, error) {
	n, err := r.client.deleteExpired(ctx, systemActor, &schemapb.PasswordResetToken{}, beforeMs, limit)
	if err != nil {
		return 0, fmt.Errorf("repo: DeleteExpiredPasswordResetTokens: %w", err)
	}
	return n, nil
}

func (r *entRepository) DeleteExpiredEmailChangeTokens(ctx context.Context, beforeMs int64, limit int) (int, error) {
	n, err := r.client.deleteExpired(ctx, systemActor, &schemapb.EmailChangeToken{}, beforeMs, limit)
	if err != nil {
		return 0, fmt.Errorf("repo: DeleteExpiredEmailChangeTokens: %w", err)
	}
	return n, nil
}

func (r *entRepository) DeleteExpiredLoginChallenges(ctx context.Context, beforeMs int64, limit int) (int, error) {
	n, err := r.client.deleteExpired(ctx, systemActor, &schemapb.LoginChallenge{}, beforeMs, limit)
	if err != nil {
		return 0, fmt.Errorf("repo: DeleteExpiredLoginChallenges: %w", err)
	}
	return n, nil
}
