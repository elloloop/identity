package entdb

import (
	"context"
	"fmt"

	schemapb "github.com/elloloop/identity/gen/go/identity/schema"
)

// The five DeleteExpired* sweepers drop up to limit rows whose
// expires_at is strictly less than beforeMs. Each one dispatches
// through entClient.deleteExpired, which in turn issues a single
// OpDeleteWhere op via tenant-shard-db v1.14.0's single-RPC sweeper
// primitive (#540). Earlier identity releases ran a QueryNodes +
// batched OpDeleteNode pair through the raw transport; v1.14.0
// collapses both into one round trip and the server caps the per-op
// limit so a runaway predicate cannot pin the single applier
// goroutine for a tenant.
//
// The OpDeleteWhere primitive does not return a row count (see the
// v1.14.0 release notes — "applied, no count for v1"); the sweeper
// methods therefore return only error, and the app-layer sweeper
// emits a per-tick "sweep completed" counter instead of a row count.
// The schema declares expires_at indexed on every affected node type
// so the underlying scan stays on a B-tree expression index.

func (r *entRepository) DeleteExpiredWebAuthnChallenges(ctx context.Context, beforeMs int64, limit int) error {
	if err := r.client.deleteExpired(ctx, systemActor, &schemapb.PasskeyChallenge{}, beforeMs, limit); err != nil {
		return fmt.Errorf("repo: DeleteExpiredWebAuthnChallenges: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteExpiredEmailVerificationTokens(ctx context.Context, beforeMs int64, limit int) error {
	if err := r.client.deleteExpired(ctx, systemActor, &schemapb.EmailVerificationToken{}, beforeMs, limit); err != nil {
		return fmt.Errorf("repo: DeleteExpiredEmailVerificationTokens: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteExpiredPasswordResetTokens(ctx context.Context, beforeMs int64, limit int) error {
	if err := r.client.deleteExpired(ctx, systemActor, &schemapb.PasswordResetToken{}, beforeMs, limit); err != nil {
		return fmt.Errorf("repo: DeleteExpiredPasswordResetTokens: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteExpiredEmailChangeTokens(ctx context.Context, beforeMs int64, limit int) error {
	if err := r.client.deleteExpired(ctx, systemActor, &schemapb.EmailChangeToken{}, beforeMs, limit); err != nil {
		return fmt.Errorf("repo: DeleteExpiredEmailChangeTokens: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteExpiredLoginChallenges(ctx context.Context, beforeMs int64, limit int) error {
	if err := r.client.deleteExpired(ctx, systemActor, &schemapb.LoginChallenge{}, beforeMs, limit); err != nil {
		return fmt.Errorf("repo: DeleteExpiredLoginChallenges: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteExpiredOAuthOneTimeCodes(ctx context.Context, beforeMs int64, limit int) error {
	if err := r.client.deleteExpired(ctx, systemActor, &schemapb.OAuthOneTimeCode{}, beforeMs, limit); err != nil {
		return fmt.Errorf("repo: DeleteExpiredOAuthOneTimeCodes: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteExpiredEmailLoginCodes(ctx context.Context, beforeMs int64, limit int) error {
	if err := r.client.deleteExpired(ctx, systemActor, &schemapb.EmailLoginCode{}, beforeMs, limit); err != nil {
		return fmt.Errorf("repo: DeleteExpiredEmailLoginCodes: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteExpiredMagicLinkTokens(ctx context.Context, beforeMs int64, limit int) error {
	if err := r.client.deleteExpired(ctx, systemActor, &schemapb.MagicLinkToken{}, beforeMs, limit); err != nil {
		return fmt.Errorf("repo: DeleteExpiredMagicLinkTokens: %w", err)
	}
	return nil
}

func (r *entRepository) DeleteExpiredPhoneVerificationCodes(ctx context.Context, beforeMs int64, limit int) error {
	if err := r.client.deleteExpired(ctx, systemActor, &schemapb.PhoneVerificationCode{}, beforeMs, limit); err != nil {
		return fmt.Errorf("repo: DeleteExpiredPhoneVerificationCodes: %w", err)
	}
	return nil
}
