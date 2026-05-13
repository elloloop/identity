package memory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/repo/conformance"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
)

// TestMemoryConformance runs the driver-agnostic conformance suite
// against the in-memory Repository implementation.
func TestMemoryConformance(t *testing.T) {
	t.Parallel()
	conformance.RunConformance(t, func(_ *testing.T) service.Repository {
		return memory.New()
	})
}

func TestRefreshTokenDeleteAndCount(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := memory.New()
	id1, err := repo.CreateRefreshToken(ctx, &service.RefreshTokenRecord{UserID: "u-1", TokenHash: "hash-1"})
	if err != nil {
		t.Fatalf("CreateRefreshToken 1: %v", err)
	}
	id2, err := repo.CreateRefreshToken(ctx, &service.RefreshTokenRecord{UserID: "u-1", TokenHash: "hash-2"})
	if err != nil {
		t.Fatalf("CreateRefreshToken 2: %v", err)
	}
	if _, err := repo.CreateRefreshToken(ctx, &service.RefreshTokenRecord{UserID: "u-2", TokenHash: "hash-3"}); err != nil {
		t.Fatalf("CreateRefreshToken 3: %v", err)
	}

	if got := repo.CountRefreshTokensForUser("u-1"); got != 2 {
		t.Fatalf("count before delete = %d", got)
	}
	if err := repo.DeleteRefreshToken(ctx, id1); err != nil {
		t.Fatalf("DeleteRefreshToken: %v", err)
	}
	if got := repo.CountRefreshTokensForUser("u-1"); got != 1 {
		t.Fatalf("count after single delete = %d", got)
	}
	if got, err := repo.FindRefreshTokenByHash(ctx, "hash-2"); err != nil || got == nil || got.NodeID != id2 {
		t.Fatalf("remaining token = %+v err=%v", got, err)
	}
	if err := repo.DeleteRefreshTokensForUser(ctx, "u-1"); err != nil {
		t.Fatalf("DeleteRefreshTokensForUser: %v", err)
	}
	if got := repo.CountRefreshTokensForUser("u-1"); got != 0 {
		t.Fatalf("count after user delete = %d", got)
	}
	if got := repo.CountRefreshTokensForUser("u-2"); got != 1 {
		t.Fatalf("other user count = %d", got)
	}
}

func TestTotpDeleteAndDBStubBehavior(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := memory.New()
	id, err := repo.CreateTotpCredential(ctx, &service.TotpCredRecord{UserID: "u-1", SecretEncrypted: "cipher", Verified: true})
	if err != nil {
		t.Fatalf("CreateTotpCredential: %v", err)
	}
	if err := repo.DeleteTotpCredential(ctx, id); err != nil {
		t.Fatalf("DeleteTotpCredential: %v", err)
	}
	got, err := repo.GetTotpCredential(ctx, "u-1")
	if err != nil {
		t.Fatalf("GetTotpCredential: %v", err)
	}
	if got != nil {
		t.Fatalf("deleted credential = %+v", got)
	}

	if _, err := repo.GetNode(ctx, "tenant", "actor", 1, "node"); !errors.Is(err, service.ErrServiceUnavailable) {
		t.Fatalf("GetNode error = %v", err)
	}
	if _, err := repo.SearchNodes(ctx, "tenant", "actor", 1, "query"); !errors.Is(err, service.ErrServiceUnavailable) {
		t.Fatalf("SearchNodes error = %v", err)
	}
	result, err := repo.ExecuteAtomic(ctx, "tenant", "actor", nil)
	if err != nil {
		t.Fatalf("ExecuteAtomic: %v", err)
	}
	if result == nil || !result.Success || !result.Applied {
		t.Fatalf("ExecuteAtomic result = %+v", result)
	}
	if edges, err := repo.GetEdgesFrom(ctx, "tenant", "actor", "node", 1); err != nil || edges != nil {
		t.Fatalf("GetEdgesFrom edges=%v err=%v", edges, err)
	}
	if edges, err := repo.GetEdgesTo(ctx, "tenant", "actor", "node", 1); err != nil || edges != nil {
		t.Fatalf("GetEdgesTo edges=%v err=%v", edges, err)
	}
}
