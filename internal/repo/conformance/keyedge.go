package conformance

import (
	"context"
	"strings"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runKeyFidelityConformance exercises the unique-key index path (a
// different code path from the structpb payload encoding): keys must be
// stored and looked up exactly, case-sensitively, and at length. A
// backend whose key index folds case, truncates, or rejects long keys
// silently mis-resolves lookups.
func runKeyFidelityConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/KeyFidelity", func(t *testing.T) {
		t.Run("LongKey", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "key-long@example.com")
			h := strings.Repeat("a1B2", 128) // 512-char token hash
			if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
				TokenHash: h, UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 100, LastUsedAt: 100,
			}); err != nil {
				t.Fatalf("CreateRefreshToken long key: %v", err)
			}
			got, err := r.FindRefreshTokenByHash(ctx, h)
			if err != nil {
				t.Fatalf("Find long key: %v", err)
			}
			if got == nil {
				t.Fatalf("long key (%d chars) not found — index truncated/rejected it", len(h))
			}
		})

		t.Run("Base64URLAndSymbolKeys", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "key-sym@example.com")
			// Credential IDs are base64url in practice; also exercise a few
			// symbols that show up in token/credential encodings.
			for _, cred := range []string{"ab-cd_ef-GH_12", "with.dots.and-dashes", "padded==base64", "tilde~and~stuff"} {
				if _, err := r.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{
					CredentialID: cred, UserID: uid, PublicKey: "pk", SignCount: 1,
				}); err != nil {
					t.Fatalf("Create cred %q: %v", cred, err)
				}
				got, err := r.GetPasskeyCredentialByCredID(ctx, cred)
				if err != nil {
					t.Fatalf("Get cred %q: %v", cred, err)
				}
				if got == nil || got.CredentialID != cred {
					t.Fatalf("symbol key %q did not round-trip through the key index: got %#v", cred, got)
				}
			}
		})

		t.Run("CaseSensitiveKeys", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "key-case@example.com")
			// Token hashes are case-sensitive (hex/base64). "AbCdEf01" and
			// "abcdef01" are distinct rows; a case-folding index would
			// collide them or mis-resolve the lookup.
			lower := "abcdef0123456789"
			mixed := "AbCdEf0123456789"
			idLower, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: lower, UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 100, LastUsedAt: 100})
			if err != nil {
				t.Fatalf("Create lower: %v", err)
			}
			idMixed, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: mixed, UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 100, LastUsedAt: 100})
			if err != nil {
				t.Fatalf("Create mixed-case (key index folds case?): %v", err)
			}
			if idLower == idMixed {
				t.Fatalf("case-distinct keys collapsed to the same node %q", idLower)
			}
			gotLower, _ := r.FindRefreshTokenByHash(ctx, lower)
			gotMixed, _ := r.FindRefreshTokenByHash(ctx, mixed)
			if gotLower == nil || gotMixed == nil {
				t.Fatalf("case-sensitive lookup missed: lower=%#v mixed=%#v", gotLower, gotMixed)
			}
			if gotLower.NodeID != idLower || gotMixed.NodeID != idMixed {
				t.Fatalf("case-sensitive lookup cross-resolved: lower→%s (want %s), mixed→%s (want %s)",
					gotLower.NodeID, idLower, gotMixed.NodeID, idMixed)
			}
		})
	})
}

// runSweeperBoundaryConformance pins the DeleteExpired* cutoff semantics:
// expiry is "strictly less than beforeMs", so a row whose expires_at
// equals beforeMs must survive a sweep at that instant and be removed
// only one millisecond later. Catches off-by-one (<= vs <) cutoffs that
// would GC a token exactly at its expiry boundary.
func runSweeperBoundaryConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/SweeperBoundary", func(t *testing.T) {
		t.Run("StrictLessThanCutoff", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "sweep-boundary@example.com")
			const expiry = 5_000
			if err := r.CreatePasswordResetToken(ctx, &service.PasswordResetToken{
				TokenHash: "boundary-tok", UserID: uid, ExpiresAt: expiry, CreatedAt: 100,
			}); err != nil {
				t.Fatalf("Create: %v", err)
			}

			// Sweep exactly AT the expiry: strict < means nothing deleted.
			if err := r.DeleteExpiredPasswordResetTokens(ctx, expiry, 10); err != nil {
				t.Fatalf("sweep at cutoff: %v", err)
			}
			if got, _ := r.FindPasswordResetTokenByHash(ctx, "boundary-tok"); got == nil {
				t.Fatalf("token with expires_at==beforeMs was deleted — cutoff is <= but contract is strict <")
			}

			// One millisecond past expiry: now it goes.
			if err := r.DeleteExpiredPasswordResetTokens(ctx, expiry+1, 10); err != nil {
				t.Fatalf("sweep past cutoff: %v", err)
			}
			if got, _ := r.FindPasswordResetTokenByHash(ctx, "boundary-tok"); got != nil {
				t.Fatalf("token with expires_at < beforeMs survived the sweep: %#v", got)
			}
		})
	})
}
