package conformance

import (
	"context"
	"fmt"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// paginationRows is deliberately chosen above the suspected per-call
// QueryNodes cap (~100 observed on a remote graph backend) and below the 1000
// the repository's drain loops assume. A List* method that issues a
// single un-paginated query truncates the result at the cap, so
// creating this many rows and asserting the full count exposes both a
// lower-than-assumed cap and any missing pagination in a read path.
const paginationRows = 250

// runPaginationConformance asserts that user/tenant-scoped list and
// bulk-delete methods cover EVERY matching row, not just the first
// server page. A remote graph backend clamps QueryNodes server-side; methods that fan a
// single query out to the caller (ListPasskeyCredentials,
// ListOAuthIdentitiesForUser, ...) silently drop rows past the cap,
// while the DeleteXxxForUser sweeps drain in a loop. This suite makes
// the divergence visible on any capped backend.
func runPaginationConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/Pagination", func(t *testing.T) {
		t.Run("PasskeyCredentials_ListReturnsAll", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "page-pk@example.com")
			for i := 0; i < paginationRows; i++ {
				if _, err := r.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{
					CredentialID: fmt.Sprintf("page-cred-%d", i), UserID: uid, PublicKey: "pk", SignCount: 1,
				}); err != nil {
					t.Fatalf("CreatePasskeyCredential %d: %v", i, err)
				}
			}
			list, err := r.ListPasskeyCredentials(ctx, uid)
			if err != nil {
				t.Fatalf("ListPasskeyCredentials: %v", err)
			}
			if len(list) != paginationRows {
				t.Fatalf("ListPasskeyCredentials returned %d of %d rows — list read does not page past the server cap", len(list), paginationRows)
			}
		})

		t.Run("OAuthIdentities_ListReturnsAll", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "page-oa@example.com")
			for i := 0; i < paginationRows; i++ {
				if err := r.CreateOAuthIdentity(ctx, &service.OAuthIdentity{
					UserID: uid, Provider: "google", ProviderUserID: fmt.Sprintf("page-sub-%d", i),
					EmailAtLinkTime: "x@y.com", CreatedAt: int64(100 + i),
				}); err != nil {
					t.Fatalf("CreateOAuthIdentity %d: %v", i, err)
				}
			}
			list, err := r.ListOAuthIdentitiesForUser(ctx, uid)
			if err != nil {
				t.Fatalf("ListOAuthIdentitiesForUser: %v", err)
			}
			if len(list) != paginationRows {
				t.Fatalf("ListOAuthIdentitiesForUser returned %d of %d rows — list read does not page past the server cap", len(list), paginationRows)
			}
		})

		t.Run("RefreshTokens_DeleteForUserDrainsAll", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "page-rt-del@example.com")
			hashes := make([]string, paginationRows)
			for i := 0; i < paginationRows; i++ {
				h := fmt.Sprintf("page-rt-%d", i)
				hashes[i] = h
				if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
					TokenHash: h, UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 100, LastUsedAt: 100,
				}); err != nil {
					t.Fatalf("CreateRefreshToken %d: %v", i, err)
				}
			}
			if err := r.DeleteRefreshTokensForUser(ctx, uid); err != nil {
				t.Fatalf("DeleteRefreshTokensForUser: %v", err)
			}
			// Every token must be gone — a capped, un-drained delete would
			// leave a logged-out user's tokens live (a security gap).
			survivors := 0
			for _, h := range hashes {
				got, err := r.FindRefreshTokenByHashIncludingConsumed(ctx, h)
				if err != nil {
					t.Fatalf("Find %q post-delete: %v", h, err)
				}
				if got != nil {
					survivors++
				}
			}
			if survivors != 0 {
				t.Fatalf("DeleteRefreshTokensForUser left %d of %d tokens live", survivors, paginationRows)
			}
		})
	})
}

// runFreshTenantConformance asserts that a read issued before any write
// returns an empty result, never an error. On a remote graph backend a brand-new tenant
// has no WAL yet, so a filter QueryNodes returns FailedPrecondition
// "tenant not opened"; the repository is expected to translate that to
// "no rows". (tenant-shard-db v1.16.0 regressed this by sanitizing the
// precondition into an opaque Internal error — these subtests are the
// isolated cross-backend repro and will go green when that lands.)
//
// Every check uses a fresh repo (a fresh, never-written tenant on
// graph backend) and t.Errorf rather than Fatalf so all read paths are
// reported in one run.
func runFreshTenantConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/FreshTenant", func(t *testing.T) {
		t.Run("FindUserByProviderID", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			got, err := r.FindUserByProviderID(ctx, "google", "no-such-sub")
			if err != nil {
				t.Errorf("FindUserByProviderID on fresh tenant: want (nil,nil), got err=%v", err)
			}
			if got != nil {
				t.Errorf("FindUserByProviderID on fresh tenant: want nil user, got %#v", got)
			}
		})

		t.Run("GetLatestIdentityVerificationForUser", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			got, err := r.GetLatestIdentityVerificationForUser(ctx, "no-such-user")
			if err != nil {
				t.Errorf("GetLatest on fresh tenant: want (nil,nil), got err=%v", err)
			}
			if got != nil {
				t.Errorf("GetLatest on fresh tenant: want nil, got %#v", got)
			}
		})

		t.Run("ListPasskeyCredentials", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			got, err := r.ListPasskeyCredentials(ctx, "no-such-user")
			if err != nil {
				t.Errorf("ListPasskeyCredentials on fresh tenant: want empty, got err=%v", err)
			}
			if len(got) != 0 {
				t.Errorf("ListPasskeyCredentials on fresh tenant: want 0 rows, got %d", len(got))
			}
		})

		t.Run("FindRecoveryCodeByHash", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			got, err := r.FindRecoveryCodeByHash(ctx, "no-such-user", "no-such-hash")
			if err != nil {
				t.Errorf("FindRecoveryCodeByHash on fresh tenant: want (nil,nil), got err=%v", err)
			}
			if got != nil {
				t.Errorf("FindRecoveryCodeByHash on fresh tenant: want nil, got %#v", got)
			}
		})
	})
}
