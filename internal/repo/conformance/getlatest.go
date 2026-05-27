package conformance

import (
	"context"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runGetLatestConformance pins the semantics of
// GetLatestIdentityVerificationForUser: it returns the record with the
// greatest CreatedAt, NOT the most-recently-inserted row. The two
// differ when a record is created with an older timestamp after a newer
// one — a backend that returns insertion-order-latest (or relies on
// storage order) would resolve the wrong verification.
func runGetLatestConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/GetLatestSemantics", func(t *testing.T) {
		t.Run("MaxCreatedAt_NotInsertionOrder", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid, err := r.CreateUser(ctx, &service.User{Email: "getlatest@example.com", Status: "active", Role: "member"})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			// Insert the higher-timestamp record FIRST, the lower one SECOND.
			if err := r.CreateIdentityVerification(ctx, &service.IdentityVerificationRecord{
				VerificationID: "gl-high", UserID: uid, Provider: "stub",
				Status: service.IDVStatusPending, CreatedAt: 500, UpdatedAt: 500,
			}); err != nil {
				t.Fatalf("create high: %v", err)
			}
			if err := r.CreateIdentityVerification(ctx, &service.IdentityVerificationRecord{
				VerificationID: "gl-low", UserID: uid, Provider: "stub",
				Status: service.IDVStatusPending, CreatedAt: 200, UpdatedAt: 200,
			}); err != nil {
				t.Fatalf("create low: %v", err)
			}
			got, err := r.GetLatestIdentityVerificationForUser(ctx, uid)
			if err != nil || got == nil {
				t.Fatalf("GetLatest: %v %#v", err, got)
			}
			if got.VerificationID != "gl-high" {
				t.Fatalf("GetLatest returned %q (CreatedAt=%d), want gl-high (max CreatedAt=500) — backend returned insertion-order latest, not max timestamp", got.VerificationID, got.CreatedAt)
			}
		})
	})
}
