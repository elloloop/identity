package conformance

import (
	"context"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runAccountDeletionConformance exercises the self-service account-deletion
// persistence surface every driver must honour identically: the
// deletion_scheduled_at_ms column round-trips through UpdateUser/GetUser, and
// ListUsersPendingDeletionBefore selects exactly the pending_deletion rows whose
// scheduled instant is in (0, cutoff], ordered and capped, ignoring every other
// account state.
func runAccountDeletionConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/AccountDeletion", func(t *testing.T) {
		t.Run("DeletionScheduledAt_RoundTrip", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			id := createTestUser(t, r, "ad-roundtrip@example.com")

			// A fresh account carries no scheduled deletion.
			got, err := r.GetUser(ctx, id)
			if err != nil || got == nil {
				t.Fatalf("GetUser: %v %#v", err, got)
			}
			if got.DeletionScheduledAtMs != 0 {
				t.Fatalf("fresh user deletion_scheduled_at_ms = %d, want 0", got.DeletionScheduledAtMs)
			}

			// Scheduling deletion writes the status + instant atomically.
			if err := r.UpdateUser(ctx, id, map[string]any{
				"status":                   service.StatusPendingDeletion,
				"deletion_scheduled_at_ms": int64(1_800_000),
			}); err != nil {
				t.Fatalf("UpdateUser schedule: %v", err)
			}
			got, _ = r.GetUser(ctx, id)
			if got == nil || got.Status != service.StatusPendingDeletion || got.DeletionScheduledAtMs != 1_800_000 {
				t.Fatalf("after schedule: %+v", got)
			}

			// Cancelling clears the instant back to 0.
			if err := r.UpdateUser(ctx, id, map[string]any{
				"status":                   service.StatusActive,
				"deletion_scheduled_at_ms": int64(0),
			}); err != nil {
				t.Fatalf("UpdateUser cancel: %v", err)
			}
			got, _ = r.GetUser(ctx, id)
			if got == nil || got.Status != service.StatusActive || got.DeletionScheduledAtMs != 0 {
				t.Fatalf("after cancel: %+v", got)
			}
		})

		t.Run("ListUsersPendingDeletionBefore_FiltersAndOrders", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)

			// due2 (scheduled 200) and due1 (scheduled 100) are past a cutoff of
			// 500; future is scheduled after the cutoff; active/deactivated are
			// not pending deletion at all. Only due1+due2 must be returned, in
			// ascending scheduled-instant order.
			due1 := schedulePendingDeletion(t, r, "ad-due1@example.com", 100)
			due2 := schedulePendingDeletion(t, r, "ad-due2@example.com", 200)
			schedulePendingDeletion(t, r, "ad-future@example.com", 9_000)
			createTestUser(t, r, "ad-active@example.com")
			deact := createTestUser(t, r, "ad-deact@example.com")
			if err := r.UpdateUser(ctx, deact, map[string]any{"status": "deactivated"}); err != nil {
				t.Fatalf("UpdateUser deactivate: %v", err)
			}

			out, err := r.ListUsersPendingDeletionBefore(ctx, 500, 100)
			if err != nil {
				t.Fatalf("ListUsersPendingDeletionBefore: %v", err)
			}
			if len(out) != 2 {
				t.Fatalf("want 2 due users, got %d: %+v", len(out), out)
			}
			if out[0].ID != due1 || out[1].ID != due2 {
				t.Fatalf("ordering: got [%s, %s], want [%s, %s]", out[0].ID, out[1].ID, due1, due2)
			}

			// The cutoff is inclusive of its own value and exclusive of later
			// instants: cutoff=100 returns only due1.
			atBoundary, err := r.ListUsersPendingDeletionBefore(ctx, 100, 100)
			if err != nil {
				t.Fatalf("ListUsersPendingDeletionBefore boundary: %v", err)
			}
			if len(atBoundary) != 1 || atBoundary[0].ID != due1 {
				t.Fatalf("cutoff=100 must return only due1: %+v", atBoundary)
			}

			// The limit caps the batch (drains the earliest first).
			capped, err := r.ListUsersPendingDeletionBefore(ctx, 500, 1)
			if err != nil {
				t.Fatalf("ListUsersPendingDeletionBefore limit: %v", err)
			}
			if len(capped) != 1 || capped[0].ID != due1 {
				t.Fatalf("limit=1 must return only the earliest (due1): %+v", capped)
			}

			// A non-positive limit is rejected, matching the DeleteExpired* sweeps.
			for _, bad := range []int{0, -1} {
				if _, err := r.ListUsersPendingDeletionBefore(ctx, 500, bad); err == nil {
					t.Errorf("ListUsersPendingDeletionBefore limit=%d: want error, got nil", bad)
				}
			}
		})
	})
}

// schedulePendingDeletion creates a user and moves it into pending_deletion with
// the given scheduled-purge instant, returning its id. Like createTestUser it
// runs on context.Background so the two share one context discipline.
func schedulePendingDeletion(t *testing.T, r service.Repository, email string, scheduledAtMs int64) string {
	t.Helper()
	id := createTestUser(t, r, email)
	if err := r.UpdateUser(context.Background(), id, map[string]any{
		"status":                   service.StatusPendingDeletion,
		"deletion_scheduled_at_ms": scheduledAtMs,
	}); err != nil {
		t.Fatalf("schedulePendingDeletion %q: %v", email, err)
	}
	return id
}
