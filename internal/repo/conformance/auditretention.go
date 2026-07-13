package conformance

import (
	"context"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runAuditRetentionConformance exercises DeleteAuditEventsBefore — the GDPR Art
// 5(1)(e) storage-limitation sweep for the audit trail — which every driver
// must honour identically: events strictly older than the cutoff are removed,
// events at or after it survive, the returned count is the number removed, and
// a repeat sweep at the same cutoff is a no-op.
func runAuditRetentionConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/AuditRetention", func(t *testing.T) {
		t.Run("DeleteAuditEventsBefore_DeletesOldKeepsRecent", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)

			// actor scopes the readback; the audit trail has no users FK, so the
			// principal need not be a real user (mirrors the CreateAuditEvent
			// conformance above).
			const actor = "audit-retention-actor"
			const cutoff = 1_000

			// old1 (100) and old2 (999) are strictly before the cutoff and must
			// be deleted; boundary (1000) is AT the cutoff and must survive
			// (strictly-older semantics); recent (5000) is after it and stays.
			seed := []*service.AuditEvent{
				{EventType: "old_1", ActorUserID: actor, TargetUserID: actor, CreatedAt: 100},
				{EventType: "old_2", ActorUserID: actor, TargetUserID: actor, CreatedAt: 999},
				{EventType: "boundary", ActorUserID: actor, TargetUserID: actor, CreatedAt: cutoff},
				{EventType: "recent", ActorUserID: actor, TargetUserID: actor, CreatedAt: 5_000},
			}
			for i, e := range seed {
				if _, err := r.CreateAuditEvent(ctx, e); err != nil {
					t.Fatalf("CreateAuditEvent[%d]: %v", i, err)
				}
			}

			deleted, err := r.DeleteAuditEventsBefore(ctx, cutoff)
			if err != nil {
				t.Fatalf("DeleteAuditEventsBefore: %v", err)
			}
			if deleted != 2 {
				t.Fatalf("deleted count = %d, want 2 (old_1 + old_2)", deleted)
			}

			got, err := r.ListAuditEventsForUser(ctx, actor, 50)
			if err != nil {
				t.Fatalf("ListAuditEventsForUser: %v", err)
			}
			if len(got) != 2 {
				t.Fatalf("survivors = %d, want 2 (boundary + recent): %+v", len(got), got)
			}
			for _, e := range got {
				if e.EventType == "old_1" || e.EventType == "old_2" {
					t.Fatalf("event older than cutoff survived the sweep: %+v", e)
				}
			}

			// A repeat sweep at the same cutoff removes nothing (idempotent).
			again, err := r.DeleteAuditEventsBefore(ctx, cutoff)
			if err != nil {
				t.Fatalf("DeleteAuditEventsBefore repeat: %v", err)
			}
			if again != 0 {
				t.Fatalf("repeat sweep deleted %d, want 0", again)
			}
		})

		t.Run("DeleteAuditEventsBefore_EmptyStoreDeletesNothing", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)

			deleted, err := r.DeleteAuditEventsBefore(ctx, 1_000_000)
			if err != nil {
				t.Fatalf("DeleteAuditEventsBefore on empty store: %v", err)
			}
			if deleted != 0 {
				t.Fatalf("empty-store sweep deleted %d, want 0", deleted)
			}
		})
	})
}
