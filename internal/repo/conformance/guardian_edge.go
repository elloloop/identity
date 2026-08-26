package conformance

import (
	"context"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runGuardianEdgeConformance pins the cross-driver semantics of the
// guardian-edge methods (UpsertGuardianEdge / DeleteGuardianEdge /
// GetGuardianEdge / ListGuardiansOfChild / ListChildrenOfGuardian): every
// driver must agree on upsert idempotency (a re-upsert preserves the original
// CreatedAtMs), on (guardian, child) uniqueness, on both traversal directions,
// on absent-is-(nil, nil) reads, and — critically, because an edge is live
// authorization state rather than an audit artifact — that DeleteUser of
// EITHER side removes the edge (the SQL drivers' ON DELETE CASCADE posture).
func runGuardianEdgeConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/GuardianEdge", func(t *testing.T) {
		t.Run("UpsertGet_RoundTrip", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			guardian := createTestUser(t, r, "ge-guardian@example.com")
			child := createTestUser(t, r, "ge-child@example.com")

			if got, err := r.GetGuardianEdge(ctx, guardian, child); err != nil || got != nil {
				t.Fatalf("Get on absent: got %#v err %v, want nil nil", got, err)
			}

			e := &service.GuardianEdge{GuardianUserID: guardian, ChildUserID: child, CreatedAtMs: 1000}
			if err := r.UpsertGuardianEdge(ctx, e); err != nil {
				t.Fatalf("UpsertGuardianEdge: %v", err)
			}
			got, err := r.GetGuardianEdge(ctx, guardian, child)
			if err != nil || got == nil {
				t.Fatalf("Get: %#v %v", got, err)
			}
			if got.GuardianUserID != guardian || got.ChildUserID != child || got.CreatedAtMs != 1000 {
				t.Fatalf("value round-trip mismatch: %#v", got)
			}
		})

		t.Run("ReUpsert_Idempotent_PreservesCreatedAt", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			guardian := createTestUser(t, r, "ge-idem-guardian@example.com")
			child := createTestUser(t, r, "ge-idem-child@example.com")

			if err := r.UpsertGuardianEdge(ctx, &service.GuardianEdge{GuardianUserID: guardian, ChildUserID: child, CreatedAtMs: 1000}); err != nil {
				t.Fatalf("first upsert: %v", err)
			}
			// A second upsert of the same (guardian, child) pair must neither
			// error nor duplicate nor move created_at_ms.
			if err := r.UpsertGuardianEdge(ctx, &service.GuardianEdge{GuardianUserID: guardian, ChildUserID: child, CreatedAtMs: 9999}); err != nil {
				t.Fatalf("re-upsert: %v", err)
			}
			got, err := r.GetGuardianEdge(ctx, guardian, child)
			if err != nil || got == nil {
				t.Fatalf("Get: %#v %v", got, err)
			}
			if got.CreatedAtMs != 1000 {
				t.Fatalf("re-upsert moved created_at_ms to %d, want 1000", got.CreatedAtMs)
			}
			list, err := r.ListChildrenOfGuardian(ctx, guardian)
			if err != nil {
				t.Fatalf("ListChildrenOfGuardian: %v", err)
			}
			if len(list) != 1 {
				t.Fatalf("re-upsert duplicated the edge: %d rows, want 1", len(list))
			}
		})

		t.Run("ManyGuardiansManyChildren", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			g1 := createTestUser(t, r, "ge-mg-1@example.com")
			g2 := createTestUser(t, r, "ge-mg-2@example.com")
			c1 := createTestUser(t, r, "ge-mc-1@example.com")
			c2 := createTestUser(t, r, "ge-mc-2@example.com")

			for _, e := range [][2]string{{g1, c1}, {g2, c1}, {g1, c2}} {
				if err := r.UpsertGuardianEdge(ctx, &service.GuardianEdge{GuardianUserID: e[0], ChildUserID: e[1], CreatedAtMs: 1}); err != nil {
					t.Fatalf("upsert %v: %v", e, err)
				}
			}

			guardians, err := r.ListGuardiansOfChild(ctx, c1)
			if err != nil {
				t.Fatalf("ListGuardiansOfChild: %v", err)
			}
			if len(guardians) != 2 {
				t.Fatalf("child c1 has %d guardians, want 2", len(guardians))
			}
			children, err := r.ListChildrenOfGuardian(ctx, g1)
			if err != nil {
				t.Fatalf("ListChildrenOfGuardian: %v", err)
			}
			if len(children) != 2 {
				t.Fatalf("guardian g1 manages %d children, want 2", len(children))
			}
			children, err = r.ListChildrenOfGuardian(ctx, g2)
			if err != nil {
				t.Fatalf("ListChildrenOfGuardian: %v", err)
			}
			if len(children) != 1 || children[0].ChildUserID != c1 {
				t.Fatalf("guardian g2 children = %#v, want [c1]", children)
			}
		})

		t.Run("Delete_RemovesEdge", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			guardian := createTestUser(t, r, "ge-del-guardian@example.com")
			child := createTestUser(t, r, "ge-del-child@example.com")

			if err := r.UpsertGuardianEdge(ctx, &service.GuardianEdge{GuardianUserID: guardian, ChildUserID: child, CreatedAtMs: 1}); err != nil {
				t.Fatalf("upsert: %v", err)
			}
			if err := r.DeleteGuardianEdge(ctx, guardian, child); err != nil {
				t.Fatalf("DeleteGuardianEdge: %v", err)
			}
			if got, err := r.GetGuardianEdge(ctx, guardian, child); err != nil || got != nil {
				t.Fatalf("Get after delete: got %#v err %v, want nil nil", got, err)
			}
			// Deleting an absent edge is not an error.
			if err := r.DeleteGuardianEdge(ctx, guardian, child); err != nil {
				t.Fatalf("delete of absent edge: %v", err)
			}
		})

		t.Run("GuardianDeletion_RemovesEdge", func(t *testing.T) {
			// Unlike the parental-consent record (an audit artifact that
			// survives DeleteUser), the edge is live authorization state: it
			// must die with the guardian.
			ctx := context.Background()
			r := driver.NewRepo(t)
			guardian := createTestUser(t, r, "ge-gdel-guardian@example.com")
			child := createTestUser(t, r, "ge-gdel-child@example.com")
			if err := r.UpsertGuardianEdge(ctx, &service.GuardianEdge{GuardianUserID: guardian, ChildUserID: child, CreatedAtMs: 1}); err != nil {
				t.Fatalf("upsert: %v", err)
			}
			if err := r.DeleteUser(ctx, guardian); err != nil {
				t.Fatalf("DeleteUser: %v", err)
			}
			if got, err := r.GetGuardianEdge(ctx, guardian, child); err != nil || got != nil {
				t.Fatalf("edge must die with the guardian, got %#v err %v", got, err)
			}
			if list, err := r.ListGuardiansOfChild(ctx, child); err != nil || len(list) != 0 {
				t.Fatalf("child must have no guardians after guardian deletion, got %#v err %v", list, err)
			}
		})

		t.Run("ChildDeletion_RemovesEdge", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			guardian := createTestUser(t, r, "ge-cdel-guardian@example.com")
			child := createTestUser(t, r, "ge-cdel-child@example.com")
			if err := r.UpsertGuardianEdge(ctx, &service.GuardianEdge{GuardianUserID: guardian, ChildUserID: child, CreatedAtMs: 1}); err != nil {
				t.Fatalf("upsert: %v", err)
			}
			if err := r.DeleteUser(ctx, child); err != nil {
				t.Fatalf("DeleteUser: %v", err)
			}
			if got, err := r.GetGuardianEdge(ctx, guardian, child); err != nil || got != nil {
				t.Fatalf("edge must die with the child, got %#v err %v", got, err)
			}
			if list, err := r.ListChildrenOfGuardian(ctx, guardian); err != nil || len(list) != 0 {
				t.Fatalf("guardian must manage no children after child deletion, got %#v err %v", list, err)
			}
		})
	})
}
