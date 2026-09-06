package conformance

import (
	"context"
	"fmt"
	"sort"
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
			list, err := r.ListChildrenOfGuardian(ctx, guardian, 100, 0)
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

			// Both listings are ORDERED, not merely complete: they reach
			// clients verbatim through GetGuardians / ListManagedChildren, so
			// a driver returning them in storage-iteration order would answer
			// the same call differently every time.
			guardians, err := r.ListGuardiansOfChild(ctx, c1, 100, 0)
			if err != nil {
				t.Fatalf("ListGuardiansOfChild: %v", err)
			}
			wantGuardians := sortedPair(g1, g2)
			if len(guardians) != 2 ||
				guardians[0].GuardianUserID != wantGuardians[0] ||
				guardians[1].GuardianUserID != wantGuardians[1] {
				t.Fatalf("child c1 guardians = %s, want %v in guardian_user_id order",
					guardianIDs(guardians), wantGuardians)
			}
			children, err := r.ListChildrenOfGuardian(ctx, g1, 100, 0)
			if err != nil {
				t.Fatalf("ListChildrenOfGuardian: %v", err)
			}
			wantChildren := sortedPair(c1, c2)
			if len(children) != 2 ||
				children[0].ChildUserID != wantChildren[0] ||
				children[1].ChildUserID != wantChildren[1] {
				t.Fatalf("guardian g1 children = %s, want %v in child_user_id order",
					childIDs(children), wantChildren)
			}
			children, err = r.ListChildrenOfGuardian(ctx, g2, 100, 0)
			if err != nil {
				t.Fatalf("ListChildrenOfGuardian: %v", err)
			}
			if len(children) != 1 || children[0].ChildUserID != c1 {
				t.Fatalf("guardian g2 children = %#v, want [c1]", children)
			}
		})

		t.Run("Listings_PageInTheQuery", func(t *testing.T) {
			// Paging lives in the query, not the caller: slicing a full
			// result set in the service made a traversal re-scan every edge
			// per page. Each driver must window in SQL (or its equivalent)
			// and refuse an unbounded read outright.
			ctx := context.Background()
			r := driver.NewRepo(t)
			guardian := createTestUser(t, r, "ge-page-guardian@example.com")
			kids := make([]string, 0, 5)
			for i := 0; i < 5; i++ {
				kids = append(kids, createTestUser(t, r, fmt.Sprintf("ge-page-kid-%d@example.com", i)))
			}
			for _, kid := range kids {
				if err := r.UpsertGuardianEdge(ctx, &service.GuardianEdge{
					GuardianUserID: guardian, ChildUserID: kid, CreatedAtMs: 1,
				}); err != nil {
					t.Fatalf("upsert %s: %v", kid, err)
				}
			}
			sort.Strings(kids)

			// Walk in pages of two and expect the ordered set back exactly
			// once, with the window honoured on every call.
			var walked []string
			for offset := 0; offset < len(kids); offset += 2 {
				page, err := r.ListChildrenOfGuardian(ctx, guardian, 2, offset)
				if err != nil {
					t.Fatalf("page at offset %d: %v", offset, err)
				}
				if len(page) > 2 {
					t.Fatalf("page at offset %d returned %d rows, want at most 2", offset, len(page))
				}
				for _, e := range page {
					walked = append(walked, e.ChildUserID)
				}
			}
			if len(walked) != len(kids) {
				t.Fatalf("walked %d children, want %d", len(walked), len(kids))
			}
			for i, id := range walked {
				if id != kids[i] {
					t.Fatalf("walked = %v, want %v (ordered, no repeats)", walked, kids)
				}
			}

			// An offset past the end is an empty page, not an error.
			if page, err := r.ListChildrenOfGuardian(ctx, guardian, 2, 999); err != nil || len(page) != 0 {
				t.Fatalf("offset past end = %#v %v, want empty and nil", page, err)
			}
			// An unbounded read is refused, like the sweepers.
			if _, err := r.ListChildrenOfGuardian(ctx, guardian, 0, 0); err == nil {
				t.Fatal("ListChildrenOfGuardian limit=0: want error, got nil")
			}
			if _, err := r.ListGuardiansOfChild(ctx, kids[0], 0, 0); err == nil {
				t.Fatal("ListGuardiansOfChild limit=0: want error, got nil")
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
			if list, err := r.ListGuardiansOfChild(ctx, child, 100, 0); err != nil || len(list) != 0 {
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
			if list, err := r.ListChildrenOfGuardian(ctx, guardian, 100, 0); err != nil || len(list) != 0 {
				t.Fatalf("guardian must manage no children after child deletion, got %#v err %v", list, err)
			}
		})
	})
}

// sortedPair returns the two ids in the ascending order both drivers' ORDER BY
// produces, so the ordering assertions do not depend on which id the fixture
// happened to mint first.
func sortedPair(a, b string) []string {
	if a <= b {
		return []string{a, b}
	}
	return []string{b, a}
}

func guardianIDs(edges []*service.GuardianEdge) []string {
	out := make([]string, 0, len(edges))
	for _, e := range edges {
		out = append(out, e.GuardianUserID)
	}
	return out
}

func childIDs(edges []*service.GuardianEdge) []string {
	out := make([]string, 0, len(edges))
	for _, e := range edges {
		out = append(out, e.ChildUserID)
	}
	return out
}
