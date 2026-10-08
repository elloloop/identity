package conformance

import (
	"context"
	"testing"
)

// runMergedIntoConformance pins the merged_into_user_id column: default ""
// at create, and an exact round-trip through UpdateUser alongside the
// deactivated status a merge writes with it.
func runMergedIntoConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/MergedInto", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		survivor := createTestUser(t, r, "mi-survivor@example.com")
		other := createTestUser(t, r, "mi-other@example.com")
		got, err := r.GetUser(ctx, other)
		if err != nil || got == nil || got.MergedIntoUserID != "" {
			t.Fatalf("default MergedIntoUserID: %#v %v", got, err)
		}
		if err := r.UpdateUser(ctx, other, map[string]any{"status": "deactivated", "merged_into_user_id": survivor}); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		got, err = r.GetUser(ctx, other)
		if err != nil || got == nil || got.MergedIntoUserID != survivor || got.Status != "deactivated" {
			t.Fatalf("round-trip: %#v %v", got, err)
		}
	})
}
