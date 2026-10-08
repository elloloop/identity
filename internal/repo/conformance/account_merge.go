package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runAccountMergeConformance pins ApplyAccountMerge across drivers: one
// transaction that retires the other account, moves what it is asked to, and
// refuses (changing nothing) when either account is no longer active and
// unmerged.
func runAccountMergeConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/AccountMerge", func(t *testing.T) {
		t.Run("MovesAndRetires", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			survivor, err := r.CreateUser(ctx, &service.User{Status: "active", Role: "member", Email: "am-s@example.com", AccountAddress: "am-s@accounts.example.com"})
			if err != nil {
				t.Fatal(err)
			}
			other, err := r.CreateUser(ctx, &service.User{Status: "active", Role: "member", Username: "am-bob", PasswordHash: "hash", AccountAddress: "am-bob@accounts.example.com"})
			if err != nil {
				t.Fatal(err)
			}
			if err := r.ApplyAccountMerge(ctx, service.AccountMerge{
				SurvivorID: survivor, OtherID: other,
				MoveUsername: true, MovePassword: true, SwapAddress: true, AtMs: 1000,
			}); err != nil {
				t.Fatalf("ApplyAccountMerge: %v", err)
			}
			s, _ := r.GetUser(ctx, survivor)
			o, _ := r.GetUser(ctx, other)
			if s.Username != "am-bob" || s.PasswordHash != "hash" || s.AccountAddress != "am-bob@accounts.example.com" {
				t.Fatalf("survivor after merge: %#v", s)
			}
			if o.Status != "deactivated" || o.MergedIntoUserID != survivor || o.Username != "" || o.AccountAddress != "am-s@accounts.example.com" {
				t.Fatalf("retired after merge: %#v", o)
			}
			// A second merge of the same account is a conflict and changes nothing.
			if err := r.ApplyAccountMerge(ctx, service.AccountMerge{SurvivorID: survivor, OtherID: other, AtMs: 2000}); !errors.Is(err, service.ErrMergeConflict) {
				t.Fatalf("second merge: want ErrMergeConflict, got %v", err)
			}
			// Nor can the survivor be merged into the retired account.
			if err := r.ApplyAccountMerge(ctx, service.AccountMerge{SurvivorID: other, OtherID: survivor, AtMs: 3000}); !errors.Is(err, service.ErrMergeConflict) {
				t.Fatalf("reverse merge: want ErrMergeConflict, got %v", err)
			}
			s2, _ := r.GetUser(ctx, survivor)
			if s2.Status != "active" || s2.Username != "am-bob" {
				t.Fatalf("a refused merge changed the survivor: %#v", s2)
			}
		})
	})
}
