package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runAccountAddressConformance pins the cross-driver semantics of the
// account_address column: default "" at create, exact round-trip through
// create and update, (project_id, account_address) uniqueness on non-empty
// addresses — on create and on update — with empty addresses never
// colliding, and uniqueness scoped to the project.
func runAccountAddressConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/AccountAddress", func(t *testing.T) {
		t.Run("RoundTrip_CreateUpdate", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)

			idDefault := createTestUser(t, r, "aa-default@example.com")
			got, err := r.GetUser(ctx, idDefault)
			if err != nil || got == nil {
				t.Fatalf("GetUser(default): %v %#v", err, got)
			}
			if got.AccountAddress != "" {
				t.Errorf("default AccountAddress = %q, want \"\"", got.AccountAddress)
			}

			idCreate, err := r.CreateUser(ctx, &service.User{
				Status: "active", Role: "member", Username: "aa-kid",
				AccountAddress: "aa-kid@accounts.example.com",
			})
			if err != nil {
				t.Fatalf("CreateUser(account address): %v", err)
			}
			got, err = r.GetUser(ctx, idCreate)
			if err != nil || got == nil {
				t.Fatalf("GetUser(create): %v %#v", err, got)
			}
			if got.AccountAddress != "aa-kid@accounts.example.com" {
				t.Errorf("create AccountAddress = %q", got.AccountAddress)
			}

			if err := r.UpdateUser(ctx, idDefault, map[string]any{
				"account_address": "aa-default-at-example.com@accounts.example.com",
			}); err != nil {
				t.Fatalf("UpdateUser(account address): %v", err)
			}
			got, err = r.GetUser(ctx, idDefault)
			if err != nil || got == nil {
				t.Fatalf("GetUser(update): %v %#v", err, got)
			}
			if got.AccountAddress != "aa-default-at-example.com@accounts.example.com" {
				t.Errorf("update AccountAddress = %q", got.AccountAddress)
			}
		})

		t.Run("Duplicate_Rejected", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			const addr = "taken@accounts.example.com"
			if _, err := r.CreateUser(ctx, &service.User{Status: "active", Email: "aa-1@example.com", AccountAddress: addr}); err != nil {
				t.Fatalf("first CreateUser: %v", err)
			}
			_, err := r.CreateUser(ctx, &service.User{Status: "active", Email: "aa-2@example.com", AccountAddress: addr})
			if !errors.Is(err, service.ErrAlreadyExists) {
				t.Fatalf("CreateUser duplicate account address: want ErrAlreadyExists, got %v", err)
			}
			otherID := createTestUser(t, r, "aa-3@example.com")
			err = r.UpdateUser(ctx, otherID, map[string]any{"account_address": addr})
			if !errors.Is(err, service.ErrAlreadyExists) {
				t.Fatalf("UpdateUser account address collision: want ErrAlreadyExists, got %v", err)
			}
			// Re-writing a row's own address is not a collision.
			own, err := r.CreateUser(ctx, &service.User{Status: "active", Email: "aa-4@example.com", AccountAddress: "own@accounts.example.com"})
			if err != nil {
				t.Fatalf("CreateUser own: %v", err)
			}
			if err := r.UpdateUser(ctx, own, map[string]any{"account_address": "own@accounts.example.com"}); err != nil {
				t.Fatalf("UpdateUser same address on same row: %v", err)
			}
		})

		t.Run("Assign_CompareAndSet", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			id := createTestUser(t, r, "aa-cas@example.com")
			held, err := r.AssignAccountAddress(ctx, id, "first@accounts.example.com")
			if err != nil || held != "first@accounts.example.com" {
				t.Fatalf("first assign: %q %v", held, err)
			}
			// A second assignment never replaces the held address; it reports it.
			held, err = r.AssignAccountAddress(ctx, id, "second@accounts.example.com")
			if err != nil || held != "first@accounts.example.com" {
				t.Fatalf("second assign: %q %v, want the first address kept", held, err)
			}
			got, err := r.GetUser(ctx, id)
			if err != nil || got == nil || got.AccountAddress != "first@accounts.example.com" {
				t.Fatalf("stored address: %#v %v", got, err)
			}
			// Another account's address is a clash.
			other := createTestUser(t, r, "aa-cas-2@example.com")
			if _, err := r.AssignAccountAddress(ctx, other, "first@accounts.example.com"); !errors.Is(err, service.ErrAlreadyExists) {
				t.Fatalf("clashing assign: want ErrAlreadyExists, got %v", err)
			}
			// An unknown account holds nothing.
			if held, err := r.AssignAccountAddress(ctx, "no-such-user", "x@accounts.example.com"); err != nil || held != "" {
				t.Fatalf("unknown user: %q %v", held, err)
			}
		})

		t.Run("Empty_NotUnique", func(t *testing.T) {
			r := driver.NewRepo(t)
			createTestUser(t, r, "aa-e1@example.com")
			createTestUser(t, r, "aa-e2@example.com")
		})

		t.Run("UniquePerProject_AcrossProjects", func(t *testing.T) {
			if driver.BindProject == nil {
				t.Skipf("%s: no BindProject hook — per-project scoping not exercised", driver.Name)
			}
			ctx := context.Background()
			base := driver.NewRepo(t)
			a := driver.BindProject(t, base, "aa-project-a")
			b := driver.BindProject(t, base, "aa-project-b")
			const addr = "shared@accounts.example.com"
			if _, err := a.CreateUser(ctx, &service.User{Status: "active", Email: "aa-a@example.com", AccountAddress: addr}); err != nil {
				t.Fatalf("CreateUser in project A: %v", err)
			}
			if _, err := b.CreateUser(ctx, &service.User{Status: "active", Email: "aa-b@example.com", AccountAddress: addr}); err != nil {
				t.Fatalf("same address in project B must be allowed: %v", err)
			}
		})
	})
}
