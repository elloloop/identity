package conformance

import (
	"context"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/service"
)

// runPasswordChangeRequiredConformance pins the password_change_required
// column: false by default, persisted by CreateUser, and cleared through
// UpdateUser together with the password that replaces the issued one.
func runPasswordChangeRequiredConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/PasswordChangeRequired", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		plain := createTestUser(t, r, "pcr-plain@example.com")
		got, err := r.GetUser(ctx, plain)
		if err != nil || got == nil || got.PasswordChangeRequired {
			t.Fatalf("default PasswordChangeRequired: %#v %v", got, err)
		}

		now := time.Now()
		issued, err := r.CreateUser(ctx, &service.User{
			Email: "pcr-issued@example.com", Status: "active", Role: "member",
			PasswordHash: "issued-hash", PasswordChangeRequired: true,
			CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		got, err = r.GetUser(ctx, issued)
		if err != nil || got == nil || !got.PasswordChangeRequired {
			t.Fatalf("CreateUser round-trip: %#v %v", got, err)
		}
		if err := r.UpdateUser(ctx, issued, map[string]any{"password_hash": "own-hash", "password_change_required": false}); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		got, err = r.GetUser(ctx, issued)
		if err != nil || got == nil || got.PasswordChangeRequired || got.PasswordHash != "own-hash" {
			t.Fatalf("UpdateUser round-trip: %#v %v", got, err)
		}
		if err := r.UpdateUser(ctx, issued, map[string]any{"password_change_required": true}); err != nil {
			t.Fatalf("UpdateUser set: %v", err)
		}
		got, _ = r.GetUser(ctx, issued)
		if !got.PasswordChangeRequired {
			t.Fatal("UpdateUser did not set password_change_required")
		}
	})
}
