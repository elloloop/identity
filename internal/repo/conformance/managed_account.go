package conformance

import (
	"context"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/service"
)

// runManagedAccountConformance pins the managed-account columns of users:
// a personal account reads managed_by_tenant_id "", set_up_at_ms 0 and
// setup_epoch 0, and CreateUser persists all three, read back by id and by
// email alike.
func runManagedAccountConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/ManagedAccountColumns", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		personal := createTestUser(t, r, "personal@example.com")
		got, err := r.GetUser(ctx, personal)
		if err != nil || got == nil {
			t.Fatalf("GetUser: %#v %v", got, err)
		}
		if got.ManagedByTenantID != "" || got.SetUpAtMs != 0 || got.SetupEpoch != 0 {
			t.Fatalf("a personal account must read as unmanaged: %#v", got)
		}

		now := time.Now()
		managed, err := r.CreateUser(ctx, &service.User{
			Email: "ann@acme.example.com", Name: "Ann", Status: service.StatusActive, Role: "member",
			ManagedByTenantID: "tenant-acme", SetUpAtMs: now.UnixMilli(), SetupEpoch: 3,
			CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		for name, read := range map[string]func() (*service.User, error){
			"GetUser":         func() (*service.User, error) { return r.GetUser(ctx, managed) },
			"FindUserByEmail": func() (*service.User, error) { return r.FindUserByEmail(ctx, "ann@acme.example.com") },
		} {
			got, err := read()
			if err != nil || got == nil {
				t.Fatalf("%s: %#v %v", name, got, err)
			}
			if got.ManagedByTenantID != "tenant-acme" || got.SetUpAtMs != now.UnixMilli() || got.SetupEpoch != 3 {
				t.Fatalf("%s round-trip: %#v", name, got)
			}
		}
	})
}
