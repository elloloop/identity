package conformance

import (
	"context"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runIsolationConformance asserts tenant isolation: two independently
// constructed repositories (each a distinct tenant on entdb/postgres, a
// distinct store on memory) must not see each other's rows, and a
// unique key (email) is scoped per tenant, not global. A leak here is a
// cross-tenant data exposure — the most serious class of bug for a
// multi-tenant identity server.
func runIsolationConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/TenantIsolation", func(t *testing.T) {
		ctx := context.Background()
		a := driver.NewRepo(t)
		b := driver.NewRepo(t)

		uidA, err := a.CreateUser(ctx, &service.User{Email: "iso-a@example.com", Status: "active", Role: "member", PasswordHash: "secret-A"})
		if err != nil {
			t.Fatalf("CreateUser A: %v", err)
		}
		if _, err := b.CreateUser(ctx, &service.User{Email: "iso-b@example.com", Status: "active", Role: "member"}); err != nil {
			t.Fatalf("CreateUser B: %v", err)
		}

		// Tenant B must not resolve tenant A's user — by email or by id.
		if got, err := b.FindUserByEmail(ctx, "iso-a@example.com"); err != nil || got != nil {
			t.Fatalf("cross-tenant leak: FindUserByEmail in B found A's user: %#v (err=%v)", got, err)
		}
		// Check on DATA, not just non-nil: the memory backend restarts its
		// node-id counter per instance, so A and B can mint the same id
		// string for their respective first user. A real leak is B
		// returning A's *data* (A's email), not B's own row that happens
		// to share an id string.
		if got, err := b.GetUser(ctx, uidA); err != nil {
			t.Fatalf("GetUser in B: %v", err)
		} else if got != nil && got.Email == "iso-a@example.com" {
			t.Fatalf("cross-tenant leak: GetUser in B resolved A's user data: %#v", got)
		}
		// And symmetrically.
		if got, err := a.FindUserByEmail(ctx, "iso-b@example.com"); err != nil || got != nil {
			t.Fatalf("cross-tenant leak: FindUserByEmail in A found B's user: %#v (err=%v)", got, err)
		}

		// Per-tenant uniqueness: the same email is creatable in B even
		// though A already uses it, and resolves to B's own (distinct) row.
		uidA2InB, err := b.CreateUser(ctx, &service.User{Email: "iso-a@example.com", Status: "active", Role: "member", PasswordHash: "secret-B"})
		if err != nil {
			t.Fatalf("same email in a second tenant should be allowed: %v", err)
		}
		gotB, err := b.FindUserByEmail(ctx, "iso-a@example.com")
		if err != nil || gotB == nil {
			t.Fatalf("FindUserByEmail in B after create: %v %#v", err, gotB)
		}
		if gotB.ID == uidA {
			t.Fatalf("cross-tenant leak: B's lookup resolved to A's node id %q", uidA)
		}
		if gotB.ID != uidA2InB || gotB.PasswordHash != "secret-B" {
			t.Fatalf("B resolved the wrong row: got id=%q hash=%q, want id=%q hash=secret-B", gotB.ID, gotB.PasswordHash, uidA2InB)
		}
	})
}
