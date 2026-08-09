package conformance

import (
	"context"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runIsolationConformance asserts tenant isolation: two independently
// constructed repositories (each a distinct tenant on postgres, a
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

// runProjectIsolationConformance is the inversion's proof (ADR-0002): two
// projects derived from ONE backing store via the driver's WithProject
// binding must not see each other's rows. Unlike TenantIsolation (which
// constructs two independent repos), this exercises the real per-request
// project scoping — the mechanism a single deployment uses to keep two
// projects' data apart through the same connection pool / SDK client / store.
//
// It asserts, for two projects A and B sharing one store: the same email is
// creatable under each (uniqueness is per-project, not global); each project
// reads back only its own row (by email and by id); a cross-project GetUser
// never surfaces the other's data; and deleting the user in A leaves B's user
// intact. A leak here is a cross-project data exposure — the most serious
// class of bug for the converged model.
//
// Drivers that do not provide a BindProject hook skip this subtest.
func runProjectIsolationConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/Project_Isolation", func(t *testing.T) {
		if driver.BindProject == nil {
			t.Skipf("%s: no BindProject hook — per-project WithProject scoping not exercised", driver.Name)
		}
		ctx := context.Background()

		base := driver.NewRepo(t)
		const projectA, projectB = "conf-project-a", "conf-project-b"
		a := driver.BindProject(t, base, projectA)
		b := driver.BindProject(t, base, projectB)

		const sharedEmail = "shared@example.com"

		uidA, err := a.CreateUser(ctx, &service.User{
			Email: sharedEmail, Status: "active", Role: "member", PasswordHash: "hash-A",
		})
		if err != nil {
			t.Fatalf("CreateUser in project A: %v", err)
		}

		// Per-project uniqueness: the SAME email is creatable in project B even
		// though A already uses it. A global unique constraint would reject it.
		uidB, err := b.CreateUser(ctx, &service.User{
			Email: sharedEmail, Status: "active", Role: "member", PasswordHash: "hash-B",
		})
		if err != nil {
			t.Fatalf("same email in project B must be allowed (per-project uniqueness): %v", err)
		}

		// Each project resolves only its OWN row by email.
		gotA, err := a.FindUserByEmail(ctx, sharedEmail)
		if err != nil || gotA == nil {
			t.Fatalf("FindUserByEmail in A: %v %#v", err, gotA)
		}
		if gotA.ID != uidA || gotA.PasswordHash != "hash-A" {
			t.Fatalf("A resolved the wrong row: got id=%q hash=%q, want id=%q hash=hash-A", gotA.ID, gotA.PasswordHash, uidA)
		}
		gotB, err := b.FindUserByEmail(ctx, sharedEmail)
		if err != nil || gotB == nil {
			t.Fatalf("FindUserByEmail in B: %v %#v", err, gotB)
		}
		if gotB.ID != uidB || gotB.PasswordHash != "hash-B" {
			t.Fatalf("B resolved the wrong row: got id=%q hash=%q, want id=%q hash=hash-B", gotB.ID, gotB.PasswordHash, uidB)
		}

		// Cross-project GetUser must not surface the other project's data.
		// (Check on DATA, not just non-nil: some backends restart their node-id
		// counter per scope, so A and B can mint the same id string; a real
		// leak is B returning A's row data.)
		if got, err := b.GetUser(ctx, uidA); err != nil {
			t.Fatalf("GetUser(uidA) in B: %v", err)
		} else if got != nil && got.PasswordHash == "hash-A" {
			t.Fatalf("cross-project leak: GetUser in B resolved A's user data: %#v", got)
		}

		// Deleting A's user must not touch B's user under the same email.
		if err := a.DeleteUser(ctx, uidA); err != nil {
			t.Fatalf("DeleteUser in A: %v", err)
		}
		if got, err := a.FindUserByEmail(ctx, sharedEmail); err != nil || got != nil {
			t.Fatalf("after delete, A must have no user for %q: got %#v (err=%v)", sharedEmail, got, err)
		}
		stillB, err := b.FindUserByEmail(ctx, sharedEmail)
		if err != nil || stillB == nil {
			t.Fatalf("delete in A leaked into B: B's user must survive: %v %#v", err, stillB)
		}
		if stillB.ID != uidB || stillB.PasswordHash != "hash-B" {
			t.Fatalf("delete in A corrupted B's row: got id=%q hash=%q, want id=%q hash=hash-B", stillB.ID, stillB.PasswordHash, uidB)
		}

		// SSO must never bridge projects (ADR-0014). One deployment runs the
		// consumer product pool and the separate, allowlisted admin project on
		// the same auth origin, which means ONE browser holds ONE SSO cookie
		// that both sign-in surfaces will present to their own project. Signing
		// into a consumer app must not hand anybody a fast path into the admin
		// project's door; the admin re-authenticates, deliberately.
		//
		// The property is structural rather than a check someone could forget:
		// every SSO lookup is project-scoped, so B simply never finds A's row.
		// This pins that, because "the query has a project_id predicate" is
		// exactly the kind of thing a later refactor drops silently.
		ssoUserB, err := b.CreateUser(ctx, &service.User{
			Email: "sso-isolation@example.com", Status: "active", Role: "member",
		})
		if err != nil {
			t.Fatalf("CreateUser for SSO isolation in B: %v", err)
		}
		const sharedCookieHash = "conf-sso-shared-cookie-hash"
		if _, err := b.CreateSSOSession(ctx, &service.SSOSessionRecord{
			TokenHash: sharedCookieHash, UserID: ssoUserB, LoginMethod: "oauth",
			CreatedAtMs: 100, LastUsedAtMs: 100, ExpiresAtMs: 9_000_000_000_000,
		}); err != nil {
			t.Fatalf("CreateSSOSession in B: %v", err)
		}

		// The same cookie value, presented to project A, is not a session.
		leaked, err := a.FindSSOSessionByHash(ctx, sharedCookieHash)
		if err != nil {
			t.Fatalf("FindSSOSessionByHash in A: %v", err)
		}
		if leaked != nil {
			t.Fatalf("cross-project SSO leak: A resolved B's session: %+v", leaked)
		}

		// Nor can A revoke or roll B's session by holding the cookie value.
		if err := a.RevokeSSOSession(ctx, sharedCookieHash, 500); err != nil {
			t.Fatalf("RevokeSSOSession in A: %v", err)
		}
		if err := a.TouchSSOSession(ctx, sharedCookieHash, 600, 1_000); err != nil {
			t.Fatalf("TouchSSOSession in A: %v", err)
		}
		intact, err := b.FindSSOSessionByHash(ctx, sharedCookieHash)
		if err != nil || intact == nil {
			t.Fatalf("B's session must survive A's writes: %v %#v", err, intact)
		}
		if intact.RevokedAtMs != 0 {
			t.Fatalf("project A revoked project B's SSO session: %+v", intact)
		}
		if intact.ExpiresAtMs != 9_000_000_000_000 {
			t.Fatalf("project A rolled project B's SSO session window: %+v", intact)
		}
	})
}
