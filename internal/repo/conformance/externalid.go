package conformance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/service"
)

// RunExternalIDConformance exercises the SCIM externalId surface every
// driver must honour identically (#260): external_id round-trips through
// CreateUser/UpdateUser, FindUserByExternalID resolves exactly within the
// project, a non-empty external_id is unique per project (collision →
// service.ErrAlreadyExists on both create and update), an empty external_id
// is exempt from uniqueness, and ListUsers filters + paginates with the
// same ordering across backends.
func runExternalIDConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/ExternalID", func(t *testing.T) {
		t.Run("RoundTrip_CreateFind", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)

			// Empty external_id never matches.
			if got, err := r.FindUserByExternalID(ctx, ""); err != nil || got != nil {
				t.Fatalf("FindUserByExternalID empty: got=%#v err=%v", got, err)
			}
			if got, err := r.FindUserByExternalID(ctx, "okta-1"); err != nil || got != nil {
				t.Fatalf("FindUserByExternalID before create: got=%#v err=%v", got, err)
			}

			id, err := r.CreateUser(ctx, &service.User{
				Email: "ext-rt@example.com", Status: "active", Role: "member",
				ExternalID: "okta-1",
			})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			got, err := r.FindUserByExternalID(ctx, "okta-1")
			if err != nil || got == nil {
				t.Fatalf("FindUserByExternalID: got=%#v err=%v", got, err)
			}
			if got.ID != id || got.ExternalID != "okta-1" {
				t.Fatalf("FindUserByExternalID round-trip: %+v", got)
			}
			// GetUser/FindUserByEmail also carry external_id.
			byID, _ := r.GetUser(ctx, id)
			if byID == nil || byID.ExternalID != "okta-1" {
				t.Fatalf("GetUser external_id = %#v", byID)
			}
		})

		t.Run("UpdateSetsExternalID", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			id, err := r.CreateUser(ctx, &service.User{Email: "ext-upd@example.com", Status: "active"})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			if err := r.UpdateUser(ctx, id, map[string]any{"external_id": "entra-9"}); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
			got, _ := r.FindUserByExternalID(ctx, "entra-9")
			if got == nil || got.ID != id {
				t.Fatalf("after UpdateUser external_id: %#v", got)
			}
		})

		t.Run("UniquePerProject_Create", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			if _, err := r.CreateUser(ctx, &service.User{Email: "ext-a@example.com", Status: "active", ExternalID: "dup-1"}); err != nil {
				t.Fatalf("first CreateUser: %v", err)
			}
			_, err := r.CreateUser(ctx, &service.User{Email: "ext-b@example.com", Status: "active", ExternalID: "dup-1"})
			if !errors.Is(err, service.ErrAlreadyExists) {
				t.Fatalf("duplicate external_id on create: want ErrAlreadyExists, got %v", err)
			}
		})

		t.Run("UniquePerProject_Update", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			if _, err := r.CreateUser(ctx, &service.User{Email: "ext-c@example.com", Status: "active", ExternalID: "taken"}); err != nil {
				t.Fatalf("CreateUser c: %v", err)
			}
			otherID, err := r.CreateUser(ctx, &service.User{Email: "ext-d@example.com", Status: "active"})
			if err != nil {
				t.Fatalf("CreateUser d: %v", err)
			}
			err = r.UpdateUser(ctx, otherID, map[string]any{"external_id": "taken"})
			if !errors.Is(err, service.ErrAlreadyExists) {
				t.Fatalf("duplicate external_id on update: want ErrAlreadyExists, got %v", err)
			}
		})

		t.Run("UniquePerProject_AcrossProjects", func(t *testing.T) {
			// The proof that external_id uniqueness is scoped to the project,
			// NOT global: the SAME external_id is creatable under two projects
			// derived from ONE backing store (the real per-request WithProject
			// scoping). A global unique index — the memory-driver bug this
			// asserts against — would reject the second create. Drivers without
			// a BindProject hook skip (none in tree).
			if driver.BindProject == nil {
				t.Skipf("%s: no BindProject hook — per-project external_id scoping not exercised", driver.Name)
			}
			ctx := context.Background()
			base := driver.NewRepo(t)
			const projectA, projectB = "ext-project-a", "ext-project-b"
			a := driver.BindProject(t, base, projectA)
			b := driver.BindProject(t, base, projectB)

			const (
				sharedExt = "okta-shared"
				emailA    = "ext-iso-a@example.com"
				emailB    = "ext-iso-b@example.com"
			)
			if _, err := a.CreateUser(ctx, &service.User{
				Email: emailA, Status: "active", Role: "member", ExternalID: sharedExt,
			}); err != nil {
				t.Fatalf("CreateUser in project A: %v", err)
			}
			// Same external_id under project B must be allowed (per-project, not global).
			if _, err := b.CreateUser(ctx, &service.User{
				Email: emailB, Status: "active", Role: "member", ExternalID: sharedExt,
			}); err != nil {
				t.Fatalf("same external_id in project B must be allowed (per-project uniqueness): %v", err)
			}
			// Each project resolves only its OWN row by external_id. Compare on
			// DATA (email), not id: some backends restart their id counter per
			// scope, so A and B can mint the same id string for their first row;
			// a real leak is B resolving A's row data.
			gotA, err := a.FindUserByExternalID(ctx, sharedExt)
			if err != nil || gotA == nil || gotA.Email != emailA {
				t.Fatalf("FindUserByExternalID in A: got=%#v err=%v want email=%q", gotA, err, emailA)
			}
			gotB, err := b.FindUserByExternalID(ctx, sharedExt)
			if err != nil || gotB == nil || gotB.Email != emailB {
				t.Fatalf("FindUserByExternalID in B: got=%#v err=%v want email=%q", gotB, err, emailB)
			}
		})

		t.Run("EmptyExternalID_NotUnique", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			// Two users with empty external_id coexist (no constraint).
			if _, err := r.CreateUser(ctx, &service.User{Email: "ext-e1@example.com", Status: "active"}); err != nil {
				t.Fatalf("CreateUser e1: %v", err)
			}
			if _, err := r.CreateUser(ctx, &service.User{Email: "ext-e2@example.com", Status: "active"}); err != nil {
				t.Fatalf("CreateUser e2 (empty external_id must not collide): %v", err)
			}
		})

		t.Run("ListUsers_FilterAndPaginate", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			base := time.UnixMilli(1_700_000_000_000)
			for i, email := range []string{"l1@example.com", "l2@example.com", "l3@example.com"} {
				if _, err := r.CreateUser(ctx, &service.User{
					Email: email, Status: "active",
					CreatedAt: base.Add(time.Duration(i) * time.Millisecond),
					UpdatedAt: base.Add(time.Duration(i) * time.Millisecond),
				}); err != nil {
					t.Fatalf("CreateUser %s: %v", email, err)
				}
			}

			// Filter by email eq resolves exactly one (case-insensitive).
			byEmail, err := r.ListUsers(ctx, service.UserListFilter{Email: "L2@EXAMPLE.COM"})
			if err != nil {
				t.Fatalf("ListUsers byEmail: %v", err)
			}
			if len(byEmail) != 1 || byEmail[0].Email != "l2@example.com" {
				t.Fatalf("ListUsers email filter: %+v", byEmail)
			}

			// Pagination: first page (created_at asc), then offset.
			page1, err := r.ListUsers(ctx, service.UserListFilter{Limit: 2})
			if err != nil {
				t.Fatalf("ListUsers page1: %v", err)
			}
			if len(page1) != 2 || page1[0].Email != "l1@example.com" || page1[1].Email != "l2@example.com" {
				t.Fatalf("ListUsers page1 ordering: %+v", page1)
			}
			page2, err := r.ListUsers(ctx, service.UserListFilter{Limit: 2, Offset: 2})
			if err != nil {
				t.Fatalf("ListUsers page2: %v", err)
			}
			if len(page2) != 1 || page2[0].Email != "l3@example.com" {
				t.Fatalf("ListUsers page2: %+v", page2)
			}

			// Offset past the end yields nothing.
			none, err := r.ListUsers(ctx, service.UserListFilter{Offset: 99})
			if err != nil {
				t.Fatalf("ListUsers past end: %v", err)
			}
			if len(none) != 0 {
				t.Fatalf("ListUsers past end: want empty, got %+v", none)
			}

			// CountUsers reports the full match count, INDEPENDENT of the
			// Offset/Limit window — the contract the SCIM totalResults relies on
			// so a large project never truncates at the page cap. Every driver
			// must count identically.
			total, err := r.CountUsers(ctx, service.UserListFilter{})
			if err != nil || total != 3 {
				t.Fatalf("CountUsers all: got=%d err=%v want 3", total, err)
			}
			// A page-sized window must not change the count.
			totalPaged, err := r.CountUsers(ctx, service.UserListFilter{Limit: 1, Offset: 2})
			if err != nil || totalPaged != 3 {
				t.Fatalf("CountUsers ignores Offset/Limit: got=%d err=%v want 3", totalPaged, err)
			}
			// The equality filter narrows the count the same as ListUsers.
			byEmailCount, err := r.CountUsers(ctx, service.UserListFilter{Email: "L2@EXAMPLE.COM"})
			if err != nil || byEmailCount != 1 {
				t.Fatalf("CountUsers email filter: got=%d err=%v want 1", byEmailCount, err)
			}
		})
	})
}
