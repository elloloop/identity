package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runManagedChildConformance pins the cross-driver semantics of the
// managed-child-account surface (#460):
//
//   - the username column: default "" at create, exact round-trip through
//     create/update, lookup via FindUserByUsername (empty matches nobody);
//   - (project_id, username) uniqueness on non-empty usernames — including
//     across UpdateUser — with empty usernames never colliding (the partial
//     index posture);
//   - Repository.CreateManagedChildAccount atomicity: the child user, the
//     guardian edge, and the consent record are ALL visible after a success,
//     and a duplicate username fails with service.ErrAlreadyExists leaving
//     NONE of the three behind (the child id the failed call minted resolves
//     to nothing, no edge, no consent).
func runManagedChildConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/Username", func(t *testing.T) {
		t.Run("RoundTrip_CreateUpdateLookup", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)

			// Omitted at create → "" (not a managed child).
			idDefault := createTestUser(t, r, "un-default@example.com")
			gotDefault, err := r.GetUser(ctx, idDefault)
			if err != nil || gotDefault == nil {
				t.Fatalf("GetUser(default): %v %#v", err, gotDefault)
			}
			if gotDefault.Username != "" {
				t.Errorf("default Username = %q, want \"\"", gotDefault.Username)
			}

			// Set at create → reads back exactly and resolves by lookup.
			idCreate, err := r.CreateUser(ctx, &service.User{
				Status: "active", Role: "member",
				Name: "Kid", Username: "kid.one",
			})
			if err != nil {
				t.Fatalf("CreateUser(username): %v", err)
			}
			gotCreate, err := r.GetUser(ctx, idCreate)
			if err != nil || gotCreate == nil {
				t.Fatalf("GetUser(create): %v %#v", err, gotCreate)
			}
			if gotCreate.Username != "kid.one" {
				t.Errorf("create Username = %q, want %q", gotCreate.Username, "kid.one")
			}
			byName, err := r.FindUserByUsername(ctx, "kid.one")
			if err != nil || byName == nil || byName.ID != idCreate {
				t.Fatalf("FindUserByUsername: %#v err=%v, want id %q", byName, err, idCreate)
			}

			// Updated → reads back the new value and the lookup follows.
			if err := r.UpdateUser(ctx, idCreate, map[string]any{"username": "kid.two"}); err != nil {
				t.Fatalf("UpdateUser(username): %v", err)
			}
			gotUpdate, err := r.GetUser(ctx, idCreate)
			if err != nil || gotUpdate == nil {
				t.Fatalf("GetUser(update): %v %#v", err, gotUpdate)
			}
			if gotUpdate.Username != "kid.two" {
				t.Errorf("update Username = %q, want %q", gotUpdate.Username, "kid.two")
			}
			if stale, err := r.FindUserByUsername(ctx, "kid.one"); err != nil || stale != nil {
				t.Fatalf("FindUserByUsername(old): %#v err=%v, want nil nil", stale, err)
			}

			// Empty matches nobody — like the email lookup's early return.
			if got, err := r.FindUserByUsername(ctx, ""); err != nil || got != nil {
				t.Fatalf("FindUserByUsername(\"\"): %#v err=%v, want nil nil", got, err)
			}
		})

		t.Run("Duplicate_Username_Rejected", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			if _, err := r.CreateUser(ctx, &service.User{Status: "active", Username: "taken"}); err != nil {
				t.Fatalf("first CreateUser: %v", err)
			}
			_, err := r.CreateUser(ctx, &service.User{Status: "active", Username: "taken"})
			if !errors.Is(err, service.ErrAlreadyExists) {
				t.Fatalf("CreateUser duplicate username: want ErrAlreadyExists, got %v", err)
			}
			// An update that collides must conflict identically (the SQL
			// drivers' unique index fires on UPDATE too).
			otherID, err := r.CreateUser(ctx, &service.User{Status: "active", Username: "other"})
			if err != nil {
				t.Fatalf("second CreateUser: %v", err)
			}
			if err := r.UpdateUser(ctx, otherID, map[string]any{"username": "taken"}); !errors.Is(err, service.ErrAlreadyExists) {
				t.Fatalf("UpdateUser username collision: want ErrAlreadyExists, got %v", err)
			}
		})

		t.Run("EmptyUsername_NotUnique", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			// The index is partial (WHERE username <> ''): any number of
			// email-only or anonymous accounts coexist with no username.
			if _, err := r.CreateUser(ctx, &service.User{Email: "un-e1@example.com", Status: "active"}); err != nil {
				t.Fatalf("CreateUser e1: %v", err)
			}
			if _, err := r.CreateUser(ctx, &service.User{Email: "un-e2@example.com", Status: "active"}); err != nil {
				t.Fatalf("CreateUser e2 (empty username must not collide): %v", err)
			}
		})

		t.Run("UniquePerProject_AcrossProjects", func(t *testing.T) {
			// The proof that username uniqueness is scoped to the project, NOT
			// global: the SAME username is creatable under two projects derived
			// from ONE backing store. A global unique index — the memory-driver
			// bug class this asserts against — would reject the second create.
			if driver.BindProject == nil {
				t.Skipf("%s: no BindProject hook — per-project username scoping not exercised", driver.Name)
			}
			ctx := context.Background()
			base := driver.NewRepo(t)
			const projectA, projectB = "un-project-a", "un-project-b"
			a := driver.BindProject(t, base, projectA)
			b := driver.BindProject(t, base, projectB)

			if _, err := a.CreateUser(ctx, &service.User{Status: "active", Username: "shared-name"}); err != nil {
				t.Fatalf("CreateUser in project A: %v", err)
			}
			if _, err := b.CreateUser(ctx, &service.User{Status: "active", Username: "shared-name"}); err != nil {
				t.Fatalf("same username in project B must be allowed (per-project uniqueness): %v", err)
			}
			// Each project resolves only its OWN row.
			gotA, err := a.FindUserByUsername(ctx, "shared-name")
			if err != nil || gotA == nil {
				t.Fatalf("FindUserByUsername in A: %#v err=%v", gotA, err)
			}
			gotB, err := b.FindUserByUsername(ctx, "shared-name")
			if err != nil || gotB == nil {
				t.Fatalf("FindUserByUsername in B: %#v err=%v", gotB, err)
			}
			// Compare on DATA, not id: some backends restart their id counter
			// per scope, so A and B can mint the same id string for their first
			// row; a real leak is B resolving A's row data.
			if gotA.Username != "shared-name" || gotB.Username != "shared-name" {
				t.Fatalf("username round-trip across projects: A=%q B=%q", gotA.Username, gotB.Username)
			}
		})
	})

	t.Run(driver.Name+"/CreateManagedChildAccount", func(t *testing.T) {
		// seedArgs builds a fresh (user, edge, consent) triple for the given
		// username against an already-persisted guardian (the SQL drivers
		// enforce the guardian_edges FK).
		seedArgs := func(guardian, username string) (*service.User, *service.GuardianEdge, *service.ParentalConsentRecord) {
			u := &service.User{Status: "active", Role: "member", Name: "Kid", Username: username}
			edge := &service.GuardianEdge{GuardianUserID: guardian, CreatedAtMs: 1000}
			consent := &service.ParentalConsentRecord{
				ConsentID:        "mc-consent-" + username,
				ConsentingUserID: guardian,
				PolicyVersion:    "notice-v1",
				Factors:          "passkey",
				SteppedUp:        true,
				GrantedAt:        1000,
				Market:           "IN",
			}
			return u, edge, consent
		}

		t.Run("AtomicThreeRows_AllVisible", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			guardian := createTestUser(t, r, "mc-guardian-atomic@example.com")
			u, edge, consent := seedArgs(guardian, "mc-atomic")

			if err := r.CreateManagedChildAccount(ctx, u, edge, consent); err != nil {
				t.Fatalf("CreateManagedChildAccount: %v", err)
			}
			if u.ID == "" {
				t.Fatal("CreateManagedChildAccount did not set the child id")
			}

			gotUser, err := r.GetUser(ctx, u.ID)
			if err != nil || gotUser == nil {
				t.Fatalf("child user not visible: %#v err=%v", gotUser, err)
			}
			if gotUser.Username != "mc-atomic" || gotUser.Status != "active" {
				t.Fatalf("child row mismatch: %#v", gotUser)
			}
			gotEdge, err := r.GetGuardianEdge(ctx, guardian, u.ID)
			if err != nil || gotEdge == nil {
				t.Fatalf("guardian edge not visible: %#v err=%v", gotEdge, err)
			}
			if gotEdge.CreatedAtMs != 1000 {
				t.Fatalf("edge created_at_ms = %d, want 1000", gotEdge.CreatedAtMs)
			}
			gotConsent, err := r.GetActiveParentalConsentForChild(ctx, u.ID)
			if err != nil || gotConsent == nil {
				t.Fatalf("consent record not visible: %#v err=%v", gotConsent, err)
			}
			if gotConsent.ConsentID != "mc-consent-mc-atomic" || gotConsent.ConsentingUserID != guardian || gotConsent.Market != "IN" {
				t.Fatalf("consent record mismatch: %#v", gotConsent)
			}
		})

		t.Run("DuplicateUsername_LeavesNothing", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			guardian := createTestUser(t, r, "mc-guardian-dup@example.com")
			u1, e1, c1 := seedArgs(guardian, "mc-dup")
			if err := r.CreateManagedChildAccount(ctx, u1, e1, c1); err != nil {
				t.Fatalf("first CreateManagedChildAccount: %v", err)
			}

			// A second create with the same username must fail with
			// ErrAlreadyExists and commit NOTHING: no second user row, no
			// second edge, no consent record.
			u2, e2, c2 := seedArgs(guardian, "mc-dup")
			c2.ConsentID = "mc-consent-mc-dup-2"
			if err := r.CreateManagedChildAccount(ctx, u2, e2, c2); !errors.Is(err, service.ErrAlreadyExists) {
				t.Fatalf("duplicate CreateManagedChildAccount: want ErrAlreadyExists, got %v", err)
			}
			if got, err := r.GetUser(ctx, u2.ID); err != nil || got != nil {
				t.Fatalf("failed create leaked a user row: %#v err=%v", got, err)
			}
			if got, err := r.GetGuardianEdge(ctx, guardian, u2.ID); err != nil || got != nil {
				t.Fatalf("failed create leaked a guardian edge: %#v err=%v", got, err)
			}
			if got, err := r.GetActiveParentalConsentForChild(ctx, u2.ID); err != nil || got != nil {
				t.Fatalf("failed create leaked a consent record: %#v err=%v", got, err)
			}
			// The first child's rows are untouched.
			children, err := r.ListChildrenOfGuardian(ctx, guardian, 100, 0)
			if err != nil || len(children) != 1 {
				t.Fatalf("guardian children = %#v err=%v, want exactly 1", children, err)
			}
			byName, err := r.FindUserByUsername(ctx, "mc-dup")
			if err != nil || byName == nil || byName.ID != u1.ID {
				t.Fatalf("username must still resolve to the FIRST child: %#v err=%v", byName, err)
			}
		})
	})
}
