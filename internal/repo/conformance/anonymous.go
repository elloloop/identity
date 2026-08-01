package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runAnonymousConformance pins the storage semantics anonymous identity
// depends on and that every driver must share:
//
//   - any number of anonymous users coexist in one project (the per-project
//     email unique index is PARTIAL — it covers non-empty addresses only),
//     while email uniqueness still binds for users that have one;
//   - an empty address resolves nobody, so an anonymous user is never
//     returned by an email lookup;
//   - is_anonymous round-trips and is clearable through UpdateUser (the
//     upgrade path), and clearing it takes the user out of the sweep's
//     reach permanently;
//   - the retention sweep keys on last activity, is bounded by its limit,
//     and never touches a non-anonymous user.
func runAnonymousConformance(t *testing.T, driver Driver) {
	t.Helper()

	newAnon := func(t *testing.T, ctx context.Context, r service.Repository, lastLoginMs int64) string {
		t.Helper()
		id, err := r.CreateUser(ctx, &service.User{
			Status:        "active",
			IsAnonymous:   true,
			LastLoginAtMs: lastLoginMs,
		})
		if err != nil {
			t.Fatalf("CreateUser(anonymous): %v", err)
		}
		return id
	}

	t.Run(driver.Name+"/AnonymousUsersCoexist", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)

		first := newAnon(t, ctx, r, 1000)
		second := newAnon(t, ctx, r, 1000)
		if first == second {
			t.Fatalf("two anonymous users share id %q", first)
		}

		got, err := r.GetUser(ctx, first)
		if err != nil || got == nil {
			t.Fatalf("GetUser = (%#v, %v)", got, err)
		}
		if !got.IsAnonymous {
			t.Error("IsAnonymous did not round-trip")
		}
		if got.Email != "" {
			t.Errorf("anonymous user carries email %q, want empty", got.Email)
		}

		// Uniqueness still binds where an address exists.
		if _, err := r.CreateUser(ctx, &service.User{Email: "taken@example.com"}); err != nil {
			t.Fatalf("create first addressed user: %v", err)
		}
		if _, err := r.CreateUser(ctx, &service.User{Email: "taken@example.com"}); !errors.Is(err, service.ErrAlreadyExists) {
			t.Fatalf("duplicate email err = %v, want ErrAlreadyExists", err)
		}
	})

	t.Run(driver.Name+"/AnonymousUserNotFoundByEmail", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		newAnon(t, ctx, r, 1000)

		// The empty address must resolve nobody — otherwise a login for ""
		// would land on an arbitrary anonymous account.
		got, err := r.FindUserByEmail(ctx, "")
		if err != nil || got != nil {
			t.Fatalf("FindUserByEmail(\"\") = (%#v, %v), want (nil, nil)", got, err)
		}
	})

	t.Run(driver.Name+"/UpgradeClearsAnonymousFlag", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		id := newAnon(t, ctx, r, 1000)

		if err := r.UpdateUser(ctx, id, map[string]any{
			"email":        "upgraded@example.com",
			"is_anonymous": false,
		}); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		got, err := r.GetUser(ctx, id)
		if err != nil || got == nil {
			t.Fatalf("GetUser after upgrade = (%#v, %v)", got, err)
		}
		if got.IsAnonymous {
			t.Error("is_anonymous survived the upgrade")
		}
		if got.Email != "upgraded@example.com" {
			t.Errorf("Email = %q after upgrade", got.Email)
		}
		// The id is the whole point of the upgrade path.
		if got.ID != id {
			t.Errorf("upgrade changed the user id: %q -> %q", id, got.ID)
		}
	})

	t.Run(driver.Name+"/RetentionSweep", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)

		stale := newAnon(t, ctx, r, 1000)
		fresh := newAnon(t, ctx, r, 9000)

		// An upgraded account is out of the sweep's reach even though its
		// activity is just as old as the stale anonymous one.
		upgraded := newAnon(t, ctx, r, 1000)
		if err := r.UpdateUser(ctx, upgraded, map[string]any{
			"email":        "kept@example.com",
			"is_anonymous": false,
		}); err != nil {
			t.Fatalf("upgrade: %v", err)
		}

		// A user that was never anonymous is likewise untouched.
		permanent, err := r.CreateUser(ctx, &service.User{
			Email: "permanent@example.com", LastLoginAtMs: 1000,
		})
		if err != nil {
			t.Fatalf("create permanent: %v", err)
		}

		if err := r.DeleteStaleAnonymousUsers(ctx, 5000, 100); err != nil {
			if errors.Is(err, service.ErrSweepNotImplemented) {
				t.Skip("sweep not implemented for this backend")
			}
			t.Fatalf("sweep: %v", err)
		}

		for _, tc := range []struct {
			id       string
			label    string
			wantGone bool
		}{
			{stale, "stale anonymous", true},
			{fresh, "recently-active anonymous", false},
			{upgraded, "upgraded account", false},
			{permanent, "never-anonymous account", false},
		} {
			got, err := r.GetUser(ctx, tc.id)
			if err != nil && !errors.Is(err, service.ErrNotFound) {
				t.Fatalf("GetUser(%s): %v", tc.label, err)
			}
			if gone := got == nil; gone != tc.wantGone {
				t.Errorf("%s: gone=%v, want %v", tc.label, gone, tc.wantGone)
			}
		}

		// A non-positive limit is rejected rather than running unbounded.
		if err := r.DeleteStaleAnonymousUsers(ctx, 5000, 0); err == nil {
			t.Error("limit <= 0 must be rejected")
		}
	})

	t.Run(driver.Name+"/RetentionSweepRespectsLimit", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)

		// Three equally-stale users, one batch of two: the sweep must delete
		// exactly two and leave the third for the next tick.
		for i := 0; i < 3; i++ {
			newAnon(t, ctx, r, int64(1000+i))
		}
		if err := r.DeleteStaleAnonymousUsers(ctx, 5000, 2); err != nil {
			if errors.Is(err, service.ErrSweepNotImplemented) {
				t.Skip("sweep not implemented for this backend")
			}
			t.Fatalf("sweep: %v", err)
		}
		// IncludeAnonymous: the default listing excludes them, which is the
		// point of that filter — but this assertion is about which ones the
		// SWEEP left behind.
		remaining, err := r.ListUsers(ctx, service.UserListFilter{IncludeAnonymous: true})
		if err != nil {
			t.Fatalf("ListUsers: %v", err)
		}
		if len(remaining) != 1 {
			t.Fatalf("after a limit-2 sweep of 3 users, %d remain, want 1", len(remaining))
		}
		// Oldest-first: the survivor is the most recently active.
		if remaining[0].LastLoginAtMs != 1002 {
			t.Errorf("survivor LastLoginAtMs = %d, want 1002 (sweep must delete oldest first)",
				remaining[0].LastLoginAtMs)
		}
	})
}
