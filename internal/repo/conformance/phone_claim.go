package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runPhoneClaimConformance pins the rule a project that keeps phone numbers
// unique relies on: one account holds a number, and it moves only once
// released or once its claim is older than the caller allows.
func runPhoneClaimConformance(t *testing.T, driver Driver) {
	t.Helper()

	phoneOf := func(t *testing.T, r service.Repository, id string) (string, bool, int64) {
		t.Helper()
		u, err := r.GetUser(context.Background(), id)
		if err != nil || u == nil {
			t.Fatalf("GetUser(%s) = %#v %v", id, u, err)
		}
		return u.PhoneNumber, u.PhoneVerified, u.PhoneVerifiedAt
	}

	t.Run(driver.Name+"/PhoneClaim_OneAccountPerNumber", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		a := createTestUser(t, r, "claim-a@example.com")
		b := createTestUser(t, r, "claim-b@example.com")
		const number = "+14155550101"

		if prev, err := r.ClaimPhoneNumber(ctx, a, number, 100, 0); err != nil || prev != "" {
			t.Fatalf("first claim = %q %v, want no previous holder", prev, err)
		}
		if n, ok, at := phoneOf(t, r, a); n != number || !ok || at != 100 {
			t.Fatalf("holder's phone = %q %v %d", n, ok, at)
		}
		// Claiming again is the holder's to do, and keeps the claim's age.
		if prev, err := r.ClaimPhoneNumber(ctx, a, number, 150, 0); err != nil || prev != "" {
			t.Fatalf("re-claim by the holder = %q %v", prev, err)
		}
		// Another account is refused, whatever the claim's age, when nothing
		// may be taken over, and while the claim is not older than the bound.
		for _, takeOverBefore := range []int64{0, 100} {
			if _, err := r.ClaimPhoneNumber(ctx, b, number, 200, takeOverBefore); !errors.Is(err, service.ErrPhoneNumberTaken) {
				t.Fatalf("claim of a held number (take over before %d): want ErrPhoneNumberTaken, got %v", takeOverBefore, err)
			}
		}
		if n, ok, _ := phoneOf(t, r, b); n != "" || ok {
			t.Fatalf("a refused claim changed the claimant: %q %v", n, ok)
		}
		if n, ok, _ := phoneOf(t, r, a); n != number || !ok {
			t.Fatalf("a refused claim changed the holder: %q %v", n, ok)
		}

		// A claim older than the bound moves, and the previous holder loses
		// the number.
		prev, err := r.ClaimPhoneNumber(ctx, b, number, 300, 101)
		if err != nil || prev != a {
			t.Fatalf("take over = %q %v, want previous holder %q", prev, err, a)
		}
		if n, ok, at := phoneOf(t, r, a); n != "" || ok || at != 0 {
			t.Fatalf("previous holder kept %q %v %d", n, ok, at)
		}
		if n, ok, at := phoneOf(t, r, b); n != number || !ok || at != 300 {
			t.Fatalf("new holder's phone = %q %v %d", n, ok, at)
		}
		// The move restarts the claim's age.
		if _, err := r.ClaimPhoneNumber(ctx, a, number, 400, 300); !errors.Is(err, service.ErrPhoneNumberTaken) {
			t.Fatalf("claim against the moved claim: want ErrPhoneNumberTaken, got %v", err)
		}
		if _, err := r.ClaimPhoneNumber(ctx, "no-such-user", "+14155550199", 1, 0); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("claim by a missing user: want ErrNotFound, got %v", err)
		}
	})

	t.Run(driver.Name+"/PhoneClaim_ReleasedByChangeRemovalAndDeletion", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		a := createTestUser(t, r, "release-a@example.com")
		b := createTestUser(t, r, "release-b@example.com")
		const first, second = "+14155550111", "+14155550122"

		if _, err := r.ClaimPhoneNumber(ctx, a, first, 100, 0); err != nil {
			t.Fatalf("claim: %v", err)
		}
		// Changing number releases the old one.
		if _, err := r.ClaimPhoneNumber(ctx, a, second, 200, 0); err != nil {
			t.Fatalf("change of number: %v", err)
		}
		if prev, err := r.ClaimPhoneNumber(ctx, b, first, 300, 0); err != nil || prev != "" {
			t.Fatalf("claim of a number its holder changed away from = %q %v", prev, err)
		}
		// Removing a number releases it and clears it on the user.
		if err := r.ReleasePhoneNumber(ctx, a, 400); err != nil {
			t.Fatalf("release: %v", err)
		}
		if n, ok, at := phoneOf(t, r, a); n != "" || ok || at != 0 {
			t.Fatalf("after release the user holds %q %v %d", n, ok, at)
		}
		if err := r.ReleasePhoneNumber(ctx, a, 500); err != nil {
			t.Fatalf("release with nothing held: %v", err)
		}
		// Deleting the holder releases too.
		if err := r.DeleteUser(ctx, b); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		for _, number := range []string{first, second} {
			if prev, err := r.ClaimPhoneNumber(ctx, a, number, 600, 0); err != nil || prev != "" {
				t.Fatalf("claim of the released %s = %q %v", number, prev, err)
			}
		}
	})

	t.Run(driver.Name+"/PhoneClaim_ReleaseClearsANumberThatWasNeverClaimed", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		a := createTestUser(t, r, "unclaimed@example.com")
		if err := r.SetUserPhoneVerified(ctx, a, "+14155550133", 100); err != nil {
			t.Fatalf("SetUserPhoneVerified: %v", err)
		}
		if err := r.ReleasePhoneNumber(ctx, a, 200); err != nil {
			t.Fatalf("release: %v", err)
		}
		if n, ok, at := phoneOf(t, r, a); n != "" || ok || at != 0 {
			t.Fatalf("after release the user holds %q %v %d", n, ok, at)
		}
	})
}
