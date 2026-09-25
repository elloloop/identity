package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runEmailFoldConformance pins the one rule under which every driver matches
// and de-duplicates account emails: service.FoldEmail, exact up to ASCII
// case. The Postgres default lower() folds by the database's locale, so
// without a pinned rule the same addresses matched on one deployment and not
// on another, and the service could not pair the rows a lookup returned with
// the addresses that asked for them. The non-ASCII cases are the ones a
// locale-dependent or Unicode fold gets wrong.
func runEmailFoldConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/EmailFold", func(t *testing.T) {
		t.Run("Lookups_IgnoreASCIICaseOnly", func(t *testing.T) {
			r := driver.NewRepo(t)
			kate := createTestUser(t, r, "kate@example.com")
			emile := createTestUser(t, r, "Émile@Example.com")

			for addr, want := range map[string]string{
				"kate@example.com":        kate,
				"KATE@EXAMPLE.COM":        kate,
				"Émile@example.com":       emile,
				"ÉMILE@EXAMPLE.COM":       emile,
				"\u212aate@example.com":   "", // KELVIN SIGN, which Unicode lowers to "k"
				"émile@example.com":       "", // differs from the stored address in non-ASCII case
				"E\u0301mile@example.com": "", // the decomposed spelling: no normalization either
			} {
				assertEmailLookups(t, r, addr, want)
			}
		})

		t.Run("Uniqueness_FollowsTheSameRule", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			upper := createTestUser(t, r, "Émile@example.com")
			if _, err := r.CreateUser(ctx, &service.User{Email: "ÉMILE@EXAMPLE.COM", Status: "active"}); !errors.Is(err, service.ErrAlreadyExists) {
				t.Fatalf("CreateUser differing only in ASCII case: err = %v, want ErrAlreadyExists", err)
			}
			// Differing in non-ASCII case, or by a KELVIN SIGN, is a different
			// address, so it is a separate account that lookups tell apart.
			lower := createTestUser(t, r, "émile@example.com")
			kate := createTestUser(t, r, "kate@example.com")
			kelvin := createTestUser(t, r, "\u212aate@example.com")
			assertEmailLookups(t, r, "Émile@example.com", upper)
			assertEmailLookups(t, r, "émile@example.com", lower)
			assertEmailLookups(t, r, "KATE@example.com", kate)
			assertEmailLookups(t, r, "\u212aATE@example.com", kelvin)

			if err := r.UpdateUserEmail(ctx, lower, "émile@EXAMPLE.com", 1_700_000_000_000); err != nil {
				t.Fatalf("UpdateUserEmail to its own address in another ASCII case: %v", err)
			}
			if err := r.UpdateUserEmail(ctx, lower, "KATE@example.com", 1_700_000_000_000); !errors.Is(err, service.ErrAlreadyExists) {
				t.Fatalf("UpdateUserEmail onto another account's address: err = %v, want ErrAlreadyExists", err)
			}
		})
	})
}

// assertEmailLookups checks that every account-email lookup resolves addr to
// the account wantID, or to nothing when wantID is empty.
func assertEmailLookups(t *testing.T, r service.Repository, addr, wantID string) {
	t.Helper()
	ctx := context.Background()
	wantN := 0
	if wantID != "" {
		wantN = 1
	}

	got, err := r.FindUserByEmail(ctx, addr)
	if err != nil {
		t.Fatalf("FindUserByEmail(%q): %v", addr, err)
	}
	if gotID := idOf(got); gotID != wantID {
		t.Fatalf("FindUserByEmail(%q) = %q, want %q", addr, gotID, wantID)
	}

	batch, err := r.FindUsersByEmails(ctx, []string{addr})
	if err != nil {
		t.Fatalf("FindUsersByEmails(%q): %v", addr, err)
	}
	if len(batch) != wantN || (wantN == 1 && batch[0].ID != wantID) {
		t.Fatalf("FindUsersByEmails(%q) = %d accounts, want %d (%q)", addr, len(batch), wantN, wantID)
	}

	listed, err := r.ListUsers(ctx, service.UserListFilter{Email: addr})
	if err != nil {
		t.Fatalf("ListUsers(Email=%q): %v", addr, err)
	}
	if len(listed) != wantN || (wantN == 1 && listed[0].ID != wantID) {
		t.Fatalf("ListUsers(Email=%q) = %d accounts, want %d (%q)", addr, len(listed), wantN, wantID)
	}

	n, err := r.CountUsers(ctx, service.UserListFilter{Email: addr})
	if err != nil {
		t.Fatalf("CountUsers(Email=%q): %v", addr, err)
	}
	if n != wantN {
		t.Fatalf("CountUsers(Email=%q) = %d, want %d", addr, n, wantN)
	}
}

func idOf(u *service.User) string {
	if u == nil {
		return ""
	}
	return u.ID
}
