package conformance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// concurrentWriters is the goroutine fan-out for the concurrency
// suite. Read-after-write index lag on entdb is load-dependent — the
// single-threaded read-your-writes suite passes on an idle backend, but
// the IDV flake only bit under the nightly's parallel load. A fan-out
// of writers reproduces that pressure so the lag (and any lost-write or
// data-race bug) surfaces deterministically rather than only in CI.
const concurrentWriters = 64

// runConcurrencyConformance stresses the Repository under concurrent
// writers: no write may be lost, and a write must still be visible to
// the issuing goroutine's immediate read even while other writers load
// the same backend.
func runConcurrencyConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/Concurrency", func(t *testing.T) {
		// Durability: N goroutines each create a distinct refresh token
		// concurrently; after a barrier, every token must be readable.
		// A backend that drops a write under contention fails here.
		t.Run("ConcurrentCreate_NoLostWrites", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "conc-nolost@example.com")

			var wg sync.WaitGroup
			start := make(chan struct{})
			errs := make(chan error, concurrentWriters)
			for i := 0; i < concurrentWriters; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
						TokenHash: fmt.Sprintf("conc-rt-%d", i), UserID: uid,
						ExpiresAt: 9_000_000_000_000, CreatedAt: 100, LastUsedAt: 100,
					}); err != nil {
						errs <- fmt.Errorf("create %d: %w", i, err)
					}
				}(i)
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatalf("concurrent create: %v", err)
			}

			missing := 0
			for i := 0; i < concurrentWriters; i++ {
				got, err := r.FindRefreshTokenByHash(ctx, fmt.Sprintf("conc-rt-%d", i))
				if err != nil {
					t.Fatalf("Find %d: %v", i, err)
				}
				if got == nil {
					missing++
				}
			}
			if missing != 0 {
				t.Fatalf("lost %d of %d concurrently-created tokens", missing, concurrentWriters)
			}
		})

		// Read-your-writes under load: N goroutines each create a fresh
		// user + OAuth link, then immediately resolve it through the
		// user_id/provider filter index. This is the IDV-class race
		// (secondary-index apply lag) under the concurrent pressure that
		// actually triggers it.
		t.Run("ConcurrentReadYourWrites_OAuthFilter", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			// Warm the tenant so the filter queries below don't race the
			// first-write "tenant open" on entdb (a separate concern,
			// covered by the FreshTenant suite).
			createTestUser(t, r, "conc-warm@example.com")

			var wg sync.WaitGroup
			start := make(chan struct{})
			var misses int64
			errs := make(chan error, concurrentWriters)
			for i := 0; i < concurrentWriters; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					uid, err := r.CreateUser(ctx, &service.User{
						Email: fmt.Sprintf("conc-oa-%d@example.com", i), Status: "active", Role: "member",
					})
					if err != nil {
						errs <- fmt.Errorf("CreateUser %d: %w", i, err)
						return
					}
					sub := fmt.Sprintf("conc-sub-%d", i)
					if err := r.CreateOAuthIdentity(ctx, &service.OAuthIdentity{
						UserID: uid, Provider: "google", ProviderUserID: sub, CreatedAt: 100,
					}); err != nil {
						errs <- fmt.Errorf("CreateOAuthIdentity %d: %w", i, err)
						return
					}
					got, err := r.FindUserByProviderID(ctx, "google", sub)
					if err != nil {
						errs <- fmt.Errorf("FindUserByProviderID %d: %w", i, err)
						return
					}
					if got == nil {
						atomic.AddInt64(&misses, 1)
					}
				}(i)
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatalf("concurrent read-your-writes: %v", err)
			}
			if n := atomic.LoadInt64(&misses); n != 0 {
				t.Fatalf("read-after-write miss under load: %d of %d OAuth links not visible to their own immediate read", n, concurrentWriters)
			}
		})

		// Composite uniqueness under contention: entdb has no composite
		// unique constraint, so CreateOAuthIdentity enforces (provider,
		// provider_user_id) uniqueness with a non-atomic query-then-
		// create. N goroutines racing the same (provider, sub) must still
		// yield exactly one link — more than one is a uniqueness breach
		// (two accounts could claim the same external identity). Memory
		// (locked) and postgres (unique index) serialize this; a
		// query-then-create guard without a serialization point does not.
		t.Run("ConcurrentDuplicate_OAuthIdentity_SingleRow", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "conc-dup-oa@example.com")

			var wg sync.WaitGroup
			start := make(chan struct{})
			var winners int64
			for i := 0; i < concurrentWriters; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if err := r.CreateOAuthIdentity(ctx, &service.OAuthIdentity{
						UserID: uid, Provider: "google", ProviderUserID: "dup-sub", CreatedAt: 100,
					}); err == nil {
						atomic.AddInt64(&winners, 1)
					}
				}()
			}
			close(start)
			wg.Wait()

			list, err := r.ListOAuthIdentitiesForUser(ctx, uid)
			if err != nil {
				t.Fatalf("ListOAuthIdentitiesForUser: %v", err)
			}
			if len(list) != 1 {
				t.Fatalf("composite uniqueness breach: %d (google,dup-sub) links exist after concurrent create (winners reported=%d), want 1", len(list), atomic.LoadInt64(&winners))
			}
		})

		// Single-field unique key under contention: email is a real
		// unique key, so the server should serialize concurrent inserts
		// to one winner regardless of backend.
		t.Run("ConcurrentDuplicate_User_SingleWinner", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			createTestUser(t, r, "conc-dup-warm@example.com") // open tenant

			var wg sync.WaitGroup
			start := make(chan struct{})
			var winners int64
			for i := 0; i < concurrentWriters; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if _, err := r.CreateUser(ctx, &service.User{
						Email: "dup-user@example.com", Status: "active", Role: "member",
					}); err == nil {
						atomic.AddInt64(&winners, 1)
					}
				}()
			}
			close(start)
			wg.Wait()

			if n := atomic.LoadInt64(&winners); n != 1 {
				t.Fatalf("duplicate email accepted: %d concurrent CreateUser calls succeeded for the same email, want exactly 1", n)
			}
		})

		// Atomic counter: N concurrent IncrementFailedLoginCount calls on
		// one user must land all N increments. A read-modify-write
		// implementation loses updates under contention, which lets an
		// attacker's parallel failed logins undercount and slip past the
		// lockout threshold — a security-relevant correctness bug.
		t.Run("ConcurrentIncrement_NoLostUpdates", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "conc-incr@example.com")

			var wg sync.WaitGroup
			start := make(chan struct{})
			errs := make(chan error, concurrentWriters)
			for i := 0; i < concurrentWriters; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if _, err := r.IncrementFailedLoginCount(ctx, uid); err != nil {
						errs <- err
					}
				}()
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatalf("IncrementFailedLoginCount: %v", err)
			}

			got, err := r.GetUser(ctx, uid)
			if err != nil || got == nil {
				t.Fatalf("GetUser: %v %#v", err, got)
			}
			if got.FailedLoginCount != concurrentWriters {
				t.Fatalf("lost updates: failed_login_count = %d after %d concurrent increments, want %d", got.FailedLoginCount, concurrentWriters, concurrentWriters)
			}
		})

		// Disjoint-field updates: two goroutines patching DIFFERENT fields
		// of the same user must both land. A read-modify-write that
		// rewrites the whole node loses one field (last writer wins with a
		// stale read of the other field); a true field-level patch keeps
		// both. Looped to expose the race.
		t.Run("ConcurrentUpdate_DifferentFields_NoLostUpdate", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			const iters = 30
			for k := 0; k < iters; k++ {
				id, err := r.CreateUser(ctx, &service.User{
					Email: fmt.Sprintf("conc-fields-%d@example.com", k), Status: "active", Role: "member",
				})
				if err != nil {
					t.Fatalf("CreateUser %d: %v", k, err)
				}
				var wg sync.WaitGroup
				start := make(chan struct{})
				errs := make(chan error, 2)
				wg.Add(2)
				go func() {
					defer wg.Done()
					<-start
					if err := r.UpdateUser(ctx, id, map[string]any{"name": "FINAL_NAME"}); err != nil {
						errs <- err
					}
				}()
				go func() {
					defer wg.Done()
					<-start
					if err := r.UpdateUser(ctx, id, map[string]any{"avatar_url": "FINAL_AVATAR"}); err != nil {
						errs <- err
					}
				}()
				close(start)
				wg.Wait()
				close(errs)
				for err := range errs {
					t.Fatalf("iter %d: UpdateUser: %v", k, err)
				}
				got, err := r.GetUser(ctx, id)
				if err != nil || got == nil {
					t.Fatalf("iter %d: GetUser: %v %#v", k, err, got)
				}
				if got.Name != "FINAL_NAME" || got.AvatarURL != "FINAL_AVATAR" {
					t.Fatalf("iter %d: lost update on disjoint fields: name=%q avatar=%q, want both set (read-modify-write whole-node overwrite?)", k, got.Name, got.AvatarURL)
				}
			}
		})

		// Two mutation paths racing the same row: consume (CAS) vs delete.
		// At most one consumer may win, no goroutine may see an
		// unexpected error, and the token must end up not-live (either
		// consumed or deleted) — never a corrupted half-state.
		t.Run("ConcurrentConsumeVsDelete_RefreshToken", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "conc-cvd@example.com")
			id, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
				TokenHash: "race-cvd", UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 100, LastUsedAt: 100,
			})
			if err != nil {
				t.Fatalf("CreateRefreshToken: %v", err)
			}

			const half = 16
			var wg sync.WaitGroup
			start := make(chan struct{})
			var consumeWins int64
			errs := make(chan error, 2*half)
			for i := 0; i < half; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					switch err := r.ConsumeRefreshTokenByHash(ctx, "race-cvd", 200); {
					case err == nil:
						atomic.AddInt64(&consumeWins, 1)
					case errors.Is(err, service.ErrUnauthenticated):
						// lost the race or already gone — fine
					default:
						errs <- fmt.Errorf("consume unexpected: %w", err)
					}
				}()
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if err := r.DeleteRefreshToken(ctx, id); err != nil {
						errs <- fmt.Errorf("delete unexpected: %w", err)
					}
				}()
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatalf("%v", err)
			}
			if n := atomic.LoadInt64(&consumeWins); n > 1 {
				t.Fatalf("double-consume: %d consumers won, want <=1", n)
			}
			// Token must be gone from the live view regardless of who won.
			if got, _ := r.FindRefreshTokenByHash(ctx, "race-cvd"); got != nil {
				t.Fatalf("token still live after concurrent consume+delete: %#v", got)
			}
		})

		// The GC sweeper runs continuously in production while the app
		// inserts fresh rows. A sweep (delete expires_at < cutoff) racing
		// inserts of UNEXPIRED rows must never delete an unexpired row — a
		// query-then-delete TOCTOU or a too-wide cutoff would drop live
		// data.
		t.Run("SweeperVsConcurrentInserts", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "sweep-race@example.com")
			// Seed expired rows so the sweeper actually does work.
			for i := 0; i < 50; i++ {
				if err := r.CreatePasswordResetToken(ctx, &service.PasswordResetToken{
					TokenHash: fmt.Sprintf("sweep-exp-%d", i), UserID: uid, ExpiresAt: 1_000, CreatedAt: 100,
				}); err != nil {
					t.Fatalf("seed expired %d: %v", i, err)
				}
			}

			stop := make(chan struct{})
			var swg sync.WaitGroup
			swErr := make(chan error, 1)
			swg.Add(1)
			go func() {
				defer swg.Done()
				for {
					select {
					case <-stop:
						return
					default:
						if err := r.DeleteExpiredPasswordResetTokens(ctx, 5_000, 100); err != nil {
							select {
							case swErr <- err:
							default:
							}
							return
						}
					}
				}
			}()

			const kept = 50
			hashes := make([]string, kept)
			for i := 0; i < kept; i++ {
				h := fmt.Sprintf("sweep-keep-%d", i)
				hashes[i] = h
				if err := r.CreatePasswordResetToken(ctx, &service.PasswordResetToken{
					TokenHash: h, UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 6_000,
				}); err != nil {
					t.Fatalf("insert unexpired %d: %v", i, err)
				}
			}
			close(stop)
			swg.Wait()
			select {
			case err := <-swErr:
				t.Fatalf("sweeper errored under concurrent inserts: %v", err)
			default:
			}

			gone := 0
			for _, h := range hashes {
				got, err := r.FindPasswordResetTokenByHash(ctx, h)
				if err != nil {
					t.Fatalf("find %s: %v", h, err)
				}
				if got == nil {
					gone++
				}
			}
			if gone != 0 {
				t.Fatalf("concurrent sweep deleted %d of %d UNEXPIRED tokens (cutoff/TOCTOU race)", gone, kept)
			}
		})
	})
}
