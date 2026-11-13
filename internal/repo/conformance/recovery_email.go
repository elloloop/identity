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

// runRecoveryEmailConformance pins the recovery-email store: the code's
// upsert/count/consume, the rule that an address is held once in a project,
// as one account's primary email or one account's recovery email, whichever
// write comes first, and that removing an address ends every session it
// opened, even one being opened at the same time.
func runRecoveryEmailConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/RecoveryEmailCode_UpsertCountConsume", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "rec-code@example.com")
		if got, err := r.CountRecoveryEmailCodeAttempt(ctx, uid, 100); err != nil || got != nil {
			t.Fatalf("Count before any code = %#v %v, want nil nil", got, err)
		}
		for _, hash := range []string{"old", "new"} {
			if _, err := r.UpsertRecoveryEmailCode(ctx, &service.RecoveryEmailCodeRecord{
				UserID: uid, Email: "spare@example.net", CodeHash: hash,
				ExpiresAt: 9_000_000_000_000, CreatedAt: 100, MaxAttempts: 5,
			}); err != nil {
				t.Fatalf("Upsert %s: %v", hash, err)
			}
		}
		got, err := r.CountRecoveryEmailCodeAttempt(ctx, uid, 150)
		if err != nil || got == nil || got.CodeHash != "new" || got.Email != "spare@example.net" || got.MaxAttempts != 5 ||
			got.AttemptCount != 1 || got.NodeID == "" {
			t.Fatalf("Count after two upserts = %#v %v, want the new code with one attempt", got, err)
		}
		rec, err := r.ConsumeRecoveryEmailCode(ctx, uid, 200)
		if err != nil || rec == nil || rec.ConsumedAt != 200 {
			t.Fatalf("first Consume = %#v %v", rec, err)
		}
		if _, err := r.ConsumeRecoveryEmailCode(ctx, uid, 300); !errors.Is(err, service.ErrRecoveryEmailCodeInvalid) {
			t.Fatalf("replay Consume: want ErrRecoveryEmailCodeInvalid, got %v", err)
		}
		if got, err := r.CountRecoveryEmailCodeAttempt(ctx, uid, 300); err != nil || got != nil {
			t.Fatalf("Count of a consumed code = %#v %v, want nil nil", got, err)
		}
	})

	t.Run(driver.Name+"/RecoveryEmailCode_CountStopsAtTheCapAndAtExpiry", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "rec-cap@example.com")
		if _, err := r.UpsertRecoveryEmailCode(ctx, &service.RecoveryEmailCodeRecord{
			UserID: uid, Email: "spare@example.net", CodeHash: "h", ExpiresAt: 1_000, CreatedAt: 100, MaxAttempts: 2,
		}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		if got, err := r.CountRecoveryEmailCodeAttempt(ctx, uid, 1_000); err != nil || got != nil {
			t.Fatalf("Count at expiry = %#v %v, want nil nil", got, err)
		}
		for want := int64(1); want <= 2; want++ {
			got, err := r.CountRecoveryEmailCodeAttempt(ctx, uid, 500)
			if err != nil || got == nil || got.AttemptCount != want {
				t.Fatalf("Count %d = %#v %v", want, got, err)
			}
		}
		if got, err := r.CountRecoveryEmailCodeAttempt(ctx, uid, 500); err != nil || got != nil {
			t.Fatalf("Count past the cap = %#v %v, want nil nil", got, err)
		}
	})

	t.Run(driver.Name+"/RecoveryEmailCode_ConcurrentGuessesStopAtTheCap", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "rec-race@example.com")
		const maxAttempts = 3
		if _, err := r.UpsertRecoveryEmailCode(ctx, &service.RecoveryEmailCodeRecord{
			UserID: uid, Email: "spare@example.net", CodeHash: "h", ExpiresAt: 9_000_000_000_000, CreatedAt: 100, MaxAttempts: maxAttempts,
		}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		counted, err := countConcurrently(func() (bool, error) {
			got, err := r.CountRecoveryEmailCodeAttempt(ctx, uid, 200)
			return got != nil, err
		})
		if err != nil {
			t.Fatalf("concurrent Count: %v", err)
		}
		if counted != maxAttempts {
			t.Fatalf("%d of %d concurrent guesses were counted, want the cap of %d", counted, concurrentWriters, maxAttempts)
		}
	})

	t.Run(driver.Name+"/RecoveryEmailCode_ExpiredIsNotConsumedAndIsSwept", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "rec-expired@example.com")
		if _, err := r.UpsertRecoveryEmailCode(ctx, &service.RecoveryEmailCodeRecord{
			UserID: uid, Email: "spare@example.net", CodeHash: "h", ExpiresAt: 150, CreatedAt: 100,
		}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		if _, err := r.ConsumeRecoveryEmailCode(ctx, uid, 150); !errors.Is(err, service.ErrRecoveryEmailCodeInvalid) {
			t.Fatalf("Consume at expiry: want ErrRecoveryEmailCodeInvalid, got %v", err)
		}
		if err := r.DeleteExpiredRecoveryEmailCodes(ctx, 151, 10); err != nil {
			t.Fatalf("DeleteExpired: %v", err)
		}
		if got, err := r.CountRecoveryEmailCodeAttempt(ctx, uid, 100); err != nil || got != nil {
			t.Fatalf("Count after sweep = %#v %v, want nil nil", got, err)
		}
		if err := r.DeleteExpiredRecoveryEmailCodes(ctx, 151, 0); err == nil {
			t.Fatal("DeleteExpired with limit 0: want an error")
		}
	})

	t.Run(driver.Name+"/RecoveryEmail_AddListRemove", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "rec-owner@example.com")
		if list, err := r.ListRecoveryEmails(ctx, uid); err != nil || len(list) != 0 {
			t.Fatalf("List before any = %v %v", list, err)
		}
		for i, addr := range []string{"first@example.net", "second@example.net"} {
			if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: uid, Email: addr, VerifiedAt: int64(100 + i)}, 2); err != nil {
				t.Fatalf("Add %s: %v", addr, err)
			}
		}
		list, err := r.ListRecoveryEmails(ctx, uid)
		if err != nil || len(list) != 2 || list[0].Email != "first@example.net" || list[1].Email != "second@example.net" ||
			list[0].VerifiedAt != 100 || list[0].UserID != uid {
			t.Fatalf("List = %#v %v, want first then second", list, err)
		}
		// The same address again changes nothing, whatever its case, and is
		// not counted against the cap.
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: uid, Email: "FIRST@example.net", VerifiedAt: 999}, 2); err != nil {
			t.Fatalf("re-Add held address: %v", err)
		}
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: uid, Email: "third@example.net", VerifiedAt: 300}, 2); !errors.Is(err, service.ErrRecoveryEmailLimit) {
			t.Fatalf("Add past the cap: want ErrRecoveryEmailLimit, got %v", err)
		}
		if ended, err := r.RemoveRecoveryEmail(ctx, uid, "First@example.net", 400); err != nil || ended != 0 {
			t.Fatalf("Remove = %d %v, want 0 nil", ended, err)
		}
		if _, err := r.RemoveRecoveryEmail(ctx, uid, "first@example.net", 500); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("Remove again: want ErrNotFound, got %v", err)
		}
		if list, _ = r.ListRecoveryEmails(ctx, uid); len(list) != 1 || list[0].Email != "second@example.net" || list[0].VerifiedAt != 101 {
			t.Fatalf("List after remove = %#v", list)
		}
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: "no-such-user", Email: "x@example.net", VerifiedAt: 1}, 2); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("Add for a missing user: want ErrNotFound, got %v", err)
		}
	})

	t.Run(driver.Name+"/RecoveryEmail_OneAccountPerAddress", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		a := createTestUser(t, r, "rec-a@example.com")
		b := createTestUser(t, r, "rec-b@example.com")
		// Another account's primary email, and the account's own.
		for _, addr := range []string{"REC-B@example.com", "rec-a@example.com"} {
			if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: a, Email: addr, VerifiedAt: 1}, 5); !errors.Is(err, service.ErrRecoveryEmailTaken) {
				t.Fatalf("Add primary %s: want ErrRecoveryEmailTaken, got %v", addr, err)
			}
		}
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: a, Email: "shared@example.net", VerifiedAt: 1}, 5); err != nil {
			t.Fatalf("Add: %v", err)
		}
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: b, Email: "Shared@example.net", VerifiedAt: 2}, 5); !errors.Is(err, service.ErrRecoveryEmailTaken) {
			t.Fatalf("Add another account's recovery email: want ErrRecoveryEmailTaken, got %v", err)
		}
		if list, _ := r.ListRecoveryEmails(ctx, b); len(list) != 0 {
			t.Fatalf("the refused account holds %#v", list)
		}

		// No account may take a recovery email as its primary email.
		if _, err := r.CreateUser(ctx, &service.User{Email: "SHARED@example.net", Status: "active"}); !errors.Is(err, service.ErrAlreadyExists) {
			t.Fatalf("CreateUser on a recovery email: want ErrAlreadyExists, got %v", err)
		}
		if err := r.UpdateUser(ctx, b, map[string]any{"email": "shared@example.net"}); !errors.Is(err, service.ErrAlreadyExists) {
			t.Fatalf("UpdateUser onto a recovery email: want ErrAlreadyExists, got %v", err)
		}
		if err := r.UpdateUserEmail(ctx, a, "shared@example.net", 5); !errors.Is(err, service.ErrAlreadyExists) {
			t.Fatalf("UpdateUserEmail onto the account's own recovery email: want ErrAlreadyExists, got %v", err)
		}
		if got, _ := r.GetUser(ctx, b); got == nil || got.Email != "rec-b@example.com" {
			t.Fatalf("a refused update changed the user: %#v", got)
		}

		// Released, the address is free again.
		if _, err := r.RemoveRecoveryEmail(ctx, a, "shared@example.net", 3); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if err := r.UpdateUserEmail(ctx, b, "shared@example.net", 6); err != nil {
			t.Fatalf("UpdateUserEmail onto a released address: %v", err)
		}
	})

	t.Run(driver.Name+"/RecoveryEmail_DeletedWithTheUser", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "rec-gone@example.com")
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: uid, Email: "freed@example.net", VerifiedAt: 1}, 5); err != nil {
			t.Fatalf("Add: %v", err)
		}
		if _, err := r.UpsertRecoveryEmailCode(ctx, &service.RecoveryEmailCodeRecord{
			UserID: uid, Email: "other@example.net", CodeHash: "h", ExpiresAt: 9_000_000_000_000, CreatedAt: 1,
		}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		if err := r.DeleteUser(ctx, uid); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		if list, err := r.ListRecoveryEmails(ctx, uid); err != nil || len(list) != 0 {
			t.Fatalf("List after delete = %#v %v", list, err)
		}
		if got, err := r.CountRecoveryEmailCodeAttempt(ctx, uid, 2); err != nil || got != nil {
			t.Fatalf("code after delete = %#v %v", got, err)
		}
		if _, err := r.CreateUser(ctx, &service.User{Email: "freed@example.net", Status: "active"}); err != nil {
			t.Fatalf("CreateUser on the freed address: %v", err)
		}
	})

	t.Run(driver.Name+"/RecoveryEmail_HolderAndSignInStamp", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "rec-holder@example.com")
		other := createTestUser(t, r, "rec-nonholder@example.com")
		if got, err := r.FindRecoveryEmailHolder(ctx, "spare@example.net"); err != nil || got != nil {
			t.Fatalf("holder of an address nobody holds = %#v %v, want nil nil", got, err)
		}
		// A primary email is not a recovery email.
		if got, err := r.FindRecoveryEmailHolder(ctx, "rec-holder@example.com"); err != nil || got != nil {
			t.Fatalf("holder of a primary email = %#v %v, want nil nil", got, err)
		}
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: uid, Email: "spare@example.net", VerifiedAt: 10}, 5); err != nil {
			t.Fatalf("Add: %v", err)
		}
		got, err := r.FindRecoveryEmailHolder(ctx, "SPARE@example.net")
		if err != nil || got == nil || got.UserID != uid || got.Email != "spare@example.net" || got.VerifiedAt != 10 || got.LastSignInAt != 0 {
			t.Fatalf("holder = %#v %v", got, err)
		}
		const hold = 1_000
		if err := r.MarkRecoveryEmailSignIn(ctx, uid, "Spare@example.net", 5_000, hold); err != nil {
			t.Fatalf("Mark: %v", err)
		}
		if err := r.MarkRecoveryEmailSignIn(ctx, other, "spare@example.net", 5_100, hold); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("Mark by an account that does not hold the address: want ErrNotFound, got %v", err)
		}
		list, err := r.ListRecoveryEmails(ctx, uid)
		if err != nil || len(list) != 1 || list[0].LastSignInAt != 5_000 {
			t.Fatalf("List after Mark = %#v %v, want LastSignInAt 5000", list, err)
		}
		// A sign-in within the hold its address started does not extend it;
		// one once it has ended starts a new one.
		for _, step := range []struct{ at, want int64 }{{5_999, 5_000}, {6_000, 6_000}} {
			if err := r.MarkRecoveryEmailSignIn(ctx, uid, "spare@example.net", step.at, hold); err != nil {
				t.Fatalf("Mark at %d: %v", step.at, err)
			}
			if got, _ := r.FindRecoveryEmailHolder(ctx, "spare@example.net"); got == nil || got.LastSignInAt != step.want {
				t.Fatalf("holder after Mark at %d = %#v, want LastSignInAt %d", step.at, got, step.want)
			}
		}
	})

	t.Run(driver.Name+"/RecoverySession_RefreshTokenAndChallengeKeepTheRecoveryEmail", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "rec-session@example.com")
		other := createTestUser(t, r, "rec-session-other@example.com")
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: uid, Email: "spare@example.net", VerifiedAt: 1}, 5); err != nil {
			t.Fatalf("Add: %v", err)
		}
		for hash, addr := range map[string]string{"rec-rt-recovery": "Spare@example.net", "rec-rt-plain": ""} {
			if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
				TokenHash: hash, UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 1, LastUsedAt: 1, RecoveryEmail: addr,
			}); err != nil {
				t.Fatalf("CreateRefreshToken %s: %v", hash, err)
			}
			got, err := r.FindRefreshTokenByHash(ctx, hash)
			if err != nil || got == nil || got.RecoveryEmail != addr {
				t.Fatalf("refresh token %s = %#v %v, want RecoveryEmail %q", hash, got, err, addr)
			}
		}
		// A recovery session's token is stored only for an address its account
		// holds: not one nobody holds, nor another account's.
		for hash, owner := range map[string]struct{ user, addr string }{
			"rec-rt-unheld": {uid, "nobody@example.net"},
			"rec-rt-others": {other, "spare@example.net"},
		} {
			if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
				TokenHash: hash, UserID: owner.user, ExpiresAt: 9_000_000_000_000, CreatedAt: 1, LastUsedAt: 1, RecoveryEmail: owner.addr,
			}); !errors.Is(err, service.ErrNotFound) {
				t.Fatalf("CreateRefreshToken %s: want ErrNotFound, got %v", hash, err)
			}
			if got, err := r.FindRefreshTokenByHashIncludingConsumed(ctx, hash); err != nil || got != nil {
				t.Fatalf("refused refresh token %s was stored: %#v %v", hash, got, err)
			}
		}
		for id, addr := range map[string]string{"rec-lc-recovery": "spare@example.net", "rec-lc-plain": ""} {
			if _, err := r.CreateLoginChallenge(ctx, &service.LoginChallengeRecord{
				ChallengeID: id, UserID: uid, RecoveryEmail: addr, ExpiresAt: 9_000_000_000_000, CreatedAt: 1,
			}); err != nil {
				t.Fatalf("CreateLoginChallenge %s: %v", id, err)
			}
			got, err := r.GetLoginChallengeByChallengeID(ctx, id)
			if err != nil || got == nil || got.RecoveryEmail != addr {
				t.Fatalf("login challenge %s = %#v %v, want RecoveryEmail %q", id, got, err, addr)
			}
		}
	})

	t.Run(driver.Name+"/RecoveryEmail_RemoveEndsTheSessionsItOpened", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "rec-ends@example.com")
		other := createTestUser(t, r, "rec-ends-other@example.com")
		for _, a := range []struct{ user, addr string }{
			{uid, "stolen@example.net"}, {uid, "kept@example.net"}, {other, "theirs@example.net"},
		} {
			if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: a.user, Email: a.addr, VerifiedAt: 1}, 5); err != nil {
				t.Fatalf("Add %s: %v", a.addr, err)
			}
		}
		// The stolen address's sign-in, rotated once; a session the account's
		// other recovery email opened; one opened another way; and another
		// account's recovery session.
		tokens := []struct {
			hash, user, addr string
			consumed         int64
		}{
			{"rec-ends-rotated", uid, "stolen@example.net", 50},
			{"rec-ends-live", uid, "STOLEN@example.net", 0},
			{"rec-ends-kept", uid, "kept@example.net", 0},
			{"rec-ends-plain", uid, "", 0},
			{"rec-ends-other", other, "theirs@example.net", 0},
		}
		for _, tok := range tokens {
			sid := "sid-" + tok.hash
			if _, err := r.CreateSession(ctx, &service.SessionRecord{SID: sid, UserID: tok.user, CreatedAtMs: 10}); err != nil {
				t.Fatalf("CreateSession %s: %v", sid, err)
			}
			if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
				TokenHash: tok.hash, UserID: tok.user, ExpiresAt: 9_000_000_000_000, CreatedAt: 10, LastUsedAt: 10,
				SID: sid, RecoveryEmail: tok.addr,
			}); err != nil {
				t.Fatalf("CreateRefreshToken %s: %v", tok.hash, err)
			}
			if tok.consumed != 0 {
				if err := r.ConsumeRefreshTokenByHash(ctx, tok.hash, tok.consumed); err != nil {
					t.Fatalf("Consume %s: %v", tok.hash, err)
				}
			}
		}

		const at = 1_000
		ended, err := r.RemoveRecoveryEmail(ctx, uid, "Stolen@example.net", at)
		if err != nil || ended != 1 {
			t.Fatalf("Remove = %d %v, want the one unrotated session ended", ended, err)
		}
		for _, tok := range tokens {
			gone := tok.user == uid && tok.addr != "" && service.FoldEmail(tok.addr) == "stolen@example.net"
			got, err := r.FindRefreshTokenByHashIncludingConsumed(ctx, tok.hash)
			if err != nil || (got == nil) != gone {
				t.Fatalf("refresh token %s after the removal = %#v %v, want gone=%t", tok.hash, got, err, gone)
			}
			session, err := r.GetSessionBySid(ctx, "sid-"+tok.hash)
			want := int64(0)
			if gone {
				want = at
			}
			if err != nil || session == nil || session.RevokedAtMs != want {
				t.Fatalf("session of %s after the removal = %#v %v, want RevokedAtMs %d", tok.hash, session, err, want)
			}
		}
		if list, _ := r.ListRecoveryEmails(ctx, uid); len(list) != 1 || list[0].Email != "kept@example.net" {
			t.Fatalf("List after remove = %#v, want only the kept address", list)
		}
		// The address is gone, so no session can be opened for it either.
		after := tokens[1].hash + "-after"
		if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
			TokenHash: after, UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 1, LastUsedAt: 1, RecoveryEmail: "stolen@example.net",
		}); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("CreateRefreshToken for the removed address: want ErrNotFound, got %v", err)
		}
		// Another account's address of the same spelling is not this account's.
		if _, err := r.RemoveRecoveryEmail(ctx, uid, "theirs@example.net", at); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("Remove another account's address: want ErrNotFound, got %v", err)
		}
	})

	t.Run(driver.Name+"/RecoveryEmail_RemoveRacingRecoverySessionsLeavesNone", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "rec-race-remove@example.com")
		if err := r.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: uid, Email: "stolen@example.net", VerifiedAt: 1}, 5); err != nil {
			t.Fatalf("Add: %v", err)
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make(chan error, concurrentWriters+1)
		var stored atomic.Int64
		for i := range concurrentWriters {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
					TokenHash: fmt.Sprintf("rec-race-%d", i), UserID: uid,
					ExpiresAt: 9_000_000_000_000, CreatedAt: 1, LastUsedAt: 1, RecoveryEmail: "stolen@example.net",
				})
				switch {
				case err == nil:
					stored.Add(1)
				case !errors.Is(err, service.ErrNotFound):
					errs <- err
				}
			}()
		}
		var ended int
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			var err error
			if ended, err = r.RemoveRecoveryEmail(ctx, uid, "stolen@example.net", 100); err != nil {
				errs <- err
			}
		}()
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("concurrent create/remove: %v", err)
		}
		if int64(ended) != stored.Load() {
			t.Fatalf("the removal ended %d sessions, but %d were stored", ended, stored.Load())
		}
		for i := range concurrentWriters {
			if got, err := r.FindRefreshTokenByHashIncludingConsumed(ctx, fmt.Sprintf("rec-race-%d", i)); err != nil || got != nil {
				t.Fatalf("a recovery session survived the removal of its address: %#v %v", got, err)
			}
		}
	})
}
