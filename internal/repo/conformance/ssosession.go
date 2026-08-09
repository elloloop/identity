package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runSSOSessionConformance pins the browser SSO-session store (ADR-0014) to
// identical semantics on every driver. The behaviours here are the ones the
// fast path and "sign out everywhere" depend on being exactly the same
// whichever backend a deployment runs:
//
//   - a cookie hash maps to at most one session, and a duplicate is rejected
//     rather than silently shadowing;
//   - a lookup returns expired and revoked rows (the caller, not the store,
//     decides what an inactive session means);
//   - touching rolls the expiry forward but never resurrects a revoked row —
//     the race a concurrent sign-out-everywhere must win;
//   - revocation is idempotent and preserves the first timestamp;
//   - deleting a user takes their SSO sessions with them.
func runSSOSessionConformance(t *testing.T, driver Driver) {
	t.Run("SSOSession_CRUD", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "sso-crud@example.com")

		if _, err := r.CreateSSOSession(ctx, &service.SSOSessionRecord{UserID: uid}); err == nil {
			t.Fatal("CreateSSOSession with empty token_hash: want error, got nil")
		}
		if _, err := r.CreateSSOSession(ctx, &service.SSOSessionRecord{TokenHash: uniqueHash("sso")}); err == nil {
			t.Fatal("CreateSSOSession with empty user_id: want error, got nil")
		}

		hash := uniqueHash("sso")
		rec := &service.SSOSessionRecord{
			TokenHash:    hash,
			UserID:       uid,
			LoginMethod:  "oauth",
			IPAddress:    "203.0.113.7",
			UserAgent:    "Mozilla/5.0",
			CreatedAtMs:  1_700_000_000_000,
			LastUsedAtMs: 1_700_000_000_000,
			ExpiresAtMs:  1_700_000_900_000,
		}
		id, err := r.CreateSSOSession(ctx, rec)
		if err != nil || id == "" {
			t.Fatalf("CreateSSOSession: id=%q err=%v", id, err)
		}

		got, err := r.FindSSOSessionByHash(ctx, hash)
		if err != nil || got == nil {
			t.Fatalf("FindSSOSessionByHash: %v %#v", err, got)
		}
		if got.UserID != uid || got.LoginMethod != "oauth" || got.RevokedAtMs != 0 {
			t.Fatalf("SSO session round-trip mismatch: %+v", got)
		}
		if got.IPAddress != "203.0.113.7" || got.UserAgent != "Mozilla/5.0" {
			t.Fatalf("SSO session device fields lost: %+v", got)
		}
		if got.ExpiresAtMs != 1_700_000_900_000 || got.LastUsedAtMs != 1_700_000_000_000 {
			t.Fatalf("SSO session timestamps lost: %+v", got)
		}

		// One cookie value, one session: a duplicate hash must reject rather
		// than create a second row the lookup would pick between.
		if _, err := r.CreateSSOSession(ctx, &service.SSOSessionRecord{
			TokenHash: hash, UserID: uid, ExpiresAtMs: 1_700_000_900_000,
		}); err == nil {
			t.Fatal("CreateSSOSession duplicate hash: want error, got nil")
		} else if !errors.Is(err, service.ErrAlreadyExists) {
			t.Fatalf("CreateSSOSession duplicate hash: want ErrAlreadyExists, got %v", err)
		}

		miss, err := r.FindSSOSessionByHash(ctx, uniqueHash("nope"))
		if err != nil || miss != nil {
			t.Fatalf("FindSSOSessionByHash unknown: err=%v rec=%#v", err, miss)
		}
		empty, err := r.FindSSOSessionByHash(ctx, "")
		if err != nil || empty != nil {
			t.Fatalf("FindSSOSessionByHash empty: err=%v rec=%#v", err, empty)
		}
	})

	t.Run("SSOSession_FindReturnsExpiredAndRevoked", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "sso-inactive@example.com")

		// The store must not filter on behalf of the caller: the fast path
		// needs one query to tell "no session" from "session ended".
		expiredHash := uniqueHash("sso-expired")
		if _, err := r.CreateSSOSession(ctx, &service.SSOSessionRecord{
			TokenHash: expiredHash, UserID: uid, CreatedAtMs: 100, LastUsedAtMs: 100, ExpiresAtMs: 200,
		}); err != nil {
			t.Fatalf("CreateSSOSession expired: %v", err)
		}
		got, err := r.FindSSOSessionByHash(ctx, expiredHash)
		if err != nil || got == nil {
			t.Fatalf("FindSSOSessionByHash expired: want row, got %#v err=%v", got, err)
		}
		if got.Active(300) {
			t.Fatal("expired session reported Active at a later clock")
		}

		revokedHash := uniqueHash("sso-revoked")
		if _, err := r.CreateSSOSession(ctx, &service.SSOSessionRecord{
			TokenHash: revokedHash, UserID: uid, CreatedAtMs: 100, LastUsedAtMs: 100, ExpiresAtMs: 9_000,
		}); err != nil {
			t.Fatalf("CreateSSOSession revoked: %v", err)
		}
		if err := r.RevokeSSOSession(ctx, revokedHash, 500); err != nil {
			t.Fatalf("RevokeSSOSession: %v", err)
		}
		got, err = r.FindSSOSessionByHash(ctx, revokedHash)
		if err != nil || got == nil {
			t.Fatalf("FindSSOSessionByHash revoked: want row, got %#v err=%v", got, err)
		}
		if got.RevokedAtMs != 500 || got.Active(600) {
			t.Fatalf("revoked session: %+v", got)
		}
	})

	t.Run("SSOSession_TouchRollsExpiryButNotRevoked", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "sso-touch@example.com")

		hash := uniqueHash("sso-touch")
		if _, err := r.CreateSSOSession(ctx, &service.SSOSessionRecord{
			TokenHash: hash, UserID: uid, CreatedAtMs: 100, LastUsedAtMs: 100, ExpiresAtMs: 1_000,
		}); err != nil {
			t.Fatalf("CreateSSOSession: %v", err)
		}

		if err := r.TouchSSOSession(ctx, hash, 500, 5_000); err != nil {
			t.Fatalf("TouchSSOSession: %v", err)
		}
		got, err := r.FindSSOSessionByHash(ctx, hash)
		if err != nil || got == nil {
			t.Fatalf("FindSSOSessionByHash: %v %#v", err, got)
		}
		if got.LastUsedAtMs != 500 || got.ExpiresAtMs != 5_000 {
			t.Fatalf("Touch did not roll the window: %+v", got)
		}

		// A revoked session must stay dead: this is the sign-out-everywhere
		// versus continue-as race, and sign-out has to win it.
		if err := r.RevokeSSOSession(ctx, hash, 600); err != nil {
			t.Fatalf("RevokeSSOSession: %v", err)
		}
		if err := r.TouchSSOSession(ctx, hash, 900, 50_000); err != nil {
			t.Fatalf("TouchSSOSession after revoke: %v", err)
		}
		got, err = r.FindSSOSessionByHash(ctx, hash)
		if err != nil || got == nil {
			t.Fatalf("FindSSOSessionByHash after revoke: %v %#v", err, got)
		}
		if got.RevokedAtMs != 600 {
			t.Fatalf("Touch cleared the revocation: %+v", got)
		}
		if got.ExpiresAtMs != 5_000 || got.LastUsedAtMs != 500 {
			t.Fatalf("Touch mutated a revoked row: %+v", got)
		}

		// Unknown hash and empty hash are successful no-ops.
		if err := r.TouchSSOSession(ctx, uniqueHash("absent"), 1, 2); err != nil {
			t.Fatalf("TouchSSOSession unknown: %v", err)
		}
		if err := r.TouchSSOSession(ctx, "", 1, 2); err != nil {
			t.Fatalf("TouchSSOSession empty: %v", err)
		}
	})

	t.Run("SSOSession_RevokeForUser", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "sso-revoke-all@example.com")
		other := createTestUser(t, r, "sso-revoke-other@example.com")

		if err := r.RevokeSSOSessionsForUser(ctx, "no-such-user", 10); err != nil {
			t.Fatalf("RevokeSSOSessionsForUser unknown: %v", err)
		}
		if err := r.RevokeSSOSessionsForUser(ctx, "", 10); err != nil {
			t.Fatalf("RevokeSSOSessionsForUser empty: %v", err)
		}

		// Two browsers for the same person, one for someone else.
		hashes := []string{uniqueHash("sso-a"), uniqueHash("sso-b")}
		for _, h := range hashes {
			if _, err := r.CreateSSOSession(ctx, &service.SSOSessionRecord{
				TokenHash: h, UserID: uid, CreatedAtMs: 100, LastUsedAtMs: 100, ExpiresAtMs: 9_000,
			}); err != nil {
				t.Fatalf("CreateSSOSession %s: %v", h, err)
			}
		}
		otherHash := uniqueHash("sso-other")
		if _, err := r.CreateSSOSession(ctx, &service.SSOSessionRecord{
			TokenHash: otherHash, UserID: other, CreatedAtMs: 100, LastUsedAtMs: 100, ExpiresAtMs: 9_000,
		}); err != nil {
			t.Fatalf("CreateSSOSession other: %v", err)
		}

		if err := r.RevokeSSOSessionsForUser(ctx, uid, 700); err != nil {
			t.Fatalf("RevokeSSOSessionsForUser: %v", err)
		}
		for _, h := range hashes {
			got, err := r.FindSSOSessionByHash(ctx, h)
			if err != nil || got == nil {
				t.Fatalf("FindSSOSessionByHash %s: %v %#v", h, err, got)
			}
			if got.RevokedAtMs != 700 {
				t.Fatalf("session %s not revoked: %+v", h, got)
			}
		}
		untouched, err := r.FindSSOSessionByHash(ctx, otherHash)
		if err != nil || untouched == nil {
			t.Fatalf("FindSSOSessionByHash other: %v %#v", err, untouched)
		}
		if untouched.RevokedAtMs != 0 {
			t.Fatalf("another user's session was revoked: %+v", untouched)
		}

		// Re-revoking preserves the original timestamp (idempotent).
		if err := r.RevokeSSOSessionsForUser(ctx, uid, 800); err != nil {
			t.Fatalf("RevokeSSOSessionsForUser second call: %v", err)
		}
		got, err := r.FindSSOSessionByHash(ctx, hashes[0])
		if err != nil || got == nil {
			t.Fatalf("FindSSOSessionByHash: %v %#v", err, got)
		}
		if got.RevokedAtMs != 700 {
			t.Fatalf("re-revoke overwrote the first timestamp: %+v", got)
		}
	})

	t.Run("SSOSession_DeletedWithUser", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "sso-deleted@example.com")

		hash := uniqueHash("sso-del")
		if _, err := r.CreateSSOSession(ctx, &service.SSOSessionRecord{
			TokenHash: hash, UserID: uid, CreatedAtMs: 100, LastUsedAtMs: 100, ExpiresAtMs: 9_000,
		}); err != nil {
			t.Fatalf("CreateSSOSession: %v", err)
		}
		if err := r.DeleteUser(ctx, uid); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		got, err := r.FindSSOSessionByHash(ctx, hash)
		if err != nil {
			t.Fatalf("FindSSOSessionByHash after DeleteUser: %v", err)
		}
		if got != nil {
			t.Fatalf("SSO session survived account deletion: %+v", got)
		}
	})

	t.Run("SSOSession_SweepExpired", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)
		uid := createTestUser(t, r, "sso-sweep@example.com")

		expired := uniqueHash("sso-sweep-old")
		live := uniqueHash("sso-sweep-live")
		if _, err := r.CreateSSOSession(ctx, &service.SSOSessionRecord{
			TokenHash: expired, UserID: uid, CreatedAtMs: 10, LastUsedAtMs: 10, ExpiresAtMs: 100,
		}); err != nil {
			t.Fatalf("CreateSSOSession expired: %v", err)
		}
		if _, err := r.CreateSSOSession(ctx, &service.SSOSessionRecord{
			TokenHash: live, UserID: uid, CreatedAtMs: 10, LastUsedAtMs: 10, ExpiresAtMs: 10_000,
		}); err != nil {
			t.Fatalf("CreateSSOSession live: %v", err)
		}

		if err := r.DeleteExpiredSSOSessions(ctx, 0, 0); err == nil {
			t.Fatal("DeleteExpiredSSOSessions limit=0: want error, got nil")
		}
		if err := r.DeleteExpiredSSOSessions(ctx, 500, 100); err != nil {
			t.Fatalf("DeleteExpiredSSOSessions: %v", err)
		}

		gone, err := r.FindSSOSessionByHash(ctx, expired)
		if err != nil {
			t.Fatalf("FindSSOSessionByHash swept: %v", err)
		}
		if gone != nil {
			t.Fatalf("expired session survived the sweep: %+v", gone)
		}
		kept, err := r.FindSSOSessionByHash(ctx, live)
		if err != nil || kept == nil {
			t.Fatalf("live session was swept: %v %#v", err, kept)
		}
	})
}
