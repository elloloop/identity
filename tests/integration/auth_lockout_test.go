//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
)

// TestLockout_FiveFailuresLockAccountThenUnlocks drives the lockout
// flow end-to-end through the Connect-RPC layer:
//
//  1. Sign up a real user.
//  2. Five PasswordLogin attempts with the wrong password each return
//     CodeUnauthenticated.
//  3. The sixth attempt — even with the CORRECT password — returns
//     CodeResourceExhausted (the gRPC code we map ErrAccountLocked to).
//  4. After the lockout window has passed, login with the correct
//     password succeeds.
//
// The lockout window is shrunk to 1 second via direct repo mutation so
// the test stays fast; the real config defaults to 15 minutes.
func TestLockout_FiveFailuresLockAccountThenUnlocks(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	const email = "lockout-victim@example.com"

	if _, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    email,
		Password: goodPassword,
	})); err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}

	// Five wrong-password attempts: each must be Unauthenticated.
	for i := 0; i < 5; i++ {
		_, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
			Email:    email,
			Password: "Wrong-Password!9",
		}))
		if err == nil {
			t.Fatalf("attempt %d: expected error, got nil", i+1)
		}
		if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
			t.Fatalf("attempt %d: code = %v, want Unauthenticated (err=%v)", i+1, got, err)
		}
	}

	// Sixth attempt — with the correct password — must be rejected.
	_, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    email,
		Password: goodPassword,
	}))
	if err == nil {
		t.Fatalf("locked account with correct password: expected error, got nil")
	}
	if got := connect.CodeOf(err); got != connect.CodeResourceExhausted {
		t.Fatalf("locked-account code = %v, want ResourceExhausted (err=%v)", got, err)
	}

	// Force-shorten the lockout window so the test does not have to wait
	// 15 real minutes. We poke the in-memory repo directly: set
	// LockedUntil to 1ms ago, simulating "the cooldown has just lapsed".
	uid := findUserIDByEmail(t, h.Repo, email)
	pastMs := time.Now().Add(-time.Millisecond).UnixMilli()
	if err := h.Repo.SetUserLockedUntil(ctx, uid, pastMs); err != nil {
		t.Fatalf("SetUserLockedUntil: %v", err)
	}

	// The account is no longer in the lockout window — login should succeed
	// (the service-layer reset path also clears FailedLoginCount).
	resp, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    email,
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("post-lockout PasswordLogin: %v", err)
	}
	if resp.Msg.AccessToken == "" {
		t.Fatalf("post-lockout login returned empty access token")
	}
}

// findUserIDByEmail looks up a userID in the in-memory repo. Reaches
// into the package-private state under r.mu via the public helper —
// MemRepo doesn't expose a "find by email" the way the Repository
// interface does (which returns a copy), so we walk the map.
func findUserIDByEmail(t *testing.T, r *MemRepo, email string) string {
	t.Helper()
	u, err := r.FindUserByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if u == nil {
		t.Fatalf("user %s not found in repo", email)
	}
	return u.ID
}
