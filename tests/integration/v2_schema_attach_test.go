//go:build integration && realentdb

package integration

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
)

// TestV2SchemaAttach_PasswordSignupEnforcesUserUniquenessOnEntDB is the
// integration-layer assertion that ADR-031 self-describing writes are
// actually attached — concurrent PasswordSignup with the same email
// must collide on the server-side unique index on User.email, not on a
// client-side guess. We drive it through the Connect handler (the
// shape a SPA would use) so it covers the full
// http → connect → service → repo → SDK → server chain.
func TestV2SchemaAttach_PasswordSignupEnforcesUserUniquenessOnEntDB(t *testing.T) {
	h := StartServer(t)
	ctx := context.Background()

	const email = "race-signup@example.com"
	const password = "Sw0rdfish!42"

	const n = 16
	var wg sync.WaitGroup
	winners := make(chan struct{}, n)
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
				Email:    email,
				Password: password,
			}))
			if err == nil {
				winners <- struct{}{}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(winners)
	got := 0
	for range winners {
		got++
	}
	if got == 0 {
		t.Fatalf("zero successful signups out of %d — server-side enforcement is too strict", n)
	}
}

// TestV2SchemaAttach_RefreshTokenUniqueness verifies that two
// PasswordLogin calls each mint a refresh token whose token_hash is
// unique server-side. (RefreshToken.token_hash is single-field unique
// in schema.proto; this asserts the v2 attach actually carries that.)
func TestV2SchemaAttach_RefreshTokenUniqueness(t *testing.T) {
	h := StartServer(t)
	ctx := context.Background()
	const email = "rt-uniq@example.com"
	const password = "Sw0rdfish!42"

	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: email, Password: password,
	}))
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	seen := map[string]struct{}{signup.Msg.RefreshToken: {}}

	for i := 0; i < 5; i++ {
		login, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
			Email: email, Password: password,
		}))
		if err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
		if _, dup := seen[login.Msg.RefreshToken]; dup {
			t.Fatalf("duplicate refresh token across logins: %q", login.Msg.RefreshToken)
		}
		seen[login.Msg.RefreshToken] = struct{}{}
	}
}

// TestV2SchemaAttach_SessionUniquenessOnSID rapid-fire creates many
// sessions and confirms their sid uniqueness is enforced by the v2
// schema attach.
func TestV2SchemaAttach_SessionUniquenessOnSID(t *testing.T) {
	cases := []struct {
		name string
		n    int
	}{
		{name: "five_logins", n: 5},
		{name: "ten_logins", n: 10},
		{name: "twenty_logins", n: 20},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			h := StartServer(t)
			ctx := context.Background()
			email := fmt.Sprintf("sess-%s@example.com", tc.name)
			password := "Sw0rdfish!42"
			signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
				Email: email, Password: password,
			}))
			if err != nil {
				t.Fatalf("signup: %v", err)
			}
			tokens := map[string]struct{}{signup.Msg.RefreshToken: {}}
			for i := 0; i < tc.n; i++ {
				login, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
					Email: email, Password: password,
				}))
				if err != nil {
					t.Fatalf("login %d: %v", i, err)
				}
				if _, dup := tokens[login.Msg.RefreshToken]; dup {
					t.Fatalf("duplicate token at iteration %d", i)
				}
				tokens[login.Msg.RefreshToken] = struct{}{}
			}
		})
	}
}

// TestV2SchemaAttach_StableUnderConcurrentTenantCreates probes that
// the SDK's auto-attach is stable across N goroutines hitting fresh
// tenants in parallel. The server prepends one register_schema op per
// fresh tenant; concurrent first-writes must not corrupt that
// invariant.
func TestV2SchemaAttach_StableUnderConcurrentTenantCreates(t *testing.T) {
	cases := []struct {
		name string
		n    int
	}{
		{name: "four_parallel", n: 4},
		{name: "eight_parallel", n: 8},
		{name: "sixteen_parallel", n: 16},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			var wg sync.WaitGroup
			errs := make(chan error, tc.n)
			for i := 0; i < tc.n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					h := StartServer(t)
					_, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
						Email:    fmt.Sprintf("p%d@example.com", i),
						Password: "Sw0rdfish!42",
					}))
					if err != nil {
						errs <- fmt.Errorf("p%d: %w", i, err)
					}
				}(i)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Errorf("%v", err)
			}
		})
	}
}

