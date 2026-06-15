//go:build integration && (realentdb || realpostgres)

package integration

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

func withSharedTenant(tenantID string) HarnessOption {
	return WithConfig(func(cfg *config.Config) {
		cfg.DefaultTenantID = tenantID
		// The data-plane binds to the project (ADR-0002); on real entdb the
		// partition is provisioned under tenantID, so the default project must
		// resolve to it too — otherwise reads/writes hit an unprovisioned scope.
		cfg.DefaultProjectID = tenantID
	})
}

type signupResult struct {
	accessToken string
	err         error
}

func TestRealBackend_RefreshReplayAcrossReplicasRevokesSessions(t *testing.T) {
	t.Parallel()

	tenantID := fmt.Sprintf("replica-refresh-%d", time.Now().UnixNano())
	hA := StartServer(t, withSharedTenant(tenantID))
	hB := StartServer(t, withSharedTenant(tenantID))
	ctx := context.Background()

	_, refresh, _ := signupViaClient(t, hA, "replica-refresh@example.com")

	first, err := hA.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: refresh,
	}))
	if err != nil {
		t.Fatalf("first RefreshToken: %v", err)
	}

	_, err = hB.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: refresh,
	}))
	if err == nil {
		t.Fatalf("expected replay via second replica to fail")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("replay code = %v, want Unauthenticated (err=%v)", got, err)
	}

	requireRefreshRejectedEventually(t, hA, first.Msg.RefreshToken)
}

func TestRealBackend_ConcurrentRefreshRotationAcrossReplicas(t *testing.T) {
	t.Parallel()

	tenantID := fmt.Sprintf("replica-race-%d", time.Now().UnixNano())
	hA := StartServer(t, withSharedTenant(tenantID))
	hB := StartServer(t, withSharedTenant(tenantID))
	ctx := context.Background()

	_, refresh, _ := signupViaClient(t, hA, "replica-race@example.com")

	type result struct {
		refresh string
		err     error
	}

	start := make(chan struct{})
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, h := range []*Harness{hA, hB} {
		wg.Add(1)
		go func(h *Harness) {
			defer wg.Done()
			<-start
			resp, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
				RefreshToken: refresh,
			}))
			if err != nil {
				results <- result{err: err}
				return
			}
			results <- result{refresh: resp.Msg.RefreshToken}
		}(h)
	}
	close(start)
	wg.Wait()
	close(results)

	var successes []string
	failures := 0
	for res := range results {
		if res.err != nil {
			if got := connect.CodeOf(res.err); got != connect.CodeUnauthenticated {
				t.Fatalf("concurrent refresh failure code = %v, want Unauthenticated (err=%v)", got, res.err)
			}
			failures++
			continue
		}
		successes = append(successes, res.refresh)
	}

	if len(successes) != 1 || failures != 1 {
		t.Fatalf("concurrent refresh results: successes=%d failures=%d, want 1/1", len(successes), failures)
	}
	requireRefreshRejectedEventually(t, hA, successes[0])
}

func TestRealBackend_ConcurrentSignupSameEmailCreatesOneUser(t *testing.T) {
	t.Parallel()

	tenantID := fmt.Sprintf("signup-race-%d", time.Now().UnixNano())
	hA := StartServer(t, withSharedTenant(tenantID))
	hB := StartServer(t, withSharedTenant(tenantID))
	ctx := context.Background()

	req := &identitypb.PasswordSignupRequest{
		Email:    "signup-race@example.com",
		Password: goodPassword,
	}

	start := make(chan struct{})
	results := make(chan signupResult, 2)
	var wg sync.WaitGroup
	for _, h := range []*Harness{hA, hB} {
		wg.Add(1)
		go func(h *Harness) {
			defer wg.Done()
			<-start
			resp, err := h.Client.PasswordSignup(ctx, connect.NewRequest(req))
			if err != nil {
				results <- signupResult{err: err}
				return
			}
			results <- signupResult{accessToken: resp.Msg.AccessToken}
		}(h)
	}
	close(start)
	wg.Wait()
	close(results)

	tokens := make([]string, 0, 2)
	for res := range results {
		if res.err != nil {
			t.Fatalf("concurrent signup: %v", res.err)
		}
		if res.accessToken == "" {
			t.Fatalf("concurrent signup returned empty access token")
		}
		tokens = append(tokens, res.accessToken)
	}

	hA.WaitForUser(t, req.Email, func(user *service.User) bool {
		return user.Email == req.Email
	})
	hA.WaitForUserCount(t, req.Email, 1)

	authedUsers := 0
	for _, token := range tokens {
		if tokenAuthenticatesEventually(t, hA, token) {
			authedUsers++
		}
	}
	if authedUsers > 1 {
		t.Fatalf("concurrent signup authenticated %d users, want at most 1", authedUsers)
	}
}

func tokenAuthenticatesEventually(t *testing.T, h *Harness, accessToken string) bool {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := h.AuthedClient(accessToken).GetCurrentUser(context.Background(), connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
		if err == nil {
			return true
		}
		switch got := connect.CodeOf(err); got {
		case connect.CodeNotFound, connect.CodeUnauthenticated:
			if time.Now().After(deadline) {
				return false
			}
			time.Sleep(20 * time.Millisecond)
		default:
			t.Fatalf("concurrent signup auth probe code = %v, want NotFound or Unauthenticated (err=%v)", got, err)
		}
	}
}
