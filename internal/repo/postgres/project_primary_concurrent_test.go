package postgres

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

func TestSetPrimaryAuthDomainStore_OverlappingPromotions(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping auth-domain concurrency test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	connURL, err := url.Parse(dsn)
	require.NoError(t, err)
	params := connURL.Query()
	params.Set("application_name", t.Name())
	connURL.RawQuery = params.Encode()
	store := newProjectStore(ctx, t, connURL.String())
	projectID, err := store.CreateProject(ctx, &service.AdminProject{StorageScopeID: "primary-overlap", Name: "Acme"})
	require.NoError(t, err)
	require.NoError(t, store.EnsureAuthDomain(ctx, projectID, "old.example.test", true, 1000))
	_, err = store.SetPrimaryProjectAuthDomain(ctx, "missing-project", "old.example.test")
	require.ErrorIs(t, err, service.ErrNotFound)
	_, err = store.SetPrimaryProjectAuthDomain(ctx, projectID, "missing.example.test")
	require.ErrorIs(t, err, service.ErrNotFound)
	for _, hostname := range []string{"first.example.test", "second.example.test"} {
		require.NoError(t, store.EnsureAuthDomain(ctx, projectID, hostname, false, 1000))
	}

	// Keep the old primary locked until both callers are waiting. This forces
	// the overlap that a goroutine start barrier alone cannot guarantee.
	blocker, err := store.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = blocker.Rollback(ctx) }()
	var domainID string
	require.NoError(t, blocker.QueryRow(ctx, `SELECT id FROM project_auth_domains
		WHERE project_id = $1 AND is_primary FOR UPDATE`, projectID).Scan(&domainID))

	errs := make(chan error, 2)
	for _, hostname := range []string{"first.example.test", "second.example.test"} {
		go func() {
			_, err := store.SetPrimaryProjectAuthDomain(ctx, projectID, hostname)
			errs <- err
		}()
	}
	require.Eventually(t, func() bool {
		var waiting int
		err := store.pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND application_name = $1
			AND wait_event_type = 'Lock'`, t.Name()).Scan(&waiting)
		return err == nil && waiting == 2
	}, 5*time.Second, 10*time.Millisecond, "both promotions must overlap before releasing the old primary")
	require.NoError(t, blocker.Commit(ctx))
	for range 2 {
		require.NoError(t, <-errs)
	}

	domains, err := store.ListAuthDomains(ctx, projectID)
	require.NoError(t, err)
	primaryCount := 0
	for _, domain := range domains {
		if domain.IsPrimary {
			primaryCount++
			require.NotEqual(t, "old.example.test", domain.Hostname)
		}
	}
	require.Equal(t, 1, primaryCount)
}
