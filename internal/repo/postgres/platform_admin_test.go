package postgres

import (
	"context"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// fakeAdminHash is a placeholder password-hash value for the store tests; the
// store persists whatever hash it is handed, so the bytes are irrelevant.
// #nosec G101 -- a test fixture, not a real credential.
const fakeAdminHash = "bcrypt-hash-placeholder"

// newPlatformAdminStore migrates a Postgres at dsn and returns a
// PlatformAdminStore backed by it. The owning *pgRepository is closed on
// cleanup. Shared by the env-driven smoke test and the testcontainers
// container test (platform_admin_dockertest_test.go).
func newPlatformAdminStore(ctx context.Context, t *testing.T, dsn string) *PlatformAdminStore {
	t.Helper()
	repo, err := New(ctx, Config{
		DSN:         dsn,
		MaxConns:    10,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		ProjectID:   "control-plane",
	})
	require.NoError(t, err)
	t.Cleanup(repo.Close)
	return NewPlatformAdminStore(repo)
}

// TestPlatformAdminStore_Smoke exercises the zero-config first-admin bootstrap
// against a live Postgres pointed to by GATEWAY_TEST_POSTGRES_DSN: the first
// insert on an empty table creates the admin; a second is refused
// (created=false); and a burst of concurrent bootstraps creates exactly one.
// Skips without a backend; the dockerpostgres variant runs the same body in a
// throwaway container.
func TestPlatformAdminStore_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping platform-admin store smoke test")
	}
	runPlatformAdminSmoke(t, dsn)
}

func runPlatformAdminSmoke(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	store := newPlatformAdminStore(ctx, t, dsn)

	// Empty table → the first bootstrap creates the admin and writes its id.
	first := &service.PlatformAdmin{
		Email:        "ops@acme.test",
		PasswordHash: fakeAdminHash,
		Status:       service.PlatformAdminStatusActive,
	}
	created, err := store.CreateFirstPlatformAdmin(ctx, first)
	require.NoError(t, err)
	require.True(t, created, "first bootstrap on an empty table must create the admin")
	require.NotEmpty(t, first.ID, "the assigned id must be written back")

	n, err := store.CountPlatformAdmins(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	// Table not empty → a second bootstrap is permanently refused, even with a
	// different email. No second row is written.
	second := &service.PlatformAdmin{Email: "intruder@acme.test", PasswordHash: fakeAdminHash}
	created, err = store.CreateFirstPlatformAdmin(ctx, second)
	require.NoError(t, err)
	require.False(t, created, "a second bootstrap must be refused once an admin exists")
	require.Empty(t, second.ID, "a refused bootstrap must not assign an id")

	n, err = store.CountPlatformAdmins(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n, "the second bootstrap must not have written a row")

	// Concurrency: against a freshly-truncated table, a burst of bootstraps —
	// all racing on the advisory lock — must create EXACTLY one admin.
	require.NoError(t, truncateAll(ctx, dsn))

	// Each racer uses a DISTINCT email, so exactly-one is enforced by the
	// advisory-locked emptiness check — NOT by the email unique index (which
	// distinct emails would let all of them pass).
	const racers = 16
	var wg sync.WaitGroup
	var successes int32
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func(i int) {
			defer wg.Done()
			ok, cErr := store.CreateFirstPlatformAdmin(ctx, &service.PlatformAdmin{
				Email:        "race-" + strconv.Itoa(i) + "@acme.test",
				PasswordHash: fakeAdminHash,
			})
			require.NoError(t, cErr)
			if ok {
				atomic.AddInt32(&successes, 1)
			}
		}(i)
	}
	wg.Wait()

	require.Equal(t, int32(1), successes, "exactly one concurrent bootstrap must succeed")
	n, err = store.CountPlatformAdmins(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n, "concurrent bootstraps must leave exactly one admin")
}
