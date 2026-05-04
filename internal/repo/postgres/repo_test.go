package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// TestPostgres_Smoke is the default-tag smoke test for the Postgres
// repository. It runs only when GATEWAY_TEST_POSTGRES_DSN is set,
// so the unit-test job in CI (which has no Postgres available) skips
// cleanly. Container-based tests live behind the
// `dockerpostgres` build tag (see repo_dockertest_test.go).
func TestPostgres_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping postgres smoke test")
	}
	runRepositorySmoke(t, dsn, "smoke-tenant")
}

// runRepositorySmoke is the shared smoke-test body called both from
// the env-driven TestPostgres_Smoke and from the testcontainers-driven
// TestPostgres_Container (see repo_dockertest_test.go). When the
// internal/repo/conformance package lands the EntDB-rewrite agent will
// extend this to also run conformance.RunConformance(t, makeFresh).
func runRepositorySmoke(t *testing.T, dsn, tenantID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Truncate any prior state for repeatable runs.
	require.NoError(t, truncateAll(ctx, dsn))

	cfg := Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		TenantID:    tenantID,
	}
	repo, err := New(ctx, cfg)
	require.NoError(t, err)
	defer repo.(*pgRepository).Close()

	// CreateUser → GetUser → FindUserByEmail round-trip.
	now := time.Now()
	u := &service.User{
		Email:     "alice@example.com",
		Name:      "Alice",
		Role:      "admin",
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}
	id, err := repo.CreateUser(ctx, u)
	require.NoError(t, err)
	require.NotEmpty(t, id)

	got, err := repo.GetUser(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "alice@example.com", got.Email)

	byEmail, err := repo.FindUserByEmail(ctx, "Alice@Example.com") // case-insensitive
	require.NoError(t, err)
	require.NotNil(t, byEmail)
	require.Equal(t, id, byEmail.ID)

	// Duplicate email -> ErrAlreadyExists via wrapPgErr.
	_, err = repo.CreateUser(ctx, &service.User{
		Email: "alice@example.com", Name: "Alice2", CreatedAt: now, UpdatedAt: now,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, service.ErrAlreadyExists)

	// Failed-login lockout — atomic increment.
	c1, err := repo.IncrementFailedLoginCount(ctx, id)
	require.NoError(t, err)
	require.EqualValues(t, 1, c1)
	c2, err := repo.IncrementFailedLoginCount(ctx, id)
	require.NoError(t, err)
	require.EqualValues(t, 2, c2)
	require.NoError(t, repo.SetUserLockedUntil(ctx, id, 9999999999))
	require.NoError(t, repo.ResetFailedLoginCount(ctx, id))

	// Refresh-token lifecycle: create -> find -> consume -> replay attempt.
	rt := &service.RefreshTokenRecord{
		TokenHash:  "hash-aaa",
		UserID:     id,
		ExpiresAt:  time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt:  time.Now().UnixMilli(),
		LastUsedAt: time.Now().UnixMilli(),
	}
	rtID, err := repo.CreateRefreshToken(ctx, rt)
	require.NoError(t, err)
	require.NotEmpty(t, rtID)

	found, err := repo.FindRefreshTokenByHash(ctx, "hash-aaa")
	require.NoError(t, err)
	require.NotNil(t, found)

	require.NoError(t, repo.ConsumeRefreshTokenByHash(ctx, "hash-aaa", time.Now().UnixMilli()))
	// Second consume must lose the race.
	err = repo.ConsumeRefreshTokenByHash(ctx, "hash-aaa", time.Now().UnixMilli())
	require.ErrorIs(t, err, service.ErrUnauthenticated)

	// Live lookup hides the consumed row.
	notFound, err := repo.FindRefreshTokenByHash(ctx, "hash-aaa")
	require.NoError(t, err)
	require.Nil(t, notFound)

	// IncludingConsumed surfaces it for replay detection.
	consumed, err := repo.FindRefreshTokenByHashIncludingConsumed(ctx, "hash-aaa")
	require.NoError(t, err)
	require.NotNil(t, consumed)
	require.Greater(t, consumed.ConsumedAtMs, int64(0))

	// OAuth identity round-trip.
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &service.OAuthIdentity{
		UserID: id, Provider: "google", ProviderUserID: "google-uid-1",
		EmailAtLinkTime: "alice@example.com", CreatedAt: time.Now().UnixMilli(),
	}))
	user, err := repo.FindUserByProviderID(ctx, "google", "google-uid-1")
	require.NoError(t, err)
	require.NotNil(t, user)
	require.Equal(t, id, user.ID)

	// Duplicate (provider, provider_user_id) → ErrAlreadyExists.
	err = repo.CreateOAuthIdentity(ctx, &service.OAuthIdentity{
		UserID: id, Provider: "google", ProviderUserID: "google-uid-1",
		EmailAtLinkTime: "alice@example.com", CreatedAt: time.Now().UnixMilli(),
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists)

	idents, err := repo.ListOAuthIdentitiesForUser(ctx, id)
	require.NoError(t, err)
	require.Len(t, idents, 1)
}

// truncateAll wipes every table the postgres repo owns. We do this
// directly via a fresh pool because the service.Repository interface
// has no truncate method (and shouldn't).
func truncateAll(ctx context.Context, dsn string) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()

	// Migrate up so the tables exist before truncate.
	if err := runMigrations(dsn); err != nil {
		return err
	}

	const stmt = `
		TRUNCATE TABLE
			login_challenges,
			recovery_codes,
			totp_secrets,
			passkey_challenges,
			passkeys,
			qr_login_sessions,
			user_invitations,
			audit_events,
			group_memberships,
			groups,
			oauth_identities,
			email_change_tokens,
			email_verification_tokens,
			password_reset_tokens,
			sessions,
			refresh_tokens,
			users
		RESTART IDENTITY CASCADE`
	_, err = pool.Exec(ctx, stmt)
	return err
}

// TestPostgres_ConfigValidation exercises the env / default plumbing.
// It does not require a running Postgres.
func TestPostgres_ConfigValidation(t *testing.T) {
	cfg := Config{}
	cfg.applyDefaults()
	require.Equal(t, DefaultMaxConns, cfg.MaxConns)
	require.Equal(t, DefaultConnTimeout, cfg.ConnTimeout)

	require.Error(t, cfg.validate(), "empty DSN must fail validation")

	cfg.DSN = "postgres://x:y@localhost:5432/db"
	require.Error(t, cfg.validate(), "missing tenant must fail")

	cfg.TenantID = "test"
	require.NoError(t, cfg.validate())
}
