package postgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

func teammateKeyRepo(t *testing.T) (*pgRepository, string) {
	t.Helper()
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx := context.Background()
	project := fmt.Sprintf("teammate-keys-%d", time.Now().UnixNano())
	repo, err := New(ctx, Config{DSN: dsn, ProjectID: project, AutoMigrate: true})
	require.NoError(t, err)
	t.Cleanup(repo.Close)
	seedProject(ctx, t, repo, project)
	return repo, project
}

func teammateKey(claim string, publicKey byte) *service.TeammateKey {
	return &service.TeammateKey{ID: "key-" + claim, ClaimID: claim, TeammateID: "agent-1", CompanyID: "company-1", WorkstationID: "workstation-1", PublicKey: []byte{0x30, publicKey}, Algorithm: service.TeammateKeyECDSAP256, CreatedAtMs: 1000}
}

func TestTeammateKeyMigrationRoundTrip(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	scratch := createScratchDatabase(ctx, t, dsn)
	source, err := iofs.New(migrationFS, "migrations")
	require.NoError(t, err)
	defer func() { _ = source.Close() }()
	previous, err := source.Prev(50)
	require.NoError(t, err)
	migrateToVersion(t, scratch, previous)
	raw, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	for _, version := range []uint{50, previous, 50} {
		migrateToVersion(t, scratch, version)
		for _, table := range []string{"teammate_keys", "teammate_key_challenges"} {
			var exists bool
			require.NoError(t, raw.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists))
			require.Equal(t, version == 50, exists)
		}
		var kinds string
		require.NoError(t, raw.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='project_credentials_kind_check'`).Scan(&kinds))
		require.Equal(t, version == 50, strings.Contains(kinds, "teammate_key_manager"))
		require.True(t, strings.Contains(kinds, "directory_reader"))
	}
}

func TestTeammateKeyRegistrationIsOnePerClaimAndKey(t *testing.T) {
	repo, _ := teammateKeyRepo(t)
	ctx := context.Background()
	stored, err := repo.RegisterTeammateKey(ctx, teammateKey("claim-a", 1))
	require.NoError(t, err)
	require.Equal(t, teammateKey("claim-a", 1), stored)

	retry := teammateKey("claim-a", 2)
	retry.ID = "key-other"
	stored, err = repo.RegisterTeammateKey(ctx, retry)
	require.NoError(t, err)
	require.Equal(t, "key-claim-a", stored.ID)
	require.Equal(t, []byte{0x30, 1}, stored.PublicKey)

	_, err = repo.RegisterTeammateKey(ctx, teammateKey("claim-b", 1))
	require.ErrorIs(t, err, service.ErrAlreadyExists)
	missing, err := repo.GetTeammateKey(ctx, "key-claim-b")
	require.NoError(t, err)
	require.Nil(t, missing)

	got, err := repo.GetTeammateKey(ctx, "key-claim-a")
	require.NoError(t, err)
	require.Equal(t, teammateKey("claim-a", 1), got)
	other, ok := repo.WithProject("another-project").(*pgRepository)
	require.True(t, ok)
	hidden, err := other.GetTeammateKey(ctx, "key-claim-a")
	require.NoError(t, err)
	require.Nil(t, hidden)
}

func TestTeammateKeyRevocationEndsChallenges(t *testing.T) {
	repo, _ := teammateKeyRepo(t)
	ctx := context.Background()
	_, err := repo.RegisterTeammateKey(ctx, teammateKey("claim-a", 1))
	require.NoError(t, err)
	require.NoError(t, repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "challenge-1", KeyID: "key-claim-a", Message: "m", CreatedAtMs: 2000, ExpiresAtMs: 62000}))

	revoked, err := repo.RevokeTeammateKey(ctx, "claim-a", service.TeammateKeyReleased, 3000)
	require.NoError(t, err)
	require.True(t, revoked)
	revoked, err = repo.RevokeTeammateKey(ctx, "claim-a", service.TeammateKeyRemoved, 4000)
	require.NoError(t, err)
	require.False(t, revoked)
	revoked, err = repo.RevokeTeammateKey(ctx, "claim-unknown", service.TeammateKeyReleased, 4000)
	require.NoError(t, err)
	require.False(t, revoked)

	key, err := repo.GetTeammateKey(ctx, "key-claim-a")
	require.NoError(t, err)
	require.Equal(t, int64(3000), key.RevokedAtMs)
	require.Equal(t, service.TeammateKeyReleased, key.RevocationReason)
	challenge, err := repo.GetTeammateKeyChallenge(ctx, "challenge-1")
	require.NoError(t, err)
	require.Nil(t, challenge)
	err = repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "challenge-2", KeyID: "key-claim-a", Message: "m", CreatedAtMs: 5000, ExpiresAtMs: 65000})
	require.ErrorIs(t, err, service.ErrUnauthenticated)
	err = repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "challenge-3", KeyID: "key-unknown", Message: "m", CreatedAtMs: 5000, ExpiresAtMs: 65000})
	require.ErrorIs(t, err, service.ErrUnauthenticated)

	stored, err := repo.RegisterTeammateKey(ctx, teammateKey("claim-a", 1))
	require.NoError(t, err)
	require.Equal(t, int64(3000), stored.RevokedAtMs)
}

func TestTeammateKeyChallengeIsSingleUseAndBounded(t *testing.T) {
	repo, _ := teammateKeyRepo(t)
	ctx := context.Background()
	_, err := repo.RegisterTeammateKey(ctx, teammateKey("claim-a", 1))
	require.NoError(t, err)
	_, err = repo.RegisterTeammateKey(ctx, teammateKey("claim-b", 2))
	require.NoError(t, err)
	for i := range service.MaxTeammateKeyChallenges {
		require.NoError(t, repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: fmt.Sprintf("challenge-%d", i), KeyID: "key-claim-a", Message: "m", CreatedAtMs: 1000, ExpiresAtMs: 61000}))
	}
	err = repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "challenge-over", KeyID: "key-claim-a", Message: "m", CreatedAtMs: 1000, ExpiresAtMs: 61000})
	require.ErrorIs(t, err, service.ErrTeammateKeyChallengeLimit)
	require.NoError(t, repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "challenge-after-expiry", KeyID: "key-claim-a", Message: "m", CreatedAtMs: 61000, ExpiresAtMs: 121000}))
	expired, err := repo.GetTeammateKeyChallenge(ctx, "challenge-0")
	require.NoError(t, err)
	require.Nil(t, expired)

	got, err := repo.GetTeammateKeyChallenge(ctx, "challenge-after-expiry")
	require.NoError(t, err)
	require.Equal(t, &service.TeammateKeyChallenge{ID: "challenge-after-expiry", KeyID: "key-claim-a", Message: "m", CreatedAtMs: 61000, ExpiresAtMs: 121000}, got)
	consumed, err := repo.ConsumeTeammateKeyChallenge(ctx, "challenge-after-expiry", "key-claim-b", 62000)
	require.NoError(t, err)
	require.False(t, consumed)
	consumed, err = repo.ConsumeTeammateKeyChallenge(ctx, "challenge-after-expiry", "key-claim-a", 121000)
	require.NoError(t, err)
	require.False(t, consumed)
	consumed, err = repo.ConsumeTeammateKeyChallenge(ctx, "challenge-after-expiry", "key-claim-a", 62000)
	require.NoError(t, err)
	require.True(t, consumed)
	consumed, err = repo.ConsumeTeammateKeyChallenge(ctx, "challenge-after-expiry", "key-claim-a", 62000)
	require.NoError(t, err)
	require.False(t, consumed)
}

func TestTeammateKeyConsumeRefusesARevokedKey(t *testing.T) {
	repo, _ := teammateKeyRepo(t)
	ctx := context.Background()
	_, err := repo.RegisterTeammateKey(ctx, teammateKey("claim-a", 1))
	require.NoError(t, err)
	require.NoError(t, repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "challenge-1", KeyID: "key-claim-a", Message: "m", CreatedAtMs: 1000, ExpiresAtMs: 61000}))
	_, err = repo.pool.Exec(ctx, `UPDATE teammate_keys SET revoked_at_ms=2000,revocation_reason='drifted' WHERE project_id=$1 AND id='key-claim-a'`, repo.projectID)
	require.NoError(t, err)
	consumed, err := repo.ConsumeTeammateKeyChallenge(ctx, "challenge-1", "key-claim-a", 3000)
	require.NoError(t, err)
	require.False(t, consumed)
}

func TestTeammateKeySweeps(t *testing.T) {
	repo, _ := teammateKeyRepo(t)
	ctx := context.Background()
	for i, claim := range []string{"claim-a", "claim-b", "claim-c"} {
		_, err := repo.RegisterTeammateKey(ctx, teammateKey(claim, byte(i)))
		require.NoError(t, err)
	}
	require.NoError(t, repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "old", KeyID: "key-claim-c", Message: "m", CreatedAtMs: 1000, ExpiresAtMs: 61000}))
	require.NoError(t, repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "new", KeyID: "key-claim-c", Message: "m", CreatedAtMs: 60000, ExpiresAtMs: 120000}))
	_, err := repo.RevokeTeammateKey(ctx, "claim-a", service.TeammateKeyReclaimed, 1000)
	require.NoError(t, err)
	_, err = repo.RevokeTeammateKey(ctx, "claim-b", service.TeammateKeyReclaimed, 5000)
	require.NoError(t, err)

	for _, limit := range []int{0, 10001} {
		require.ErrorIs(t, repo.DeleteExpiredTeammateKeyChallenges(ctx, 61000, limit), service.ErrInvalidArgument)
		require.ErrorIs(t, repo.DeleteTeammateKeysRevokedBefore(ctx, 5000, limit), service.ErrInvalidArgument)
	}
	require.NoError(t, repo.DeleteExpiredTeammateKeyChallenges(ctx, 61000, 100))
	old, err := repo.GetTeammateKeyChallenge(ctx, "old")
	require.NoError(t, err)
	require.Nil(t, old)
	kept, err := repo.GetTeammateKeyChallenge(ctx, "new")
	require.NoError(t, err)
	require.NotNil(t, kept)

	require.NoError(t, repo.DeleteTeammateKeysRevokedBefore(ctx, 5000, 100))
	for id, present := range map[string]bool{"key-claim-a": false, "key-claim-b": true, "key-claim-c": true} {
		key, err := repo.GetTeammateKey(ctx, id)
		require.NoError(t, err)
		require.Equal(t, present, key != nil, id)
	}
}
