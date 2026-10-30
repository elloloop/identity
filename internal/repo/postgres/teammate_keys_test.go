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

const teammatePlacement = "placement-1"

func teammateKey(claim string, publicKey byte) *service.TeammateKey {
	return &service.TeammateKey{ID: "key-" + claim, ClaimID: claim, TeammateID: "agent-1", CompanyID: "company-1", WorkstationID: "workstation-1", PublicKey: []byte{0x30, publicKey}, Algorithm: service.TeammateKeyECDSAP256, GrantID: "grant-" + claim, CreatedAtMs: 1000}
}

func storedTeammateKey(claim string, publicKey byte) *service.TeammateKey {
	key := teammateKey(claim, publicKey)
	key.OwnerUserID = "lead-1"
	return key
}

func hireGrant(id string) *service.HireGrant {
	return &service.HireGrant{ID: id, OwnerUserID: "lead-1", TeammateID: "agent-1", PlacementID: teammatePlacement, CompanyID: "company-1", CreatedAtMs: 500, ExpiresAtMs: 10000}
}

func registerGranted(ctx context.Context, t *testing.T, repo *pgRepository, key *service.TeammateKey) (*service.TeammateKey, error) {
	t.Helper()
	require.NoError(t, repo.CreateHireGrant(ctx, hireGrant(key.GrantID)))
	return repo.RegisterTeammateKey(ctx, key, teammatePlacement)
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

func TestHireGrantMigrationRoundTrip(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	scratch := createScratchDatabase(ctx, t, dsn)
	migrateToVersion(t, scratch, 54)
	raw, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	_, err = raw.Exec(ctx, `INSERT INTO projects (id, storage_scope_id, created_at_ms, updated_at_ms) VALUES ('p', 'scope-p', 0, 0)`)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `SELECT set_config('app.current_project_id','p',false)`)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `INSERT INTO teammate_keys(project_id,id,claim_id,teammate_id,company_id,workstation_id,public_key,algorithm,created_at_ms) VALUES('p','k','c','a','co','w','\x3001','ecdsa_p256',1000)`)
	require.NoError(t, err)

	for _, version := range []uint{55, 54, 55} {
		migrateToVersion(t, scratch, version)
		var exists bool
		require.NoError(t, raw.QueryRow(ctx, `SELECT to_regclass('hire_grants') IS NOT NULL`).Scan(&exists))
		require.Equal(t, version == 55, exists)
		var columns int
		require.NoError(t, raw.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name='teammate_keys' AND column_name IN ('grant_id','owner_user_id')`).Scan(&columns))
		require.Equal(t, map[bool]int{true: 2, false: 0}[version == 55], columns)
	}
	var revokedAt int64
	var reason string
	require.NoError(t, raw.QueryRow(ctx, `SELECT revoked_at_ms,revocation_reason FROM teammate_keys WHERE id='k'`).Scan(&revokedAt, &reason))
	require.Positive(t, revokedAt)
	require.Equal(t, service.TeammateKeyRemoved, reason)
	_, err = raw.Exec(ctx, `INSERT INTO teammate_keys(project_id,id,claim_id,teammate_id,company_id,workstation_id,public_key,algorithm,created_at_ms) VALUES('p','k2','c2','a','co','w','\x3002','ecdsa_p256',1000)`)
	require.ErrorContains(t, err, "teammate_keys_granted")
}

func TestTeammateKeyRegistrationIsOnePerClaimAndKey(t *testing.T) {
	repo, _ := teammateKeyRepo(t)
	ctx := context.Background()
	stored, err := registerGranted(ctx, t, repo, teammateKey("claim-a", 1))
	require.NoError(t, err)
	require.Equal(t, storedTeammateKey("claim-a", 1), stored)

	retry := teammateKey("claim-a", 2)
	retry.ID = "key-other"
	retry.GrantID = "grant-retry"
	stored, err = registerGranted(ctx, t, repo, retry)
	require.NoError(t, err)
	require.Equal(t, "key-claim-a", stored.ID)
	require.Equal(t, []byte{0x30, 1}, stored.PublicKey)
	unused := teammateKey("claim-z", 3)
	unused.GrantID = "grant-retry"
	_, err = repo.RegisterTeammateKey(ctx, unused, teammatePlacement)
	require.NoError(t, err, "a claim that already had a key leaves the grant unused")

	_, err = registerGranted(ctx, t, repo, teammateKey("claim-b", 1))
	require.ErrorIs(t, err, service.ErrAlreadyExists)
	missing, err := repo.GetTeammateKey(ctx, "key-claim-b")
	require.NoError(t, err)
	require.Nil(t, missing)

	got, err := repo.GetTeammateKey(ctx, "key-claim-a")
	require.NoError(t, err)
	require.Equal(t, storedTeammateKey("claim-a", 1), got)
	other, ok := repo.WithProject("another-project").(*pgRepository)
	require.True(t, ok)
	hidden, err := other.GetTeammateKey(ctx, "key-claim-a")
	require.NoError(t, err)
	require.Nil(t, hidden)
}

func TestTeammateKeyRegistrationConsumesOnlyAMatchingGrant(t *testing.T) {
	repo, _ := teammateKeyRepo(t)
	ctx := context.Background()
	for name, grant := range map[string]*service.HireGrant{
		"another teammate":  {TeammateID: "agent-2"},
		"another placement": {PlacementID: "placement-2"},
		"another company":   {CompanyID: "company-2"},
		"expired":           {ExpiresAtMs: 1000},
	} {
		full := hireGrant("grant-" + strings.ReplaceAll(name, " ", "-"))
		if grant.TeammateID != "" {
			full.TeammateID = grant.TeammateID
		}
		if grant.PlacementID != "" {
			full.PlacementID = grant.PlacementID
		}
		if grant.CompanyID != "" {
			full.CompanyID = grant.CompanyID
		}
		if grant.ExpiresAtMs != 0 {
			full.ExpiresAtMs = grant.ExpiresAtMs
		}
		require.NoError(t, repo.CreateHireGrant(ctx, full))
		key := teammateKey("claim-"+strings.ReplaceAll(name, " ", "-"), 9)
		key.GrantID = full.ID
		_, err := repo.RegisterTeammateKey(ctx, key, teammatePlacement)
		require.ErrorIs(t, err, service.ErrHireGrantRefused, name)
	}
	unknown := teammateKey("claim-unknown", 8)
	unknown.GrantID = "grant-unknown"
	_, err := repo.RegisterTeammateKey(ctx, unknown, teammatePlacement)
	require.ErrorIs(t, err, service.ErrHireGrantRefused)

	_, err = registerGranted(ctx, t, repo, teammateKey("claim-a", 1))
	require.NoError(t, err)
	again, err := repo.RegisterTeammateKey(ctx, teammateKey("claim-a", 1), teammatePlacement)
	require.NoError(t, err, "a retry of the claim that used the grant")
	require.Equal(t, "key-claim-a", again.ID)
	reused := teammateKey("claim-b", 2)
	reused.GrantID = "grant-claim-a"
	_, err = repo.RegisterTeammateKey(ctx, reused, teammatePlacement)
	require.ErrorIs(t, err, service.ErrHireGrantRefused, "a grant used by another claim")
	other, ok := repo.WithProject("another-project").(*pgRepository)
	require.True(t, ok)
	require.NoError(t, repo.CreateHireGrant(ctx, hireGrant("grant-claim-c")))
	_, err = other.RegisterTeammateKey(ctx, teammateKey("claim-c", 3), teammatePlacement)
	require.ErrorIs(t, err, service.ErrHireGrantRefused, "a grant of another project")
}

func TestTeammateKeyRevocationEndsChallenges(t *testing.T) {
	repo, _ := teammateKeyRepo(t)
	ctx := context.Background()
	_, err := registerGranted(ctx, t, repo, teammateKey("claim-a", 1))
	require.NoError(t, err)
	require.NoError(t, repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "challenge-1", KeyID: "key-claim-a", Message: "m", CreatedAtMs: 2000, ExpiresAtMs: 62000}))

	stopsAt, changed, err := repo.RevokeTeammateKey(ctx, "claim-a", service.TeammateKeyReleased, 3000, 3000)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, int64(3000), stopsAt)
	stopsAt, changed, err = repo.RevokeTeammateKey(ctx, "claim-a", service.TeammateKeyRemoved, 4000, 4000)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, int64(3000), stopsAt)
	stopsAt, changed, err = repo.RevokeTeammateKey(ctx, "claim-unknown", service.TeammateKeyReleased, 4000, 4000)
	require.NoError(t, err)
	require.False(t, changed)
	require.Zero(t, stopsAt)

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

	stored, err := repo.RegisterTeammateKey(ctx, teammateKey("claim-a", 1), teammatePlacement)
	require.NoError(t, err)
	require.Equal(t, int64(3000), stored.RevokedAtMs)
}

func TestTeammateKeyRevocationDeadlineEndsTheKeyWithNoFurtherCall(t *testing.T) {
	repo, _ := teammateKeyRepo(t)
	ctx := context.Background()
	_, err := registerGranted(ctx, t, repo, teammateKey("claim-a", 1))
	require.NoError(t, err)
	require.NoError(t, repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "pending", KeyID: "key-claim-a", Message: "m", CreatedAtMs: 2000, ExpiresAtMs: 62000}))

	stopsAt, changed, err := repo.RevokeTeammateKey(ctx, "claim-a", service.TeammateKeyReleased, 50000, 3000)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, int64(50000), stopsAt)
	stopsAt, changed, err = repo.RevokeTeammateKey(ctx, "claim-a", service.TeammateKeyReleased, 90000, 4000)
	require.NoError(t, err)
	require.False(t, changed, "a later deadline never moves it back")
	require.Equal(t, int64(50000), stopsAt)

	require.NoError(t, repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "draining", KeyID: "key-claim-a", Message: "m", CreatedAtMs: 49000, ExpiresAtMs: 109000}))
	consumed, stopsAt, err := repo.ConsumeTeammateKeyChallenge(ctx, "pending", "key-claim-a", 49999)
	require.NoError(t, err)
	require.True(t, consumed, "the key works until its deadline")
	require.Equal(t, int64(50000), stopsAt, "the consumption reports the deadline it ran under")
	consumed, _, err = repo.ConsumeTeammateKeyChallenge(ctx, "draining", "key-claim-a", 50000)
	require.NoError(t, err)
	require.False(t, consumed, "no exchange from the deadline")
	err = repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "late", KeyID: "key-claim-a", Message: "m", CreatedAtMs: 50000, ExpiresAtMs: 110000})
	require.ErrorIs(t, err, service.ErrUnauthenticated)

	stopsAt, changed, err = repo.RevokeTeammateKey(ctx, "claim-a", service.TeammateKeyDrifted, 20000, 20000)
	require.NoError(t, err)
	require.True(t, changed, "an earlier time brings it forward")
	require.Equal(t, int64(20000), stopsAt)
	key, err := repo.GetTeammateKey(ctx, "key-claim-a")
	require.NoError(t, err)
	require.Equal(t, service.TeammateKeyDrifted, key.RevocationReason)
	draining, err := repo.GetTeammateKeyChallenge(ctx, "draining")
	require.NoError(t, err)
	require.Nil(t, draining)
}

func TestTeammateKeyChallengeIsSingleUseAndBounded(t *testing.T) {
	repo, _ := teammateKeyRepo(t)
	ctx := context.Background()
	_, err := registerGranted(ctx, t, repo, teammateKey("claim-a", 1))
	require.NoError(t, err)
	_, err = registerGranted(ctx, t, repo, teammateKey("claim-b", 2))
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
	consumed, _, err := repo.ConsumeTeammateKeyChallenge(ctx, "challenge-after-expiry", "key-claim-b", 62000)
	require.NoError(t, err)
	require.False(t, consumed)
	consumed, _, err = repo.ConsumeTeammateKeyChallenge(ctx, "challenge-after-expiry", "key-claim-a", 121000)
	require.NoError(t, err)
	require.False(t, consumed)
	consumed, _, err = repo.ConsumeTeammateKeyChallenge(ctx, "challenge-after-expiry", "key-claim-a", 62000)
	require.NoError(t, err)
	require.True(t, consumed)
	consumed, _, err = repo.ConsumeTeammateKeyChallenge(ctx, "challenge-after-expiry", "key-claim-a", 62000)
	require.NoError(t, err)
	require.False(t, consumed)
}

func TestTeammateKeyConsumeRefusesARevokedKey(t *testing.T) {
	repo, _ := teammateKeyRepo(t)
	ctx := context.Background()
	_, err := registerGranted(ctx, t, repo, teammateKey("claim-a", 1))
	require.NoError(t, err)
	require.NoError(t, repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "challenge-1", KeyID: "key-claim-a", Message: "m", CreatedAtMs: 1000, ExpiresAtMs: 61000}))
	_, err = repo.pool.Exec(ctx, `UPDATE teammate_keys SET revoked_at_ms=2000,revocation_reason='drifted' WHERE project_id=$1 AND id='key-claim-a'`, repo.projectID)
	require.NoError(t, err)
	consumed, _, err := repo.ConsumeTeammateKeyChallenge(ctx, "challenge-1", "key-claim-a", 3000)
	require.NoError(t, err)
	require.False(t, consumed)
}

func TestTeammateKeySweeps(t *testing.T) {
	repo, _ := teammateKeyRepo(t)
	ctx := context.Background()
	for i, claim := range []string{"claim-a", "claim-b", "claim-c"} {
		_, err := registerGranted(ctx, t, repo, teammateKey(claim, byte(i)))
		require.NoError(t, err)
	}
	require.NoError(t, repo.CreateHireGrant(ctx, &service.HireGrant{ID: "grant-late", OwnerUserID: "lead-1", TeammateID: "agent-1", PlacementID: teammatePlacement, CompanyID: "company-1", CreatedAtMs: 500, ExpiresAtMs: 20000}))
	require.NoError(t, repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "old", KeyID: "key-claim-c", Message: "m", CreatedAtMs: 1000, ExpiresAtMs: 61000}))
	require.NoError(t, repo.CreateTeammateKeyChallenge(ctx, &service.TeammateKeyChallenge{ID: "new", KeyID: "key-claim-c", Message: "m", CreatedAtMs: 60000, ExpiresAtMs: 120000}))
	_, _, err := repo.RevokeTeammateKey(ctx, "claim-a", service.TeammateKeyReclaimed, 1000, 1000)
	require.NoError(t, err)
	_, _, err = repo.RevokeTeammateKey(ctx, "claim-b", service.TeammateKeyReclaimed, 5000, 5000)
	require.NoError(t, err)

	for _, limit := range []int{0, 10001} {
		require.ErrorIs(t, repo.DeleteExpiredTeammateKeyChallenges(ctx, 61000, limit), service.ErrInvalidArgument)
		require.ErrorIs(t, repo.DeleteTeammateKeysRevokedBefore(ctx, 5000, limit), service.ErrInvalidArgument)
		require.ErrorIs(t, repo.DeleteHireGrantsExpiredBefore(ctx, 10000, limit), service.ErrInvalidArgument)
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

	require.NoError(t, repo.DeleteHireGrantsExpiredBefore(ctx, 10000, 100))
	var grants []string
	rows, err := repo.pool.Query(ctx, `SELECT id FROM hire_grants WHERE project_id=$1 ORDER BY id`, repo.projectID)
	require.NoError(t, err)
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		grants = append(grants, id)
	}
	require.NoError(t, rows.Err())
	require.Equal(t, []string{"grant-late"}, grants)
	again, err := repo.RegisterTeammateKey(ctx, teammateKey("claim-c", 2), teammatePlacement)
	require.NoError(t, err, "a retry needs no live grant once its claim has the key")
	require.Equal(t, "key-claim-c", again.ID)
}
