package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/repo/conformance"
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
	defer repo.Close()

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

	require.NoError(t, seedConformanceUsers(ctx, repo))
	conformance.RunConformance(t, func(t *testing.T) service.Repository {
		t.Helper()

		fresh, err := New(ctx, Config{
			DSN:         dsn,
			MaxConns:    5,
			ConnTimeout: 5 * time.Second,
			TenantID:    fmt.Sprintf("%s-conformance-%d", tenantID, time.Now().UnixNano()),
		})
		require.NoError(t, err)
		t.Cleanup(fresh.Close)
		return fresh
	})
}

func seedConformanceUsers(ctx context.Context, repo *pgRepository) error {
	now := time.Now().UnixMilli()
	_, err := repo.pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, name, role, status, created_at_ms, updated_at_ms)
		VALUES
			('u-1', $1, 'u-1@example.com', 'U One', 'member', 'active', $2, $2),
			('u-2', $1, 'u-2@example.com', 'U Two', 'member', 'active', $2, $2),
			('other', $1, 'other@example.com', 'Other', 'member', 'active', $2, $2)
		ON CONFLICT (id) DO NOTHING`,
		repo.tenantID, now)
	return err
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
			admin_help_requests,
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

func TestPostgres_DBAtomicQueriesAndEdges(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping postgres DB coverage test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))

	tenantID := fmt.Sprintf("db-tenant-%d", time.Now().UnixNano())
	repo, err := New(ctx, Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		TenantID:    tenantID,
	})
	require.NoError(t, err)
	defer repo.Close()

	userID := "db-user-1"
	groupID := "db-group-1"
	refreshID := "db-refresh-1"
	passkeyID := "db-passkey-1"
	qrID := "db-qr-1"
	createdAt := int64(1_700_000_000_000)

	result, err := repo.ExecuteAtomic(ctx, tenantID, "actor", "idem-1", []sdk.Operation{
		{
			Type:   sdk.OpCreateNode,
			TypeID: dbTypeUser,
			NodeID: userID,
			Data: map[string]any{
				dbUfEmail:            "db-user@example.com",
				dbUfName:             "DB User",
				dbUfRole:             "admin",
				dbUfAvatarURL:        "https://example.com/avatar.png",
				dbUfCreatedAt:        createdAt,
				dbUfUpdatedAt:        createdAt,
				dbUfPasswordHash:     "hash",
				dbUfTOTPRequired:     true,
				dbUfFailedLoginCount: int64(2),
				dbUfLockedUntil:      int64(3),
				dbUfStatus:           "active",
				dbUfRecoveryEmail:    "recover@example.com",
				dbUfInvitedBy:        "inviter",
				dbUfInvitedAt:        int64(4),
				dbUfQuotaBytes:       int64(1024),
				dbUfDeactivatedAt:    int64(0),
				dbUfLastLoginAt:      int64(5),
				dbUfEmailVerified:    true,
				dbUfEmailVerifiedAt:  int64(6),
			},
		},
		{
			Type:   sdk.OpCreateNode,
			TypeID: dbTypeWorkingGroup,
			NodeID: groupID,
			Data: map[string]any{
				dbGfName:        "Core Team",
				dbGfDescription: "Core product team",
				dbGfCreatedBy:   userID,
				dbGfCreatedAt:   createdAt,
				dbGfUpdatedAt:   createdAt,
			},
		},
		{
			Type:   sdk.OpCreateNode,
			TypeID: dbTypePasswordReset,
			NodeID: "db-reset-1",
			Data: map[string]any{
				dbPrfTokenHash: "reset-hash",
				dbPrfUserID:    userID,
				dbPrfExpiresAt: createdAt + 1000,
				dbPrfCreatedAt: createdAt,
			},
		},
		{
			Type:   sdk.OpCreateNode,
			TypeID: dbTypeInvitation,
			NodeID: "db-invitation-1",
			Data: map[string]any{
				dbInvTokenHash:  "inv-hash",
				dbInvEmail:      "invitee@example.com",
				dbInvUserID:     userID,
				dbInvInvitedBy:  userID,
				dbInvRole:       "member",
				dbInvExpiresAt:  createdAt + 1000,
				dbInvAcceptedAt: int64(0),
				dbInvCreatedAt:  createdAt,
			},
		},
		{
			Type:   sdk.OpCreateNode,
			TypeID: dbTypeAuditEvent,
			NodeID: "db-audit-1",
			Data: map[string]any{
				dbAfEventType:    "user.created",
				dbAfActorUserID:  userID,
				dbAfTargetUserID: userID,
				dbAfIPAddress:    "127.0.0.1",
				dbAfUserAgent:    "test-agent",
				dbAfSuccess:      true,
				dbAfDetails:      `{"source":"test"}`,
				dbAfCreatedAt:    createdAt,
			},
		},
		{
			Type:   sdk.OpCreateNode,
			TypeID: dbTypeAdminHelpReq,
			NodeID: "db-help-1",
			Data: map[string]any{
				dbHfEmail:      "help@example.com",
				dbHfReason:     "locked out",
				dbHfSourceIP:   "127.0.0.2",
				dbHfUserAgent:  "help-agent",
				dbHfStatus:     "pending",
				dbHfCreatedAt:  createdAt,
				dbHfResolvedAt: int64(0),
			},
		},
		{
			Type:       sdk.OpCreateEdge,
			EdgeTypeID: dbEdgeMemberOf,
			FromNodeID: userID,
			ToNodeID:   groupID,
		},
	})
	require.NoError(t, err)
	require.True(t, result.Success)
	require.ElementsMatch(t, []string{userID, groupID, "db-reset-1", "db-invitation-1", "db-audit-1", "db-help-1"}, result.CreatedNodeIDs)

	_, err = repo.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
		NodeID:     refreshID,
		TokenHash:  "refresh-hash",
		UserID:     userID,
		ExpiresAt:  createdAt + 2000,
		CreatedAt:  createdAt,
		LastUsedAt: createdAt,
		DeviceName: "laptop",
		IPAddress:  "127.0.0.3",
		UserAgent:  "refresh-agent",
	})
	require.NoError(t, err)
	_, err = repo.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{
		NodeID:       passkeyID,
		CredentialID: "passkey-lookup-id",
		UserID:       userID,
		PublicKey:    "public-key",
		SignCount:    1,
		DeviceName:   "security key",
		CreatedAt:    createdAt,
		LastUsedAt:   createdAt,
	})
	require.NoError(t, err)
	_, err = repo.CreateQrLoginSession(ctx, &service.QrLoginSessionRecord{
		NodeID:        qrID,
		SessionID:     "qr-session",
		Status:        "pending",
		UserID:        userID,
		NewDeviceInfo: "new device",
		ExpiresAt:     createdAt + 3000,
		CreatedAt:     createdAt,
		UpdatedAt:     createdAt,
	})
	require.NoError(t, err)

	userNode, err := repo.GetNode(ctx, tenantID, "actor", dbTypeUser, userID)
	require.NoError(t, err)
	require.Equal(t, "db-user@example.com", userNode.Payload[dbUfEmail])
	groupNode, err := repo.GetNode(ctx, tenantID, "actor", dbTypeWorkingGroup, groupID)
	require.NoError(t, err)
	require.Equal(t, "Core Team", groupNode.Payload[dbGfName])
	refreshNode, err := repo.GetNode(ctx, tenantID, "actor", dbTypeRefreshToken, refreshID)
	require.NoError(t, err)
	require.Equal(t, "refresh-hash", refreshNode.Payload[dbRfTokenHash])
	passkeyNode, err := repo.GetNode(ctx, tenantID, "actor", dbTypePasskey, passkeyID)
	require.NoError(t, err)
	require.Equal(t, "passkey-lookup-id", passkeyNode.Payload[dbPkfCredentialID])
	auditNode, err := repo.GetNode(ctx, tenantID, "actor", dbTypeAuditEvent, "db-audit-1")
	require.NoError(t, err)
	require.Equal(t, "user.created", auditNode.Payload[dbAfEventType])
	helpNode, err := repo.GetNode(ctx, tenantID, "actor", dbTypeAdminHelpReq, "db-help-1")
	require.NoError(t, err)
	require.Equal(t, "help@example.com", helpNode.Payload[dbHfEmail])

	requireQueryCount(ctx, t, repo, dbTypeUser, map[string]any{dbUfEmail: "DB-USER@EXAMPLE.COM", dbUfTOTPRequired: true, dbUfFailedLoginCount: int64(2)}, 1)
	requireQueryCount(ctx, t, repo, dbTypeWorkingGroup, map[string]any{dbGfName: "Core Team", dbGfCreatedAt: createdAt}, 1)
	requireQueryCount(ctx, t, repo, dbTypeRefreshToken, map[string]any{dbRfTokenHash: "refresh-hash", dbRfUserID: userID}, 1)
	requireQueryCount(ctx, t, repo, dbTypePasswordReset, map[string]any{dbPrfTokenHash: "reset-hash", dbPrfExpiresAt: createdAt + 1000}, 1)
	requireQueryCount(ctx, t, repo, dbTypePasskey, map[string]any{dbPkfCredentialID: "passkey-lookup-id", dbPkfDeviceName: "security key"}, 1)
	requireQueryCount(ctx, t, repo, dbTypeAuditEvent, map[string]any{dbAfEventType: "user.created", dbAfSuccess: true}, 1)
	requireQueryCount(ctx, t, repo, dbTypeAdminHelpReq, map[string]any{dbHfEmail: "HELP@EXAMPLE.COM", dbHfStatus: "pending"}, 1)

	foundUsers, err := repo.SearchNodes(ctx, tenantID, "actor", dbTypeUser, "db-user")
	require.NoError(t, err)
	require.Len(t, foundUsers, 1)
	foundGroups, err := repo.SearchNodes(ctx, tenantID, "actor", dbTypeWorkingGroup, "product")
	require.NoError(t, err)
	require.Len(t, foundGroups, 1)
	empty, err := repo.SearchNodes(ctx, tenantID, "actor", dbTypeUser, "   ")
	require.NoError(t, err)
	require.Nil(t, empty)

	edgesFrom, err := repo.GetEdgesFrom(ctx, tenantID, "actor", userID, dbEdgeMemberOf)
	require.NoError(t, err)
	require.Len(t, edgesFrom, 1)
	edgesTo, err := repo.GetEdgesTo(ctx, tenantID, "actor", groupID, dbEdgeMemberOf)
	require.NoError(t, err)
	require.Len(t, edgesTo, 1)
	otherEdges, err := repo.GetEdgesFrom(ctx, tenantID, "actor", userID, 999)
	require.NoError(t, err)
	require.Nil(t, otherEdges)

	_, err = repo.ExecuteAtomic(ctx, tenantID, "actor", "idem-2", []sdk.Operation{
		{Type: sdk.OpUpdateNode, TypeID: dbTypeUser, NodeID: userID, Patch: map[string]any{dbUfName: "DB User Updated", dbUfQuotaBytes: int64(2048)}},
		{Type: sdk.OpUpdateNode, TypeID: dbTypeWorkingGroup, NodeID: groupID, Patch: map[string]any{dbGfDescription: "Updated description"}},
		{Type: sdk.OpUpdateNode, TypeID: dbTypeAdminHelpReq, NodeID: "db-help-1", Patch: map[string]any{dbHfStatus: "resolved", dbHfResolvedBy: userID, dbHfResolvedAt: createdAt + 4000}},
		{Type: sdk.OpUpdateNode, TypeID: dbTypePasskey, NodeID: passkeyID, Patch: map[string]any{dbPkfDeviceName: "renamed key", dbPkfLastUsedAt: createdAt + 5000, "4": int64(2)}},
		{Type: sdk.OpUpdateNode, TypeID: dbTypeQrLoginSession, NodeID: qrID, Patch: map[string]any{"2": "approved", "3": userID, "7": "approved device", "8": createdAt + 6000, "10": createdAt + 7000}},
	})
	require.NoError(t, err)
	updatedUser, err := repo.GetUser(ctx, userID)
	require.NoError(t, err)
	require.Equal(t, "DB User Updated", updatedUser.Name)
	require.EqualValues(t, 2048, updatedUser.QuotaBytes)

	_, err = repo.ExecuteAtomic(ctx, tenantID, "actor", "idem-3", []sdk.Operation{
		{Type: sdk.OpDeleteEdge, EdgeTypeID: dbEdgeMemberOf, FromNodeID: userID, ToNodeID: groupID},
		{Type: sdk.OpDeleteNode, TypeID: dbTypePasskey, NodeID: passkeyID},
		{Type: sdk.OpDeleteNode, TypeID: dbTypeRefreshToken, NodeID: refreshID},
		{Type: sdk.OpDeleteNode, TypeID: dbTypeWorkingGroup, NodeID: groupID},
	})
	require.NoError(t, err)
	edgesAfterDelete, err := repo.GetEdgesFrom(ctx, tenantID, "actor", userID, dbEdgeMemberOf)
	require.NoError(t, err)
	require.Empty(t, edgesAfterDelete)

	_, err = repo.GetNode(ctx, tenantID, "actor", 999, "anything")
	require.Error(t, err)
	_, err = repo.QueryNodes(ctx, tenantID, "actor", 999, nil)
	require.Error(t, err)
	_, err = repo.SearchNodes(ctx, tenantID, "actor", 999, "anything")
	require.Error(t, err)
	_, err = repo.ExecuteAtomic(ctx, tenantID, "actor", "idem-4", []sdk.Operation{{Type: sdk.OpCreateNode, TypeID: 999}})
	require.Error(t, err)
}

func requireQueryCount(ctx context.Context, t *testing.T, repo *pgRepository, typeID int, filter map[string]any, want int) {
	t.Helper()

	nodes, err := repo.QueryNodes(ctx, repo.tenantID, "actor", typeID, filter)
	require.NoError(t, err)
	require.Len(t, nodes, want)
}
