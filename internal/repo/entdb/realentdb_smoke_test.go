//go:build realentdb

package entdb

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/repo/entdb/entclient"
	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func TestRealEntDBRepositorySmoke(t *testing.T) {
	addr := os.Getenv("GATEWAY_ENTDB_ADDRESS")
	if addr == "" {
		t.Skip("GATEWAY_ENTDB_ADDRESS unset - skipping real EntDB repository smoke")
	}

	client, err := entclient.New(addr)
	require.NoError(t, err)
	require.NoError(t, client.Connect(context.Background()))
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tenantID := fmt.Sprintf("realentdb-smoke-%d", time.Now().UnixNano())
	ensureRealEntDBTenant(t, client, tenantID)
	repo := NewRepository(client, tenantID)
	now := time.Now()
	userID, err := repo.CreateUser(ctx, &service.User{
		Email:        "realentdb@example.com",
		Name:         "Real EntDB",
		Role:         "member",
		Status:       "active",
		PasswordHash: "hash",
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	require.NoError(t, err)
	require.NotEmpty(t, userID)

	byEmail, err := repo.FindUserByEmail(ctx, "realentdb@example.com")
	require.NoError(t, err)
	require.NotNil(t, byEmail)
	require.Equal(t, userID, byEmail.ID)

	byID, err := repo.GetUser(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, byID)
	require.Equal(t, "hash", byID.PasswordHash)

	require.NoError(t, repo.UpdateUser(ctx, userID, map[string]any{
		"name":           "Renamed EntDB",
		"avatar_url":     "https://example.com/avatar.png",
		"recovery_email": "recover@example.com",
	}))
	updated, err := repo.GetUser(ctx, userID)
	require.NoError(t, err)
	require.Equal(t, "Renamed EntDB", updated.Name)

	refreshID, err := repo.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
		TokenHash:  "real-refresh",
		UserID:     userID,
		ExpiresAt:  now.Add(time.Hour).UnixMilli(),
		CreatedAt:  now.UnixMilli(),
		LastUsedAt: now.UnixMilli(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, refreshID)
	refresh, err := repo.FindRefreshTokenByHash(ctx, "real-refresh")
	require.NoError(t, err)
	require.NotNil(t, refresh)
	require.NoError(t, repo.ConsumeRefreshTokenByHash(ctx, "real-refresh", now.Add(time.Minute).UnixMilli()))

	passkeyID, err := repo.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{
		CredentialID: "real-cred",
		UserID:       userID,
		PublicKey:    "public-key",
		SignCount:    1,
		DeviceName:   "security key",
		CreatedAt:    now.UnixMilli(),
		LastUsedAt:   now.UnixMilli(),
	})
	require.NoError(t, err)
	require.NoError(t, repo.UpdatePasskeyCredential(ctx, passkeyID, map[string]any{
		"device_name":  "renamed key",
		"sign_count":   int64(2),
		"last_used_at": now.Add(time.Minute).UnixMilli(),
	}))
	passkeys, err := repo.ListPasskeyCredentials(ctx, userID)
	require.NoError(t, err)
	require.Len(t, passkeys, 1)

	challengeID, err := repo.CreatePasskeyChallenge(ctx, &service.PasskeyChallengeRecord{
		Challenge:     "challenge",
		UserID:        userID,
		ChallengeType: "registration",
		ExpiresAt:     now.Add(time.Hour).UnixMilli(),
	})
	require.NoError(t, err)
	challenge, err := repo.GetPasskeyChallenge(ctx, challengeID)
	require.NoError(t, err)
	require.NotNil(t, challenge)
	require.NoError(t, repo.DeletePasskeyChallenge(ctx, challengeID))

	totpID, err := repo.CreateTotpCredential(ctx, &service.TotpCredRecord{
		UserID:          userID,
		SecretEncrypted: "secret",
		CreatedAt:       now.UnixMilli(),
	})
	require.NoError(t, err)
	require.NoError(t, repo.UpdateTotpCredential(ctx, totpID, map[string]any{"verified": true}))
	totp, err := repo.GetTotpCredential(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, totp)

	require.NoError(t, repo.DeleteRefreshToken(ctx, refreshID))
	require.NoError(t, repo.DeleteTotpCredential(ctx, totpID))
}
