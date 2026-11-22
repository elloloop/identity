package conformance

import (
	"context"
	"testing"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func runPasskeyProvenanceConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/PasskeyProvenanceRoundTrip", func(t *testing.T) {
		repo := driver.NewRepo(t)
		ctx := context.Background()
		user, err := repo.CreateUser(ctx, &service.User{Email: "owner@example.test", Status: service.StatusActive})
		require.NoError(t, err)
		for i, eligible := range []bool{false, true} {
			id := []string{"legacy-credential", "eligible-credential"}[i]
			_, err := repo.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{UserID: user, CredentialID: id, PublicKey: "public-key", ReauthenticationEligible: eligible})
			require.NoError(t, err)
			key, err := repo.GetPasskeyCredentialByCredID(ctx, id)
			require.NoError(t, err)
			require.Equal(t, eligible, key.ReauthenticationEligible)
			require.NoError(t, repo.UpdatePasskeyCredential(ctx, key.NodeID, map[string]any{"reauthentication_eligible": !eligible, "last_used_at": int64(100)}))
			key, err = repo.GetPasskeyCredentialByCredID(ctx, id)
			require.NoError(t, err)
			require.Equal(t, eligible, key.ReauthenticationEligible, "generic metadata edits cannot promote eligibility")
		}
		keys, err := repo.ListPasskeyCredentials(ctx, user)
		require.NoError(t, err)
		require.Len(t, keys, 2)
		record := &service.RefreshTokenRecord{UserID: user, TokenHash: "provenance-refresh", ExpiresAt: 3000, CreatedAt: 1000, AuthTimeMs: 1000, CredentialEnrollmentEligible: true, CredentialEnrollmentPasskeyID: "eligible-credential"}
		_, err = repo.CreateRefreshToken(ctx, record)
		require.NoError(t, err)
		read, err := repo.FindRefreshTokenByHash(ctx, record.TokenHash)
		require.NoError(t, err)
		require.True(t, read.CredentialEnrollmentEligible)
		require.Equal(t, record.CredentialEnrollmentPasskeyID, read.CredentialEnrollmentPasskeyID)
		verified, err := repo.GetPasskeyCredentialByCredID(ctx, "legacy-credential")
		require.NoError(t, err)
		wrong := *verified
		wrong.PublicKey = "other-public-key"
		updated, err := repo.MarkPasskeyReauthenticationEligible(ctx, &wrong)
		require.NoError(t, err)
		require.False(t, updated)
		if driver.BindProject != nil {
			other := driver.BindProject(t, repo, "other-key-project")
			updated, err := other.MarkPasskeyReauthenticationEligible(ctx, verified)
			require.NoError(t, err)
			require.False(t, updated)
		}
		updated, err = repo.MarkPasskeyReauthenticationEligible(ctx, verified)
		require.NoError(t, err)
		require.True(t, updated)
		current, err := repo.GetPasskeyCredentialByCredID(ctx, verified.CredentialID)
		require.NoError(t, err)
		require.True(t, current.ReauthenticationEligible)
		require.NoError(t, repo.DeletePasskeyCredential(ctx, user, verified.CredentialID))
		updated, err = repo.MarkPasskeyReauthenticationEligible(ctx, verified)
		require.NoError(t, err)
		require.False(t, updated)
		require.NoError(t, repo.ConsumeRefreshTokenByHash(ctx, record.TokenHash, 2000))
		read, err = repo.FindRefreshTokenByHashIncludingConsumed(ctx, record.TokenHash)
		require.NoError(t, err)
		require.True(t, read.CredentialEnrollmentEligible)
		require.Equal(t, record.CredentialEnrollmentPasskeyID, read.CredentialEnrollmentPasskeyID)
	})
}
