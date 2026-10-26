package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/jwt"
)

func TestAgentStanding_InheritsOwnerEmailVerification(t *testing.T) {
	f := newAgentFixture(t)
	f.svc.cfg.AuthRequireVerifiedEmail = true
	f.svc.cfg.RevocationMode = config.RevocationModeSession
	agent := seedAgent(f.repo, f.owner.ID)
	ctx := context.Background()

	access, refresh, err := f.svc.issueTokensWithSessionStart(ctx, agent, "", "", sessionGateRefresh, 0, 0, "")
	require.ErrorIs(t, err, ErrEmailVerificationRequired)
	assert.Empty(t, access)
	assert.Empty(t, refresh)
	assert.False(t, liveSessions(f.repo, agent.ID))

	f.repo.mu.Lock()
	f.repo.users[f.owner.ID].EmailVerified = true
	f.repo.mu.Unlock()
	access, refresh = issueAgentTokens(t, f, agent)
	claims, err := jwt.VerifyAccessToken(access, f.svc.signer, "", "", false)
	require.NoError(t, err)
	require.NotEmpty(t, claims.SID)

	f.repo.mu.Lock()
	f.repo.users[f.owner.ID].EmailVerified = false
	f.repo.mu.Unlock()
	for range 2 {
		_, access, rotated, refreshErr := f.svc.RefreshToken(ctx, refresh, "", "", "")
		require.ErrorIs(t, refreshErr, ErrEmailVerificationRequired)
		assert.Empty(t, access)
		assert.Empty(t, rotated)
		assert.True(t, sessionRevoked(t, f.repo, claims.SID))
	}

	f.repo.mu.Lock()
	f.repo.users[f.owner.ID].EmailVerified = true
	f.repo.mu.Unlock()
	_, _, rotated, err := f.svc.RefreshToken(ctx, refresh, "", "", "")
	require.NoError(t, err)
	assert.NotEqual(t, refresh, rotated)
}

func TestAgentSignIn_PrecedesEmailVerification(t *testing.T) {
	f := newAgentFixture(t)
	f.svc.cfg.AuthRequireVerifiedEmail = true
	agent := seedUser(f.repo, "unproven-agent@example.com", "", StatusActive)
	forceAgent(f.repo, agent, f.owner.ID)

	_, _, err := f.svc.issueTokens(context.Background(), agent, "", "")
	requireAgentSignInRefusal(t, f.repo, err, agent.ID)
	assert.Zero(t, f.writer.countByEventType("login_failure"))
}
