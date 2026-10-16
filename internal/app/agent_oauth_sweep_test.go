package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type agentOAuthSweepProjects struct {
	ids []string
	err error
}

func (p agentOAuthSweepProjects) ListProjectIDs(context.Context) ([]string, error) {
	return p.ids, p.err
}

type unsupportedAgentOAuthSweep struct{ service.Repository }

func (r unsupportedAgentOAuthSweep) WithProject(string) service.Repository { return r }

type unavailableAgentOAuthSweep struct {
	service.Repository
	service.AgentOAuthRepository
	err error
}

func (r unavailableAgentOAuthSweep) WithProject(string) service.Repository { return r }

func (r unavailableAgentOAuthSweep) DeleteExpiredAgentAuthorizations(context.Context, int64, int) error {
	return r.err
}

func TestAgentOAuthSweepRetainsLiveRequestsAndDeletesExpiredRequests(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	liveID, _ := f.start(t)
	repo := f.repo.(service.AgentOAuthRepository)
	live, err := repo.GetAgentAuthorization(t.Context(), liveID)
	require.NoError(t, err)
	expired := live.Clone()
	expired.ID = "expired-native-request"
	expired.CreatedAtMs = time.Now().Add(-time.Hour).UnixMilli()
	expired.ExpiresAtMs = time.Now().Add(-time.Minute).UnixMilli()
	require.NoError(t, repo.CreateAgentAuthorization(t.Context(), expired))
	cfg := *f.cfg
	cfg.SweeperIntervalSeconds = 1
	cfg.SweeperBatchSize = 100
	cfg.SweeperGraceSeconds = 0
	built, err := New(Deps{
		Config: &cfg, Logger: zap.NewNop(), Repo: f.repo, DB: f.repo.(service.DB), Signer: f.signer,
		TOTPKey: []byte("01234567890123456789012345678901"), TOTPRecoveryPepper: []byte("offline-sweep-recovery-pepper-0123456789"),
	})
	require.NoError(t, err)
	built.Start()
	t.Cleanup(built.Stop)
	require.Eventually(t, func() bool {
		old, err := repo.GetAgentAuthorization(t.Context(), expired.ID)
		return err == nil && old == nil
	}, 10*time.Second, 10*time.Millisecond, "the actual app worker must sweep delegated authorization state")
	current, err := repo.GetAgentAuthorization(t.Context(), liveID)
	require.NoError(t, err)
	require.Equal(t, live, current)
	projects := agentOAuthSweepProjects{ids: []string{f.cfg.DefaultProjectID}}
	require.NoError(t, sweepAgentOAuth(t.Context(), f.repo, projects, f.cfg.DefaultProjectID, time.Now().UnixMilli(), 100))
	current, err = repo.GetAgentAuthorization(t.Context(), liveID)
	require.NoError(t, err)
	require.Equal(t, live, current)
}

func TestAgentOAuthSweepDoesNotHideProjectCapabilityOrStorageFailures(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	unavailable := errors.New("synthetic maintenance storage unavailable")
	err := sweepAgentOAuth(t.Context(), f.repo, agentOAuthSweepProjects{err: unavailable}, f.cfg.DefaultProjectID, 1, 100)
	require.ErrorIs(t, err, unavailable)
	err = sweepAgentOAuth(t.Context(), unsupportedAgentOAuthSweep{Repository: f.repo}, nil, f.cfg.DefaultProjectID, 1, 100)
	require.ErrorIs(t, err, service.ErrServiceUnavailable)
	err = sweepAgentOAuth(t.Context(), unavailableAgentOAuthSweep{Repository: f.repo, AgentOAuthRepository: f.repo.(service.AgentOAuthRepository), err: unavailable}, nil, f.cfg.DefaultProjectID, 1, 100)
	require.ErrorIs(t, err, unavailable)
}

func TestAgentOAuthStartupRejectsRepositoryWithoutDelegationCapability(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	built, err := New(Deps{
		Config: f.cfg, Logger: zap.NewNop(),
		Repo: unsupportedAgentOAuthSweep{Repository: f.repo}, DB: f.repo.(service.DB), Signer: f.signer,
		TOTPKey: []byte("01234567890123456789012345678901"), TOTPRecoveryPepper: []byte("offline-sweep-recovery-pepper-0123456789"),
	})
	require.ErrorContains(t, err, "delegated OAuth requires a supported durable repository")
	require.Nil(t, built, "no partially authenticated service can be exposed")
}
