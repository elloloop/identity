package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/config"
)

type machineRefusalRepo struct {
	*machineFailureRepo
	sessionErr      error
	sessionOverride *SessionRecord
	sessionNil      bool
	otherSessions   map[string]*SessionRecord
	revokeNotFound  bool
	challengeErr    error
}

func (r *machineRefusalRepo) WithProject(projectID string) Repository {
	if r.otherSessions != nil && projectID != "" && projectID != "default" {
		return &machineProjectViewRepo{machineRefusalRepo: r, projectID: projectID}
	}
	return r
}

func (r *machineRefusalRepo) GetSessionBySid(ctx context.Context, sid string) (*SessionRecord, error) {
	if r.sessionErr != nil {
		return nil, r.sessionErr
	}
	if r.sessionNil {
		return nil, nil
	}
	if r.sessionOverride != nil {
		return r.sessionOverride, nil
	}
	return r.machineFailureRepo.GetSessionBySid(ctx, sid)
}

func (r *machineRefusalRepo) MutateAgentMachine(ctx context.Context, id string, m AgentMachineMutation) (*AgentMachine, error) {
	if r.revokeNotFound {
		return nil, ErrNotFound
	}
	return r.machineFailureRepo.MutateAgentMachine(ctx, id, m)
}

func (r *machineRefusalRepo) CreateAgentMachineChallenge(ctx context.Context, c *AgentMachineChallenge) error {
	if r.challengeErr != nil {
		return r.challengeErr
	}
	return r.machineFailureRepo.CreateAgentMachineChallenge(ctx, c)
}

type machineProjectViewRepo struct {
	*machineRefusalRepo
	projectID string
}

func (v *machineProjectViewRepo) GetSessionBySid(_ context.Context, _ string) (*SessionRecord, error) {
	if rec, ok := v.otherSessions[v.projectID]; ok {
		return rec, nil
	}
	return nil, nil
}

func newObservedMachineService(t *testing.T) (*AgentOAuthService, *machineRefusalRepo, *observer.ObservedLogs) {
	t.Helper()
	oauth, baseRepo, _ := machineFailureFixture(t)
	core, logs := observer.New(zapcore.WarnLevel)
	oauth.auth.logger = zap.New(core)
	oauth.auth.cfg.DefaultProjectID = "default"
	for i := range oauth.resources {
		oauth.resources[i].ProjectID = "default"
	}
	wrapped := &machineRefusalRepo{machineFailureRepo: baseRepo}
	oauth.base = wrapped
	oauth.auth.defaultRepo = wrapped
	return oauth, wrapped, logs
}

func assertLastRPCRefusal(t *testing.T, logs *observer.ObservedLogs, wantReason string) map[string]any {
	t.Helper()
	entries := logs.FilterMessage("rpc_refused").All()
	require.NotEmpty(t, entries, "expected rpc_refused log for reason %s", wantReason)
	last := entries[len(entries)-1]
	fields := last.ContextMap()
	assert.Equal(t, wantReason, fields["reason"])
	assert.Contains(t, fields, "host")
	assert.Contains(t, fields, "request_project_id")
	return fields
}

func TestAgentMachineRefusals_HumanSessionAndStepUpReasons(t *testing.T) {
	t.Parallel()

	t.Run("unauthenticated", func(t *testing.T) {
		t.Parallel()
		oauth, _, logs := newObservedMachineService(t)
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{ProjectID: "proj-req"}), "auth.example.com")

		_, err := oauth.RegisterMachine(ctx, AgentOAuthHuman{}, AgentMachineRegistration{})
		require.ErrorIs(t, err, ErrAgentOAuthReauthenticationRequired)

		fields := assertLastRPCRefusal(t, logs, ReasonUnauthenticated)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, "proj-req", fields["request_project_id"])
	})

	t.Run("sign_in_not_recent", func(t *testing.T) {
		t.Parallel()
		oauth, repo, logs := newObservedMachineService(t)
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{ProjectID: "proj-req"}), "auth.example.com")

		staleHuman := AgentOAuthHuman{
			UserID:   repo.authority.Owner.ID,
			SID:      repo.authority.HumanSession.SID,
			AuthTime: oauth.auth.nowMs()/1000 - int64(config.AgentOAuthRecentSignIn.Seconds()) - 120,
		}
		_, err := oauth.RegisterMachine(ctx, staleHuman, AgentMachineRegistration{})
		require.ErrorIs(t, err, ErrAgentOAuthReauthenticationRequired)

		fields := assertLastRPCRefusal(t, logs, ReasonSignInNotRecent)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, "proj-req", fields["request_project_id"])
		assert.Equal(t, repo.authority.Owner.ID, fields["user_id"])
		assert.Equal(t, repo.authority.HumanSession.SID, fields["session_id"])
		assert.Greater(t, fields["auth_time_age_s"], int64(config.AgentOAuthRecentSignIn.Seconds()))
		assert.EqualValues(t, int64(config.AgentOAuthRecentSignIn.Seconds()), fields["max_age_s"])
	})

	t.Run("session_lookup_failed", func(t *testing.T) {
		t.Parallel()
		oauth, repo, logs := newObservedMachineService(t)
		repo.sessionErr = errMachineStoreUnavailable
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{ProjectID: "default", Access: ProjectAccessConfig{Mode: AccessModeOpen}}), "auth.example.com")

		human := AgentOAuthHuman{
			UserID:   repo.authority.Owner.ID,
			SID:      repo.authority.HumanSession.SID,
			AuthTime: oauth.auth.nowMs() / 1000,
		}
		err := oauth.RevokeMachine(ctx, human, repo.stale.ID)
		require.ErrorIs(t, err, errMachineStoreUnavailable)

		fields := assertLastRPCRefusal(t, logs, ReasonSessionLookupFailed)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, "default", fields["request_project_id"])
		assert.Equal(t, repo.authority.Owner.ID, fields["user_id"])
		assert.Equal(t, repo.authority.HumanSession.SID, fields["session_id"])
	})

	t.Run("session_revoked", func(t *testing.T) {
		t.Parallel()
		oauth, repo, logs := newObservedMachineService(t)
		revoked := *repo.authority.HumanSession
		revoked.RevokedAtMs = 999
		repo.sessionOverride = &revoked
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{ProjectID: "default", Access: ProjectAccessConfig{Mode: AccessModeOpen}}), "auth.example.com")

		human := AgentOAuthHuman{
			UserID:   repo.authority.Owner.ID,
			SID:      repo.authority.HumanSession.SID,
			AuthTime: oauth.auth.nowMs() / 1000,
		}
		err := oauth.RevokeMachine(ctx, human, repo.stale.ID)
		require.ErrorIs(t, err, ErrAgentOAuthReauthenticationRequired)

		fields := assertLastRPCRefusal(t, logs, ReasonSessionRevoked)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, "default", fields["request_project_id"])
		assert.Equal(t, repo.authority.Owner.ID, fields["user_id"])
		assert.Equal(t, repo.authority.HumanSession.SID, fields["session_id"])
	})

	t.Run("session_project_mismatch", func(t *testing.T) {
		t.Parallel()
		oauth, repo, logs := newObservedMachineService(t)
		repo.otherSessions = map[string]*SessionRecord{}
		ctx := WithRefusalInfo(t.Context(), &RefusalInfo{ProjectID: "default"})
		ctx = WithRequestHost(WithProjectScope(ctx, &ProjectScope{ProjectID: "proj-other"}), "other.example.com")

		human := AgentOAuthHuman{
			UserID:   repo.authority.Owner.ID,
			SID:      repo.authority.HumanSession.SID,
			AuthTime: oauth.auth.nowMs() / 1000,
		}
		_, err := oauth.RegisterMachine(ctx, human, AgentMachineRegistration{})
		require.ErrorIs(t, err, ErrAgentOAuthReauthenticationRequired)

		fields := assertLastRPCRefusal(t, logs, ReasonSessionProjectMismatch)
		assert.Equal(t, "other.example.com", fields["host"])
		assert.Equal(t, "proj-other", fields["request_project_id"])
		assert.Equal(t, "default", fields["project_id"])
		assert.Equal(t, repo.authority.Owner.ID, fields["user_id"])
		assert.Equal(t, repo.authority.HumanSession.SID, fields["session_id"])
	})
}

func TestAgentMachineRefusals_MachineChallengeSignatureAndKeyReasons(t *testing.T) {
	t.Parallel()

	t.Run("machine_not_found", func(t *testing.T) {
		t.Parallel()
		oauth, repo, logs := newObservedMachineService(t)
		repo.authority.Machine = nil
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{ProjectID: "default", Access: ProjectAccessConfig{Mode: AccessModeOpen}}), "auth.example.com")

		_, err := oauth.CreateMachineChallenge(ctx, AgentMachineChallengeRequest{
			MachineID: repo.stale.ID,
			Operation: AgentMachineRoster,
		})
		require.ErrorIs(t, err, ErrUnauthenticated)

		fields := assertLastRPCRefusal(t, logs, ReasonMachineNotFound)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, "default", fields["request_project_id"])

		repo.revokeNotFound = true
		human := AgentOAuthHuman{
			UserID:   repo.authority.Owner.ID,
			SID:      repo.authority.HumanSession.SID,
			AuthTime: oauth.auth.nowMs() / 1000,
		}
		err = oauth.RevokeMachine(ctx, human, repo.stale.ID)
		require.ErrorIs(t, err, ErrNotFound)
		assertLastRPCRefusal(t, logs, ReasonMachineNotFound)

		// Also verify 403 from repo.CreateAgentMachineChallenge when the machine row is absent in the locked write path.
		oauthStore, repoStore, logsStore := newObservedMachineService(t)
		repoStore.challengeErr = errors.Join(ErrAgentOAuthGrant, ErrNotFound)
		info := &RefusalInfo{}
		ctxStore := WithRefusalInfo(WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{ProjectID: "proj-challenge", Access: ProjectAccessConfig{Mode: AccessModeOpen}}), "accounts.glassa.ai"), info)
		for i := range oauthStore.resources {
			oauthStore.resources[i].ProjectID = "proj-challenge"
		}
		_, err = oauthStore.CreateMachineChallenge(ctxStore, AgentMachineChallengeRequest{
			MachineID: repoStore.stale.ID,
			Operation: AgentMachineRoster,
		})
		require.ErrorIs(t, err, ErrAgentOAuthGrant)
		storeFields := assertLastRPCRefusal(t, logsStore, ReasonMachineNotFound)
		assert.Equal(t, "accounts.glassa.ai", storeFields["host"])
		assert.Equal(t, "proj-challenge", storeFields["request_project_id"])
		assert.Equal(t, "proj-challenge", storeFields["project_id"])
		assert.Equal(t, ReasonMachineNotFound, info.Reason)
		assert.Equal(t, "proj-challenge", info.RequestProjectID)
		assert.Equal(t, "proj-challenge", info.ProjectID)
	})

	t.Run("machine_revoked", func(t *testing.T) {
		t.Parallel()
		oauth, repo, logs := newObservedMachineService(t)
		repo.authority.Machine.RevokedAtMs = 500
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{ProjectID: "default", Access: ProjectAccessConfig{Mode: AccessModeOpen}}), "auth.example.com")

		_, err := oauth.CreateMachineChallenge(ctx, AgentMachineChallengeRequest{
			MachineID: repo.stale.ID,
			Operation: AgentMachineRoster,
		})
		require.ErrorIs(t, err, ErrAgentOAuthGrant)

		fields := assertLastRPCRefusal(t, logs, ReasonMachineRevoked)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, "default", fields["request_project_id"])
		assert.Equal(t, repo.stale.OwnerID, fields["user_id"])

		// Also verify 403 from repo.CreateAgentMachineChallenge when the machine is revoked in the locked write path.
		oauthStore, repoStore, logsStore := newObservedMachineService(t)
		repoStore.challengeErr = ErrAgentOAuthGrant
		info := &RefusalInfo{}
		ctxStore := WithRefusalInfo(WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{ProjectID: "proj-challenge", Access: ProjectAccessConfig{Mode: AccessModeOpen}}), "accounts.glassa.ai"), info)
		for i := range oauthStore.resources {
			oauthStore.resources[i].ProjectID = "proj-challenge"
		}
		_, err = oauthStore.CreateMachineChallenge(ctxStore, AgentMachineChallengeRequest{
			MachineID: repoStore.stale.ID,
			Operation: AgentMachineRoster,
		})
		require.ErrorIs(t, err, ErrAgentOAuthGrant)
		storeFields := assertLastRPCRefusal(t, logsStore, ReasonMachineRevoked)
		assert.Equal(t, "accounts.glassa.ai", storeFields["host"])
		assert.Equal(t, "proj-challenge", storeFields["request_project_id"])
		assert.Equal(t, "proj-challenge", storeFields["project_id"])
		assert.Equal(t, ReasonMachineRevoked, info.Reason)
		assert.Equal(t, "proj-challenge", info.RequestProjectID)
		assert.Equal(t, "proj-challenge", info.ProjectID)
	})

	t.Run("challenge_expired", func(t *testing.T) {
		t.Parallel()
		oauth, repo, logs := newObservedMachineService(t)
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{ProjectID: "default", Access: ProjectAccessConfig{Mode: AccessModeOpen}}), "auth.example.com")

		req := AgentMachineChallengeRequest{
			MachineID: repo.stale.ID,
			Operation: AgentMachineRoster,
		}
		proof := machineRequestProof(t, oauth, repo.machineFailureRepo, req)
		repo.challenge.ExpiresAtMs = oauth.auth.nowMs() - 1

		_, err := oauth.MachineAgents(ctx, repo.stale.ID, proof, 0)
		require.ErrorIs(t, err, ErrUnauthenticated)

		fields := assertLastRPCRefusal(t, logs, ReasonChallengeExpired)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, "default", fields["request_project_id"])
	})

	t.Run("signature_invalid", func(t *testing.T) {
		t.Parallel()
		oauth, repo, logs := newObservedMachineService(t)
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{ProjectID: "default", Access: ProjectAccessConfig{Mode: AccessModeOpen}}), "auth.example.com")

		public, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		agentKey := hex.EncodeToString(public)

		req := AgentMachineChallengeRequest{
			MachineID: repo.stale.ID,
			AgentID:   repo.authority.Agent.ID,
			Operation: AgentMachineEnroll,
			PublicKey: agentKey,
		}
		proof := machineRequestProof(t, oauth, repo.machineFailureRepo, req)
		proof.Signature[0] ^= 0xFF
		sigHex := hex.EncodeToString(proof.Signature)

		_, err = oauth.RegisterMachineAgentKey(ctx, req.MachineID, req.AgentID, agentKey, proof)
		require.ErrorIs(t, err, ErrUnauthenticated)

		fields := assertLastRPCRefusal(t, logs, ReasonSignatureInvalid)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, "default", fields["request_project_id"])
		for k, v := range fields {
			assert.NotContains(t, fmt.Sprint(v), sigHex, "field %s must not contain signature bytes", k)
		}
	})

	t.Run("key_invalid", func(t *testing.T) {
		t.Parallel()
		oauth, repo, logs := newObservedMachineService(t)
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{ProjectID: "default", Access: ProjectAccessConfig{Mode: AccessModeOpen}}), "auth.example.com")

		badKey := "not-a-valid-ed25519-hex-key-secret"
		_, err := oauth.CreateMachineChallenge(ctx, AgentMachineChallengeRequest{
			MachineID: repo.stale.ID,
			AgentID:   repo.authority.Agent.ID,
			Operation: AgentMachineEnroll,
			PublicKey: badKey,
		})
		require.ErrorIs(t, err, ErrInvalidArgument)

		fields := assertLastRPCRefusal(t, logs, ReasonKeyInvalid)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, "default", fields["request_project_id"])
		for k, v := range fields {
			assert.NotContains(t, fmt.Sprint(v), badKey, "field %s must not contain raw public key input", k)
		}
	})
}
