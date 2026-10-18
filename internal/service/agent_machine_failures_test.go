package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var errMachineStoreUnavailable = errors.New("machine store unavailable")

type machineFailureRepo struct {
	*machineAdmissionRepo
	fail            string
	authorityCalls  int
	authorityFailAt int
	consumed        int
}

func (r *machineFailureRepo) WithProject(string) Repository { return r }
func (r *machineFailureRepo) AgentMachineAuthority(ctx context.Context, id, agent string) (AgentOAuthAuthority, error) {
	r.authorityCalls++
	if r.fail == "authority" || r.authorityCalls == r.authorityFailAt {
		return AgentOAuthAuthority{}, errMachineStoreUnavailable
	}
	return r.machineAdmissionRepo.AgentMachineAuthority(ctx, id, agent)
}

func (r *machineFailureRepo) GetAgentMachineDelegation(context.Context, string, string) (*AgentAuthorization, error) {
	if r.fail == "delegation" {
		return nil, errMachineStoreUnavailable
	}
	return nil, nil
}

func (r *machineFailureRepo) CreateAgentMachineChallenge(ctx context.Context, c *AgentMachineChallenge) error {
	if r.fail == "create" {
		return errMachineStoreUnavailable
	}
	return r.machineAdmissionRepo.CreateAgentMachineChallenge(ctx, c)
}

func (r *machineFailureRepo) GetAgentMachineChallenge(ctx context.Context, id string) (*AgentMachineChallenge, error) {
	if r.fail == "read" {
		return nil, errMachineStoreUnavailable
	}
	if r.fail == "missing" {
		return nil, nil
	}
	return r.machineAdmissionRepo.GetAgentMachineChallenge(ctx, id)
}

func (r *machineFailureRepo) ConsumeAgentMachineChallenge(ctx context.Context, id string, now int64) (bool, error) {
	if r.fail == "consume" {
		return false, errMachineStoreUnavailable
	}
	if r.fail == "spent" {
		return false, nil
	}
	r.consumed++
	return r.machineAdmissionRepo.ConsumeAgentMachineChallenge(ctx, id, now)
}

func (r *machineFailureRepo) EnsureAgentMachineDelegation(ctx context.Context, id string, grant *AgentAuthorization, key, fingerprint string) (*AgentAuthorization, error) {
	if r.fail == "enroll" {
		return nil, errMachineStoreUnavailable
	}
	if r.fail == "revoked" {
		copy := grant.Clone()
		copy.RevokedAtMs = copy.CreatedAtMs
		return copy, nil
	}
	return r.machineAdmissionRepo.EnsureAgentMachineDelegation(ctx, id, grant, key, fingerprint)
}

func (r *machineFailureRepo) MutateAgentMachine(_ context.Context, _ string, m AgentMachineMutation) (*AgentMachine, error) {
	if r.fail == "invalidate" {
		return nil, errMachineStoreUnavailable
	}
	current := r.authority.Machine.Clone()
	current.RevokedAtMs = m.AtMs
	r.authority.Machine = current
	return current, nil
}

func (r *machineFailureRepo) ListUsers(ctx context.Context, filter UserListFilter) ([]*User, error) {
	if r.fail == "users" {
		return nil, errMachineStoreUnavailable
	}
	return r.machineAdmissionRepo.ListUsers(ctx, filter)
}

func machineFailureFixture(t *testing.T) (*AgentOAuthService, *machineFailureRepo, AgentMachineProof) {
	t.Helper()
	oauth, repo, proof := machineAdmissionFixture(t)
	wrapped := &machineFailureRepo{machineAdmissionRepo: repo}
	oauth.base = wrapped
	oauth.auth.defaultRepo = wrapped
	return oauth, wrapped, proof
}

func machineRequestProof(t *testing.T, oauth *AgentOAuthService, repo *machineFailureRepo, request AgentMachineChallengeRequest) AgentMachineProof {
	t.Helper()
	c, err := oauth.CreateMachineChallenge(t.Context(), request)
	require.NoError(t, err)
	return AgentMachineProof{ChallengeID: c.ID, Signature: ed25519.Sign(repo.engineKey, []byte(c.Message))}
}

func TestMachineStorageFailuresNeverReleaseRosterOrConsumeAnUnreadProof(t *testing.T) {
	for _, stage := range []string{"authority", "read", "missing", "consume", "spent", "users"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			oauth, repo, proof := machineFailureFixture(t)
			repo.fail = stage
			result, err := oauth.MachineAgents(t.Context(), repo.stale.ID, proof, 0)
			require.Error(t, err)
			require.Nil(t, result)
			if stage != "users" {
				require.Zero(t, repo.consumed)
			}
			if stage == "authority" || stage == "read" || stage == "consume" || stage == "users" {
				require.ErrorIs(t, err, errMachineStoreUnavailable)
			}
		})
	}
}

func TestMachineChallengeFailuresPreserveCurrentAuthorityChecks(t *testing.T) {
	t.Parallel()
	oauth, repo, _ := machineFailureFixture(t)
	request := AgentMachineChallengeRequest{MachineID: repo.stale.ID, Operation: AgentMachineRoster}
	repo.fail = "create"
	_, err := oauth.CreateMachineChallenge(t.Context(), request)
	require.ErrorIs(t, err, errMachineStoreUnavailable)
	repo.fail = ""
	_, _, err = oauth.currentMachine(t.Context(), "invalid/id", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
	repo.authority.Machine = nil
	_, err = oauth.CreateMachineChallenge(t.Context(), request)
	require.ErrorIs(t, err, ErrUnauthenticated)
}

func TestMachineMissingOrUnavailableAgentKeyNeverFallsBackToEngine(t *testing.T) {
	for _, stage := range []string{"delegation", "missing delegation"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			oauth, repo, _ := machineFailureFixture(t)
			repo.fail = stage
			_, err := oauth.CreateMachineChallenge(t.Context(), AgentMachineChallengeRequest{MachineID: repo.stale.ID, AgentID: repo.authority.Agent.ID, Operation: AgentMachineExchange})
			require.Error(t, err)
			if stage == "delegation" {
				require.ErrorIs(t, err, errMachineStoreUnavailable)
			} else {
				require.ErrorIs(t, err, ErrAgentOAuthGrant)
			}
		})
	}
}

func TestMachineEnrollmentStoreFailureOrRevocationNeverReturnsNewGrant(t *testing.T) {
	for _, stage := range []string{"enroll", "revoked"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			oauth, repo, _ := machineFailureFixture(t)
			public, _, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			request := AgentMachineChallengeRequest{MachineID: repo.stale.ID, AgentID: repo.authority.Agent.ID, Operation: AgentMachineEnroll, PublicKey: hex.EncodeToString(public)}
			proof := machineRequestProof(t, oauth, repo, request)
			repo.fail = stage
			grant, err := oauth.RegisterMachineAgentKey(t.Context(), request.MachineID, request.AgentID, request.PublicKey, proof)
			require.Error(t, err)
			require.Nil(t, grant)
			if stage == "enroll" {
				require.ErrorIs(t, err, errMachineStoreUnavailable)
			} else {
				require.ErrorIs(t, err, ErrAgentOAuthGrant)
			}
		})
	}
}

func TestMachineResourceRemovalRevokesWithoutPublishingAuthority(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "persisted", true: "unavailable"}[fail], func(t *testing.T) {
			t.Parallel()
			oauth, repo, proof := machineFailureFixture(t)
			oauth.resources = nil
			if fail {
				repo.fail = "invalidate"
			}
			result, err := oauth.MachineAgents(t.Context(), repo.stale.ID, proof, 0)
			require.Nil(t, result)
			if fail {
				require.ErrorIs(t, err, errMachineStoreUnavailable)
			} else {
				require.ErrorIs(t, err, ErrAgentOAuthGrant)
				require.NotZero(t, repo.authority.Machine.RevokedAtMs)
			}
			require.Zero(t, repo.consumed)
		})
	}
}

func TestMachineControlReadsRefuseAuthorityLossAfterProofConsumption(t *testing.T) {
	for _, operation := range []string{AgentMachineRoster, AgentMachineInspect} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			oauth, repo, _ := machineFailureFixture(t)
			proof := machineRequestProof(t, oauth, repo, AgentMachineChallengeRequest{MachineID: repo.stale.ID, Operation: operation})
			repo.authorityCalls = 0
			repo.authorityFailAt = 2
			if operation == AgentMachineRoster {
				result, err := oauth.MachineAgents(t.Context(), repo.stale.ID, proof, 0)
				require.Nil(t, result)
				require.ErrorIs(t, err, errMachineStoreUnavailable)
			} else {
				result, err := oauth.IntrospectMachine(t.Context(), repo.stale.Resource, repo.stale.ID, proof)
				require.Nil(t, result)
				require.ErrorIs(t, err, errMachineStoreUnavailable)
			}
			require.Equal(t, 1, repo.consumed)
		})
	}
}

func TestDisabledMachineRegistryRefusesEveryEntryPoint(t *testing.T) {
	t.Parallel()
	oauth, _, _ := machineFailureFixture(t)
	oauth.auth.cfg.AgentMachineEnabled = false
	_, err := oauth.RegisterMachine(t.Context(), AgentOAuthHuman{}, AgentMachineRegistration{})
	require.ErrorIs(t, err, ErrAgentOAuthDisabled)
	_, err = oauth.ListMachines(t.Context(), AgentOAuthHuman{}, "", 0)
	require.ErrorIs(t, err, ErrAgentOAuthDisabled)
	_, err = oauth.SelectMachineAgents(t.Context(), AgentOAuthHuman{}, "machine", 1, true, nil, nil)
	require.ErrorIs(t, err, ErrAgentOAuthDisabled)
	require.ErrorIs(t, oauth.RevokeMachine(t.Context(), AgentOAuthHuman{}, "machine"), ErrAgentOAuthDisabled)
	_, err = oauth.CreateMachineChallenge(t.Context(), AgentMachineChallengeRequest{MachineID: "machine", Operation: AgentMachineRoster})
	require.ErrorIs(t, err, ErrAgentOAuthDisabled)
}

func (r *machineFailureRepo) GetUser(context.Context, string) (*User, error) {
	return r.authority.Owner, nil
}

func (r *machineFailureRepo) GetSessionBySid(context.Context, string) (*SessionRecord, error) {
	return r.authority.HumanSession, nil
}

func (r *machineFailureRepo) GetOAuthClient(context.Context, string) (*OAuthClient, error) {
	if r.fail == "client" {
		return nil, errMachineStoreUnavailable
	}
	return r.authority.Client, nil
}

func TestMachineHumanControlRefusesInvalidRequestsAndUnavailableClient(t *testing.T) {
	t.Parallel()
	oauth, repo, _ := machineFailureFixture(t)
	human := AgentOAuthHuman{UserID: repo.authority.Owner.ID, SID: repo.authority.HumanSession.SID, AuthTime: time.Now().Unix()}
	_, err := oauth.ListMachines(t.Context(), human, "", -1)
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, err = oauth.SelectMachineAgents(t.Context(), human, "invalid/id", 1, true, nil, nil)
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorIs(t, oauth.RevokeMachine(t.Context(), human, "invalid/id"), ErrInvalidArgument)
	_, err = oauth.RegisterMachine(t.Context(), AgentOAuthHuman{}, AgentMachineRegistration{})
	require.ErrorIs(t, err, ErrAgentOAuthReauthenticationRequired)
	repo.fail = "client"
	_, err = oauth.RegisterMachine(t.Context(), human, AgentMachineRegistration{ClientID: repo.authority.Client.ID})
	require.ErrorIs(t, err, errMachineStoreUnavailable)
	repo.fail = ""
	_, err = oauth.RegisterMachine(t.Context(), human, AgentMachineRegistration{ClientID: repo.authority.Client.ID, Resource: "https://unregistered.example.test", Scopes: repo.stale.Scopes})
	require.Error(t, err)
}

func TestMachineChallengeCreationRejectsMalformedBindingAndUnselectedAgent(t *testing.T) {
	t.Parallel()
	oauth, repo, _ := machineFailureFixture(t)
	_, err := oauth.CreateMachineChallenge(t.Context(), AgentMachineChallengeRequest{MachineID: "invalid/id", Operation: AgentMachineInspect})
	require.ErrorIs(t, err, ErrInvalidArgument)
	repo.authority.Agent.OwnerUserID = "another-owner"
	_, err = oauth.CreateMachineChallenge(t.Context(), AgentMachineChallengeRequest{MachineID: repo.stale.ID, AgentID: repo.authority.Agent.ID, Operation: AgentMachineEnroll, PublicKey: oauthHash("new agent key")})
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestMachineResourceIntrospectionDoesNotRevealAnotherResourceConnection(t *testing.T) {
	t.Parallel()
	oauth, repo, _ := machineFailureFixture(t)
	proof := machineRequestProof(t, oauth, repo, AgentMachineChallengeRequest{MachineID: repo.stale.ID, Operation: AgentMachineInspect})
	result, err := oauth.IntrospectMachine(t.Context(), "https://other.example.test", repo.stale.ID, proof)
	require.NoError(t, err)
	require.False(t, result.Active)
	require.Nil(t, result.Machine)
}

func TestMachineOwnerAdmissionFailurePermanentlyInvalidatesConnection(t *testing.T) {
	t.Parallel()
	oauth, repo, proof := machineFailureFixture(t)
	oauth.auth.cfg.IDVRequired = true
	result, err := oauth.MachineAgents(t.Context(), repo.stale.ID, proof, 0)
	require.ErrorIs(t, err, ErrAgentOAuthGrant)
	require.Nil(t, result)
	require.NotZero(t, repo.authority.Machine.RevokedAtMs)
	require.Zero(t, repo.consumed)
}
