package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/elloloop/identity/pkg/audit"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/stretchr/testify/require"
)

type machineAdmissionRepo struct {
	Repository
	AgentMachineRepository
	authority AgentOAuthAuthority
	stale     *AgentMachine
	afterList func()
	challenge *AgentMachineChallenge
	engineKey ed25519.PrivateKey
	enrolled  *AgentAuthorization
}

func (r *machineAdmissionRepo) WithProject(string) Repository { return r }
func (r *machineAdmissionRepo) GetAgentMachine(context.Context, string) (*AgentMachine, error) {
	return r.stale.Clone(), nil
}

func (r *machineAdmissionRepo) AgentMachineAuthority(context.Context, string, string) (AgentOAuthAuthority, error) {
	a := r.authority
	a.Machine = a.Machine.Clone()
	return a, nil
}

func (r *machineAdmissionRepo) ListUsers(context.Context, UserListFilter) ([]*User, error) {
	if r.afterList != nil {
		r.afterList()
	}
	return []*User{r.authority.Agent}, nil
}

func machineAdmissionFixture(t *testing.T) (*AgentOAuthService, *machineAdmissionRepo, AgentMachineProof) {
	t.Helper()
	machine, authority, _ := machineGrantFixture()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	machine.PublicKey = hex.EncodeToString(public)
	repo := &machineAdmissionRepo{Repository: newFakeRepo(), authority: authority, stale: machine.Clone(), engineKey: private}
	auth, _ := newAuthSvcWithMailerForRepo(t, repo)
	auth.cfg.AgentMachineEnabled = true
	oauth := &AgentOAuthService{auth: auth, base: repo, resources: []config.AgentOAuthResourceCredential{{ProjectID: auth.cfg.DefaultProjectID, Resource: machine.Resource}}}
	challenge, err := oauth.CreateMachineChallenge(t.Context(), AgentMachineChallengeRequest{MachineID: machine.ID, Operation: AgentMachineRoster})
	require.NoError(t, err)
	return oauth, repo, AgentMachineProof{ChallengeID: challenge.ID, Signature: ed25519.Sign(private, []byte(challenge.Message))}
}

func TestMachineAdmissionNeverUsesEarlierUnrevokedSnapshot(t *testing.T) {
	oauth, repo, raw := machineAdmissionFixture(t)
	repo.authority.Machine.RevokedAtMs = 3000
	_, _, _, err := oauth.machineAccess(t.Context(), AgentMachineChallengeRequest{MachineID: repo.stale.ID, Operation: AgentMachineRoster}, raw)
	require.ErrorIs(t, err, ErrAgentOAuthGrant)
}

func TestMachineRosterFencesSelectionChangedWhileReadingUsers(t *testing.T) {
	oauth, repo, raw := machineAdmissionFixture(t)
	repo.afterList = func() {
		repo.authority.Machine.ExcludedAgentIDs = []string{repo.authority.Agent.ID}
		repo.authority.Machine.Revision++
	}
	_, err := oauth.MachineAgents(t.Context(), repo.stale.ID, raw, 0)
	require.ErrorIs(t, err, ErrAgentOAuthGrant)
}

func (r *machineAdmissionRepo) CreateAgentMachineChallenge(_ context.Context, c *AgentMachineChallenge) error {
	copy := *c
	r.challenge = &copy
	return nil
}

func (r *machineAdmissionRepo) GetAgentMachineChallenge(_ context.Context, id string) (*AgentMachineChallenge, error) {
	if r.challenge == nil || r.challenge.ID != id {
		return nil, nil
	}
	copy := *r.challenge
	return &copy, nil
}

func (r *machineAdmissionRepo) ConsumeAgentMachineChallenge(_ context.Context, id string, _ int64) (bool, error) {
	if r.challenge == nil || r.challenge.ID != id {
		return false, nil
	}
	r.challenge = nil
	return true, nil
}

func (r *machineAdmissionRepo) EnsureAgentMachineDelegation(_ context.Context, _ string, proposal *AgentAuthorization, key, fingerprint string) (*AgentAuthorization, error) {
	if err := ValidateMachineDelegation(r.authority.Machine, r.authority, proposal, key, fingerprint); err != nil {
		return nil, err
	}
	if r.enrolled != nil {
		return r.enrolled.Clone(), nil
	}
	r.enrolled = proposal.Clone()
	return proposal.Clone(), nil
}

func TestMachineEnrollmentAuditIdentifiesEngineAgentAndRecoveredGrant(t *testing.T) {
	oauth, repo, _ := machineAdmissionFixture(t)
	writer := newRecordingAuditWriter()
	oauth.auth.audit = audit.NewLogger(writer, oauth.auth.cfg.DefaultProjectID, zap.NewNop())
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key := hex.EncodeToString(public)
	request := AgentMachineChallengeRequest{MachineID: repo.stale.ID, AgentID: repo.authority.Agent.ID, Operation: AgentMachineEnroll, PublicKey: key}
	var original string
	for range 2 {
		challenge, err := oauth.CreateMachineChallenge(t.Context(), request)
		require.NoError(t, err)
		proof := AgentMachineProof{ChallengeID: challenge.ID, Signature: ed25519.Sign(repo.engineKey, []byte(challenge.Message))}
		grant, err := oauth.RegisterMachineAgentKey(t.Context(), request.MachineID, request.AgentID, key, proof)
		require.NoError(t, err)
		if original == "" {
			original = grant.ID
		}
		require.Equal(t, original, grant.ID)
	}
	require.Equal(t, 2, writer.countByEventTypeActorTarget(string(audit.EventAgentMachineAgentEnrolled), repo.stale.OwnerID, repo.authority.Agent.ID))
	details := writer.detailsOf(string(audit.EventAgentMachineAgentEnrolled))
	require.Len(t, details, 2)
	for i, detail := range details {
		require.Equal(t, repo.stale.ID, detail["machine_id"])
		require.Equal(t, original, detail["delegation_id"])
		require.Equal(t, i == 1, detail["recovered"])
		require.Len(t, detail["key_fingerprint"], 64)
	}
}
