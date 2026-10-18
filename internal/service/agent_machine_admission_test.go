package service

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/elloloop/identity/internal/config"
	"github.com/stretchr/testify/require"
)

type machineAdmissionRepo struct {
	Repository
	AgentMachineRepository
	authority AgentOAuthAuthority
	stale     *AgentMachine
	afterList func()
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

func machineAdmissionFixture(t *testing.T) (*AgentOAuthService, *machineAdmissionRepo, string) {
	t.Helper()
	machine, authority, _ := machineStateFixture()
	raw := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	machine.CredentialHash = oauthHash(raw)
	repo := &machineAdmissionRepo{Repository: newFakeRepo(), authority: authority, stale: machine.Clone()}
	auth, _ := newAuthSvcWithMailerForRepo(t, repo)
	auth.cfg.AgentMachineEnabled = true
	oauth := &AgentOAuthService{auth: auth, base: repo, resources: []config.AgentOAuthResourceCredential{{ProjectID: auth.cfg.DefaultProjectID, Resource: machine.Resource}}}
	return oauth, repo, raw
}

func TestMachineAdmissionNeverUsesEarlierUnrevokedSnapshot(t *testing.T) {
	oauth, repo, raw := machineAdmissionFixture(t)
	repo.authority.Machine.RevokedAtMs = 3000
	_, _, err := oauth.machineAccess(t.Context(), repo.stale.ID, raw, "")
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
