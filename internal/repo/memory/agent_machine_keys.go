package memory

import (
	"context"

	"github.com/elloloop/identity/internal/service"
)

//nolint:nilnil // Repository lookups return nil without error when a record does not exist.
func (r *Repo) GetAgentMachineDelegation(_ context.Context, machine, agent string) (*service.AgentAuthorization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, grant := range r.agentAuthorizations {
		if grant.MachineID == machine && grant.AgentID == agent {
			return grant.Clone(), nil
		}
	}
	return nil, nil
}

func (r *Repo) CreateAgentMachineChallenge(_ context.Context, input *service.AgentMachineChallenge) error {
	if !service.ValidAgentMachineChallenge(input) {
		return service.ErrInvalidArgument
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	machine := r.agentMachines[input.MachineID]
	if machine == nil || machine.RevokedAtMs != 0 {
		return service.ErrAgentOAuthGrant
	}
	if r.agentMachineChallenges == nil {
		r.agentMachineChallenges = make(map[string]*service.AgentMachineChallenge)
	}
	count := 0
	for id, challenge := range r.agentMachineChallenges {
		if challenge.ExpiresAtMs <= input.CreatedAtMs {
			delete(r.agentMachineChallenges, id)
		} else if challenge.MachineID == input.MachineID {
			count++
		}
	}
	if r.agentMachineChallenges[input.ID] != nil {
		return service.ErrAlreadyExists
	}
	if count >= service.MaxAgentMachineChallenges {
		return service.ErrAgentMachineChallengeLimit
	}
	copy := *input
	r.agentMachineChallenges[input.ID] = &copy
	return nil
}

//nolint:nilnil // A consumed or unknown challenge is an ordinary missing record.
func (r *Repo) GetAgentMachineChallenge(_ context.Context, id string) (*service.AgentMachineChallenge, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	challenge := r.agentMachineChallenges[id]
	if challenge == nil {
		return nil, nil
	}
	copy := *challenge
	return &copy, nil
}

func (r *Repo) ConsumeAgentMachineChallenge(_ context.Context, id string, now int64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	challenge := r.agentMachineChallenges[id]
	if challenge == nil || challenge.CreatedAtMs > now || challenge.ExpiresAtMs <= now {
		return false, nil
	}
	delete(r.agentMachineChallenges, id)
	return true, nil
}

func (r *Repo) DeleteExpiredAgentMachineChallenges(_ context.Context, before int64, limit int) error {
	if limit < 1 || limit > 10000 {
		return service.ErrInvalidArgument
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, challenge := range r.agentMachineChallenges {
		if challenge.ExpiresAtMs <= before {
			delete(r.agentMachineChallenges, id)
			limit--
			if limit == 0 {
				break
			}
		}
	}
	return nil
}
