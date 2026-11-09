package memory

import (
	"context"
	"sort"

	"github.com/elloloop/identity/internal/service"
)

var _ service.AgentMachineRepository = (*Repo)(nil)

func (r *Repo) CreateAgentMachine(_ context.Context, input *service.AgentMachine, fingerprint string) (*service.AgentMachine, error) {
	if err := service.ValidateAgentMachine(input); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.oauthAuthorityLocked(input.OwnerID, "", input.RegistrationSID, input.ClientID)
	if !a.ValidMachineRegistration(input) || a.Fingerprint() != fingerprint {
		return nil, service.ErrAgentOAuthGrant
	}
	if initial := r.agentMachineRegistrations[input.ID]; initial != nil {
		if service.SameAgentMachineRegistration(initial, input) {
			return r.agentMachines[input.ID].Clone(), nil
		}
		current := r.agentMachines[input.ID]
		// A revoked registration is replaced when the same owner registers the
		// installation again with a new key; another owner, an active registration
		// or the revoked key itself never comes back (see the SQL stores).
		if current.RevokedAtMs == 0 || current.OwnerID != input.OwnerID || current.PublicKey == input.PublicKey {
			return nil, service.ErrAlreadyExists
		}
		renewed := input.Clone()
		renewed.Revision, renewed.RevokedAtMs, renewed.RenewedAfterRevokedAtMs = current.Revision+1, 0, current.RevokedAtMs
		for id, c := range r.agentMachineChallenges {
			if c.MachineID == input.ID {
				delete(r.agentMachineChallenges, id)
			}
		}
		if current.RenewedAfterRevokedAtMs != 0 {
			for _, child := range r.agentAuthorizations {
				if child.MachineID == input.ID && child.RevokedAtMs == current.RenewedAfterRevokedAtMs {
					child.RevokedAtMs = current.RevokedAtMs
					child.Revision++
				}
			}
		}
		r.agentMachineRegistrations[input.ID] = input.Clone()
		r.agentMachines[input.ID] = renewed
		return renewed.Clone(), nil
	}
	r.agentMachineRegistrations[input.ID] = input.Clone()
	r.agentMachines[input.ID] = input.Clone()
	return input.Clone(), nil
}

func (r *Repo) GetAgentMachine(_ context.Context, id string) (*service.AgentMachine, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.agentMachines[id].Clone(), nil
}

func (r *Repo) ListAgentMachines(_ context.Context, owner, after string, limit int) ([]*service.AgentMachine, error) {
	if owner == "" || limit < 1 || limit > service.MaxAgentOAuthListLimit {
		return nil, service.ErrInvalidArgument
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0)
	for id, m := range r.agentMachines {
		if m.OwnerID == owner && id > after {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]*service.AgentMachine, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.agentMachines[id].Clone())
	}
	return out, nil
}

func (r *Repo) MutateAgentMachine(_ context.Context, id string, m service.AgentMachineMutation) (*service.AgentMachine, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.agentMachines[id]
	next, err := service.ApplyAgentMachineMutation(current, m)
	if err != nil {
		return nil, err
	}
	if m.Operation != service.AgentMachineRevoke {
		a := r.oauthAuthorityLocked(current.OwnerID, "", "", current.ClientID)
		if !a.ValidMachine(current) {
			return nil, service.ErrAgentOAuthGrant
		}
	}
	r.agentMachines[id] = next
	for _, g := range r.agentAuthorizations {
		if g.MachineID == id && g.RevokedAtMs == 0 && !next.Allows(g.AgentID) {
			g.RevokedAtMs = m.AtMs
			g.Revision++
		}
	}
	return next.Clone(), nil
}

func (r *Repo) AgentMachineAuthority(_ context.Context, id, agent string) (service.AgentOAuthAuthority, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.agentMachines[id]
	if m == nil {
		return service.AgentOAuthAuthority{}, nil
	}
	a := r.oauthAuthorityLocked(m.OwnerID, agent, "", m.ClientID)
	a.Machine = m.Clone()
	return a, nil
}

func (r *Repo) EnsureAgentMachineDelegation(_ context.Context, id string, candidate *service.AgentAuthorization, hash, fingerprint string) (*service.AgentAuthorization, error) {
	if candidate == nil {
		return nil, service.ErrAgentOAuthGrant
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.agentMachines[id]
	if m == nil {
		return nil, service.ErrAgentOAuthGrant
	}
	a := r.oauthAuthorityLocked(m.OwnerID, candidate.AgentID, "", m.ClientID)
	a.Machine = m.Clone()
	if err := service.ValidateMachineDelegation(m, a, candidate, hash, fingerprint); err != nil {
		return nil, err
	}
	for _, child := range r.agentAuthorizations {
		if child.MachineID == id && child.AgentID == candidate.AgentID {
			if child.RevokedAtMs != 0 && m.RenewedAfterRevokedAtMs != 0 && child.RevokedAtMs == m.RenewedAfterRevokedAtMs {
				// Renewed in place for the machine's renewed registration, under a new key.
				if child.MachinePublicKey == candidate.MachinePublicKey {
					return nil, service.ErrAgentOAuthGrant
				}
				for _, other := range r.agentAuthorizations {
					if other != child && other.MachineID == id && other.MachinePublicKey == candidate.MachinePublicKey {
						return nil, service.ErrAlreadyExists
					}
				}
				renewed := candidate.Clone()
				renewed.ID, renewed.Revision, renewed.RevokedAtMs, renewed.ExpiresAtMs = child.ID, child.Revision+1, 0, 0
				r.agentAuthorizations[child.ID] = renewed
				return renewed.Clone(), nil
			}
			if !a.Valid(child) || child.MachinePublicKey != candidate.MachinePublicKey {
				return nil, service.ErrAgentOAuthGrant
			}
			return child.Clone(), nil
		}
	}
	if r.agentAuthorizations == nil {
		r.agentAuthorizations = make(map[string]*service.AgentAuthorization)
		r.agentOAuthCodes = make(map[string]string)
		r.agentOAuthRefresh = make(map[string]*service.AgentOAuthRefresh)
	}
	if r.agentAuthorizations[candidate.ID] != nil {
		return nil, service.ErrAlreadyExists
	}
	for _, other := range r.agentAuthorizations {
		if other.MachineID == id && other.MachinePublicKey == candidate.MachinePublicKey {
			return nil, service.ErrAlreadyExists
		}
	}
	r.agentAuthorizations[candidate.ID] = candidate.Clone()
	return candidate.Clone(), nil
}

func (r *Repo) revokeAgentMachineLocked(m *service.AgentMachine, atMs int64) {
	if m.RevokedAtMs == 0 {
		m.RevokedAtMs = atMs
		m.Revision++
	}
	for _, child := range r.agentAuthorizations {
		if child.MachineID == m.ID && child.RevokedAtMs == 0 {
			child.RevokedAtMs = atMs
			child.Revision++
		}
	}
}
