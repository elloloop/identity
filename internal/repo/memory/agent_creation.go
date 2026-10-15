package memory

import (
	"context"

	"github.com/elloloop/identity/internal/service"
)

func (r *Repo) CreateAgent(_ context.Context, request service.AgentCreation) (*service.User, bool, error) {
	if err := service.ValidateAgentCreation(request); err != nil {
		return nil, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := service.CheckAgentCreationAuthority(r.users[request.CallerID], r.users[request.Agent.OwnerUserID]); err != nil {
		return nil, false, err
	}
	key := [2]string{request.CallerID, request.RequestID}
	if receipt, ok := r.agentCreations[key]; request.RequestID != "" && ok {
		agent := r.users[receipt.AgentID]
		if err := service.CheckAgentCreationReplay(receipt, request, agent); err != nil {
			return nil, false, err
		}
		copy := *agent
		return &copy, false, nil
	}
	count := 0
	for _, user := range r.users {
		if user.IsAgent() && user.OwnerUserID == request.Agent.OwnerUserID {
			count++
		}
	}
	if count >= request.OwnerLimit {
		return nil, false, service.ErrAgentLimitReached
	}
	copy := *request.Agent
	agent := &copy
	agent.ID = r.nextID()
	r.users[agent.ID] = agent
	if request.RequestID != "" {
		r.agentCreations[key] = service.AgentCreationReceipt{CallerID: request.CallerID, RequestID: request.RequestID, Fingerprint: request.Fingerprint, AgentID: agent.ID, OwnerID: agent.OwnerUserID}
	}
	result := *agent
	return &result, true, nil
}

// Caller, owner and subject loss permanently fences every affected receipt.
// The caller already holds mu, so the lifecycle write and fence are atomic.
func (r *Repo) invalidateAgentCreations(userID string) {
	for key, receipt := range r.agentCreations {
		if receipt.AgentID == userID || receipt.OwnerID == userID || receipt.CallerID == userID {
			receipt.Invalidated = true
			r.agentCreations[key] = receipt
		}
	}
}
