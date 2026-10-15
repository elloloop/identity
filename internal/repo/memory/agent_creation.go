package memory

import (
	"context"

	"github.com/elloloop/identity/internal/service"
)

func (r *Repo) CreateAgent(_ context.Context, request service.AgentCreation) (*service.User, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return request.ApplyToUsers(r.users, r.agentCreations, r.nextID)
}

func (r *Repo) invalidateAgentCreations(userID string) {
	service.InvalidateAgentCreationReceipts(r.agentCreations, userID)
}
