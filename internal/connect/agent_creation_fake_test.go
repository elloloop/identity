package connect

import (
	"context"

	"github.com/elloloop/identity/internal/service"
)

func (r *fakeRepo) CreateAgent(_ context.Context, request service.AgentCreation) (*service.User, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return request.ApplyToUsers(r.users, r.agentCreations, nextID)
}
