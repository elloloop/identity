//go:build integration

package integration

import (
	"context"

	"github.com/elloloop/identity/internal/service"
)

func (r *MemRepo) CreateAgent(_ context.Context, request service.AgentCreation) (*service.User, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return request.ApplyToUsers(r.users, r.agentCreations, r.nextID)
}
