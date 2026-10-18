package memory

import (
	"context"
	"sort"

	"github.com/elloloop/identity/internal/service"
)

func (r *Repo) CreateOAuthClient(_ context.Context, client *service.OAuthClient) error {
	if err := service.ValidateNewOAuthClient(client); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.oauthClients[client.ID] != nil {
		return service.ErrAlreadyExists
	}
	r.oauthClients[client.ID] = client.Clone()
	return nil
}

func (r *Repo) GetOAuthClient(_ context.Context, id string) (*service.OAuthClient, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.oauthClients[id].Clone(), nil
}

func (r *Repo) UpdateOAuthClient(_ context.Context, id string, expected int64, registration *service.OAuthClientRegistration, atMs int64) (*service.OAuthClient, error) {
	if err := service.ValidateOAuthClientUpdate(id, expected, registration, atMs); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	client := r.oauthClients[id]
	if client == nil || client.Revision != expected {
		return nil, nil
	}
	next := *client
	next.Registration = *registration
	next.Revision++
	next.UpdatedAt = atMs
	r.oauthClients[id] = next.Clone()
	for _, machine := range r.agentMachines {
		if machine.ClientID == id {
			r.revokeAgentMachineLocked(machine, atMs)
		}
	}
	for _, grant := range r.agentAuthorizations {
		if grant.ClientID == id && grant.RevokedAtMs == 0 {
			grant.RevokedAtMs = atMs
			grant.Revision++
		}
	}
	return next.Clone(), nil
}

func (r *Repo) ListOAuthClients(_ context.Context, afterID string, limit int) ([]*service.OAuthClient, error) {
	if err := service.ValidateOAuthClientPage(afterID, limit); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.oauthClients))
	for id := range r.oauthClients {
		if id > afterID {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > limit {
		ids = ids[:limit]
	}
	clients := make([]*service.OAuthClient, 0, len(ids))
	for _, id := range ids {
		clients = append(clients, r.oauthClients[id].Clone())
	}
	return clients, nil
}
