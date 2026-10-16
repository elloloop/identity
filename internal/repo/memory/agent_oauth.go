package memory

import (
	"context"
	"sort"

	"github.com/elloloop/identity/internal/service"
)

var _ service.AgentOAuthRepository = (*Repo)(nil)

func (r *Repo) CreateAgentAuthorization(_ context.Context, request *service.AgentAuthorization) error {
	if err := service.ValidateAgentAuthorization(request); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.agentAuthorizations == nil {
		r.agentAuthorizations = make(map[string]*service.AgentAuthorization)
		r.agentOAuthCodes = make(map[string]string)
		r.agentOAuthRefresh = make(map[string]*service.AgentOAuthRefresh)
	}
	if r.agentAuthorizations[request.ID] != nil {
		return service.ErrAlreadyExists
	}
	client := r.oauthClients[request.ClientID]
	if client == nil || client.Revision != request.ClientRevision || client.ValidateOAuthRequest(request.RedirectURI, request.Resource, request.Scopes, service.OAuthGrantAuthorizationCode) != nil {
		return service.ErrPermissionDenied
	}
	r.agentAuthorizations[request.ID] = request.Clone()
	return nil
}

func (r *Repo) GetAgentAuthorization(_ context.Context, id string) (*service.AgentAuthorization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.agentAuthorizations[id].Clone(), nil
}

func (r *Repo) FindAgentAuthorizationByCode(_ context.Context, hash string) (*service.AgentAuthorization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.agentAuthorizations[r.agentOAuthCodes[hash]].Clone(), nil
}

func (r *Repo) FindAgentAuthorizationByRefresh(_ context.Context, hash string) (*service.AgentAuthorization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	token := r.agentOAuthRefresh[hash]
	if token == nil {
		return nil, nil
	}
	return r.agentAuthorizations[token.AuthorizationID].Clone(), nil
}

func (r *Repo) oauthAuthorityLocked(ownerID, agentID, sid, clientID string) service.AgentOAuthAuthority {
	a := service.AgentOAuthAuthority{Client: r.oauthClients[clientID].Clone()}
	if u := r.users[ownerID]; u != nil {
		copy := *u
		a.Owner = &copy
	}
	if u := r.users[agentID]; u != nil {
		copy := *u
		a.Agent = &copy
	}
	for _, s := range r.sessions {
		if s.SID == sid {
			copy := *s
			a.HumanSession = &copy
			break
		}
	}
	for _, edge := range r.guardianEdges {
		if edge.ChildUserID == ownerID {
			a.HasGuardian = true
			break
		}
	}
	return a
}

func (r *Repo) AgentOAuthAuthority(_ context.Context, ownerID, agentID, sid, clientID string) (service.AgentOAuthAuthority, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.oauthAuthorityLocked(ownerID, agentID, sid, clientID), nil
}

func (r *Repo) MutateAgentAuthorization(_ context.Context, id string, m service.AgentOAuthMutation) (*service.AgentAuthorization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.agentAuthorizations[id]
	if current == nil {
		return nil, service.ErrAgentOAuthGrant
	}
	owner, agent, sid := current.OwnerID, current.AgentID, current.HumanSID
	if m.Operation == service.AgentOAuthApprove || m.Operation == service.AgentOAuthDeny {
		owner, agent, sid = m.OwnerID, m.AgentID, m.HumanSID
	}
	next, err := service.ApplyAgentOAuthMutation(current, r.oauthAuthorityLocked(owner, agent, sid, current.ClientID), r.agentOAuthRefresh[m.RefreshHash], m)
	if next == nil {
		return nil, err
	}
	if m.NextRefreshHash != "" && err == nil {
		if r.agentOAuthRefresh[m.NextRefreshHash] != nil {
			return nil, service.ErrAlreadyExists
		}
	}
	if next.CodeHash != "" {
		if prior := r.agentOAuthCodes[next.CodeHash]; prior != "" && prior != id {
			return nil, service.ErrAlreadyExists
		}
	}
	r.agentAuthorizations[id] = next
	if next.CodeHash != "" {
		r.agentOAuthCodes[next.CodeHash] = id
	}
	if err == nil && m.Operation == service.AgentOAuthRotate {
		r.agentOAuthRefresh[m.RefreshHash].ConsumedAtMs = m.AtMs
	}
	if err == nil && m.NextRefreshHash != "" {
		r.agentOAuthRefresh[m.NextRefreshHash] = &service.AgentOAuthRefresh{Hash: m.NextRefreshHash, AuthorizationID: id, ExpiresAtMs: m.RefreshExpiresAtMs}
	}
	return next.Clone(), err
}

func (r *Repo) ListAgentAuthorizations(_ context.Context, ownerID, after string, limit int) ([]*service.AgentAuthorization, error) {
	if ownerID == "" || limit < 1 || limit > service.MaxAgentOAuthListLimit {
		return nil, service.ErrInvalidArgument
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0)
	for id, g := range r.agentAuthorizations {
		if g.OwnerID == ownerID && id > after {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]*service.AgentAuthorization, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.agentAuthorizations[id].Clone())
	}
	return out, nil
}

func (r *Repo) revokeAgentOAuthUserLocked(before, after *service.User, atMs int64) {
	if !service.AgentOAuthAuthorityLost(before, after) {
		return
	}
	for _, g := range r.agentAuthorizations {
		if (g.OwnerID == before.ID || g.AgentID == before.ID) && g.RevokedAtMs == 0 {
			g.RevokedAtMs = atMs
			g.Revision++
		}
	}
}

func (r *Repo) revokeAgentOAuthSIDLocked(sid string, atMs int64) {
	for _, g := range r.agentAuthorizations {
		if g.HumanSID == sid && g.RevokedAtMs == 0 {
			g.RevokedAtMs = atMs
			g.Revision++
		}
	}
}

func (r *Repo) DeleteExpiredAgentAuthorizations(_ context.Context, beforeMs int64, limit int) error {
	if limit < 1 || limit > service.MaxUserListLimit {
		return service.ErrInvalidArgument
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	expired := make([]string, 0)
	for id, g := range r.agentAuthorizations {
		if max(g.ExpiresAtMs, g.GrantExpiresAtMs) < beforeMs {
			expired = append(expired, id)
		}
	}
	sort.Strings(expired)
	if len(expired) > limit {
		expired = expired[:limit]
	}
	ids := make(map[string]bool, len(expired))
	for _, id := range expired {
		ids[id] = true
		g := r.agentAuthorizations[id]
		delete(r.agentOAuthCodes, g.CodeHash)
		delete(r.agentAuthorizations, id)
	}
	for hash, token := range r.agentOAuthRefresh {
		if ids[token.AuthorizationID] {
			delete(r.agentOAuthRefresh, hash)
		}
	}
	return nil
}

func (r *Repo) revokeAgentOAuthOwnerLocked(owner string, atMs int64) {
	for _, grant := range r.agentAuthorizations {
		if grant.OwnerID == owner && grant.RevokedAtMs == 0 {
			grant.RevokedAtMs = atMs
			grant.Revision++
		}
	}
}
