package postgres

import (
	"context"

	"github.com/elloloop/identity/internal/service"
)

// The control-plane ProjectStore is the postgres driver's
// service.ProjectResolver: it resolves a request's project from a
// credential public id or a serving hostname. Resolution is the read side
// of the same control-plane tables CreateProject* writes.
var _ service.ProjectResolver = (*ProjectStore)(nil)

// ResolveByCredential resolves the active project an active credential
// public id belongs to. A revoked credential, a suspended project, an
// unknown id, or a blank id is a clean miss (nil, nil); only an
// infrastructure failure returns an error.
func (s *ProjectStore) ResolveByCredential(ctx context.Context, publicID string) (*service.ResolvedProject, error) {
	cred, err := s.GetProjectCredentialByPublicID(ctx, publicID)
	if err != nil {
		return nil, err
	}
	if cred == nil || cred.Status != credentialStatusActive {
		return nil, nil
	}
	proj, err := s.GetProjectByID(ctx, cred.ProjectID)
	if err != nil {
		return nil, err
	}
	return s.resolved(ctx, proj)
}

// ResolveByHostname resolves the active project a serving hostname maps
// onto (case-insensitive). An unmapped hostname, a suspended project, or a
// blank hostname is a clean miss (nil, nil).
func (s *ProjectStore) ResolveByHostname(ctx context.Context, hostname string) (*service.ResolvedProject, error) {
	proj, err := s.GetProjectByAuthHostname(ctx, hostname)
	if err != nil {
		return nil, err
	}
	return s.resolved(ctx, proj)
}

// resolved maps an active project to a ResolvedProject, loading its primary
// auth-domain (for branded link building). It returns nil for a nil or
// suspended project — a resolution miss; a suspended project must never
// resolve a request.
func (s *ProjectStore) resolved(ctx context.Context, p *Project) (*service.ResolvedProject, error) {
	if p == nil || p.Status != projectStatusActive {
		return nil, nil
	}
	primary, err := s.primaryAuthHostname(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	return &service.ResolvedProject{
		ID:                p.ID,
		StorageScopeID:    p.StorageScopeID,
		PrimaryAuthDomain: primary,
	}, nil
}

// primaryAuthHostname returns the project's primary serving hostname, or ""
// when it has none.
func (s *ProjectStore) primaryAuthHostname(ctx context.Context, projectID string) (string, error) {
	const q = `SELECT hostname FROM project_auth_domains
		WHERE project_id = $1 AND is_primary
		LIMIT 1`
	var hostname string
	err := s.pool.QueryRow(ctx, q, projectID).Scan(&hostname)
	if noRows(err) {
		return "", nil
	}
	if err != nil {
		return "", wrapPgErr("primaryAuthHostname", err)
	}
	return hostname, nil
}
