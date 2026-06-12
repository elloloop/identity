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
	return activeResolved(proj), nil
}

// ResolveByHostname resolves the active project a serving hostname maps
// onto (case-insensitive). An unmapped hostname, a suspended project, or a
// blank hostname is a clean miss (nil, nil).
func (s *ProjectStore) ResolveByHostname(ctx context.Context, hostname string) (*service.ResolvedProject, error) {
	proj, err := s.GetProjectByAuthHostname(ctx, hostname)
	if err != nil {
		return nil, err
	}
	return activeResolved(proj), nil
}

// activeResolved maps an active project to a ResolvedProject, or returns
// nil for a nil or suspended project — a resolution miss. A suspended
// project must never resolve a request.
func activeResolved(p *Project) *service.ResolvedProject {
	if p == nil || p.Status != projectStatusActive {
		return nil
	}
	return &service.ResolvedProject{ID: p.ID, StorageScopeID: p.StorageScopeID}
}
