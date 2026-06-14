package postgres

import (
	"context"

	"github.com/elloloop/identity/internal/service"
)

// The control-plane ProjectStore is also the postgres driver's
// service.ControlPlaneProjectStore: the write side the platform-operator
// admin RPCs (AdminCreateProject / AdminCreateProjectCredential /
// AdminAddProjectAuthDomain) use to provision projects out-of-band. These
// adapters translate the service-layer value types to the store's internal
// row types and delegate to the typed methods, mirroring project_resolver.go.
var _ service.ControlPlaneProjectStore = (*ProjectStore)(nil)

// CreateProject inserts a project from the admin service's value type and
// returns its id. EnsureAuthDomain and the resolver read the same tables.
func (s *ProjectStore) CreateProject(ctx context.Context, p *service.AdminProject) (string, error) {
	row := &Project{
		ID:             p.ID,
		StorageScopeID: p.StorageScopeID,
		Name:           p.Name,
	}
	id, err := s.createProject(ctx, row)
	if err != nil {
		return "", err
	}
	p.ID = id
	return id, nil
}

// CreateProjectCredential inserts a credential from the admin service's value
// type and returns its id. Only the secret HASH is carried in — the raw
// secret never reaches the store.
func (s *ProjectStore) CreateProjectCredential(ctx context.Context, c *service.AdminProjectCredential) (string, error) {
	row := &ProjectCredential{
		ID:         c.ID,
		ProjectID:  c.ProjectID,
		Kind:       c.Kind,
		PublicID:   c.PublicID,
		SecretHash: c.SecretHash,
	}
	id, err := s.createProjectCredential(ctx, row)
	if err != nil {
		return "", err
	}
	c.ID = id
	return id, nil
}
