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

// The ProjectStore is also the postgres driver's service.NativeOAuthProjectStore:
// the read-side lookup NativeOAuthLogin uses to validate a product→project id.
var _ service.NativeOAuthProjectStore = (*ProjectStore)(nil)

// ActiveProjectByID resolves an ACTIVE control-plane project by id as the
// driver-agnostic service.AdminProject, or (nil, nil) when no such active
// project exists. It delegates to GetProjectByID and treats a suspended
// project as a clean miss — a native login may not be scoped to a project that
// is not serving. It backs the native-OAuth product→project validation.
func (s *ProjectStore) ActiveProjectByID(ctx context.Context, projectID string) (*service.AdminProject, error) {
	p, err := s.GetProjectByID(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if p == nil || p.Status != projectStatusActive {
		return nil, nil
	}
	return &service.AdminProject{ID: p.ID, StorageScopeID: p.StorageScopeID, Name: p.Name}, nil
}

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

// CreateAuthDomain registers an UNVERIFIED custom serving hostname (the
// customer-domain flow). VerifiedAtMs is left 0 so the resolver does not
// resolve it until VerifyProjectAuthDomain proves ownership. A hostname
// already bound to any project surfaces service.ErrAlreadyExists.
func (s *ProjectStore) CreateAuthDomain(ctx context.Context, projectID, hostname string, isPrimary bool) error {
	_, err := s.CreateProjectAuthDomain(ctx, &ProjectAuthDomain{
		ProjectID: projectID,
		Hostname:  hostname,
		IsPrimary: isPrimary,
		// VerifiedAtMs: 0 — unverified until the DNS-TXT challenge passes.
	})
	return err
}

// GetAuthDomain returns a project's own auth-domain (any state) as the admin
// service's value type, or (nil, nil) when the project has no such hostname.
func (s *ProjectStore) GetAuthDomain(ctx context.Context, projectID, hostname string) (*service.AdminProjectAuthDomain, error) {
	d, err := s.GetProjectAuthDomain(ctx, projectID, hostname)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, nil
	}
	return authDomainToService(d), nil
}

// ListAuthDomains returns every auth-domain of a project (primary-first) as
// the admin service's value type.
func (s *ProjectStore) ListAuthDomains(ctx context.Context, projectID string) ([]*service.AdminProjectAuthDomain, error) {
	rows, err := s.ListProjectAuthDomains(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*service.AdminProjectAuthDomain, 0, len(rows))
	for _, d := range rows {
		out = append(out, authDomainToService(d))
	}
	return out, nil
}

// SetAuthDomainVerified stamps verifiedAtMs on a project's own auth-domain,
// flipping it to resolving. A hostname the project does not own surfaces
// service.ErrNotFound.
func (s *ProjectStore) SetAuthDomainVerified(ctx context.Context, projectID, hostname string, verifiedAtMs int64) error {
	return s.SetProjectAuthDomainVerified(ctx, projectID, hostname, verifiedAtMs)
}

// SetPrimaryAuthDomain promotes a project's VERIFIED auth-domain to primary,
// atomically demoting the current primary, and returns the promoted record as
// the admin service's value type. An unverified target surfaces
// service.ErrAuthDomainNotVerified; a hostname the project does not own
// surfaces service.ErrNotFound.
func (s *ProjectStore) SetPrimaryAuthDomain(ctx context.Context, projectID, hostname string) (*service.AdminProjectAuthDomain, error) {
	d, err := s.SetPrimaryProjectAuthDomain(ctx, projectID, hostname)
	if err != nil {
		return nil, err
	}
	return authDomainToService(d), nil
}

// UpdateProjectConfig REPLACES a project's config_json blob and returns the
// stored (normalised) value. An unknown project surfaces service.ErrNotFound.
func (s *ProjectStore) UpdateProjectConfig(ctx context.Context, projectID, configJSON string) (string, error) {
	return s.updateProjectConfig(ctx, projectID, configJSON)
}

// GetProjectConfig returns a project's stored config_json ("{}" when unset).
// An unknown project surfaces service.ErrNotFound.
func (s *ProjectStore) GetProjectConfig(ctx context.Context, projectID string) (string, error) {
	return s.getProjectConfig(ctx, projectID)
}

// authDomainToService maps the store row to the driver-agnostic admin value.
func authDomainToService(d *ProjectAuthDomain) *service.AdminProjectAuthDomain {
	return &service.AdminProjectAuthDomain{
		Hostname:     d.Hostname,
		IsPrimary:    d.IsPrimary,
		VerifiedAtMs: d.VerifiedAtMs,
	}
}
