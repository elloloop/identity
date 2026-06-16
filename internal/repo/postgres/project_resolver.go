package postgres

import (
	"context"
	"fmt"

	"github.com/elloloop/identity/internal/middleware"
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
// auth-domain (for branded link building) and its per-project CORS allow-list
// (for the CORS middleware). It returns nil for a nil or suspended project —
// a resolution miss; a suspended project must never resolve a request.
func (s *ProjectStore) resolved(ctx context.Context, p *Project) (*service.ResolvedProject, error) {
	if p == nil || p.Status != projectStatusActive {
		return nil, nil
	}
	primary, err := s.primaryAuthHostname(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	cfg, err := service.ParseProjectConfig(p.ConfigJSON)
	if err != nil {
		return nil, fmt.Errorf("project %q: %w", p.ID, err)
	}
	origins, err := projectCORSOrigins(p.ID, cfg)
	if err != nil {
		return nil, err
	}
	return &service.ResolvedProject{
		ID:                 p.ID,
		StorageScopeID:     p.StorageScopeID,
		PrimaryAuthDomain:  primary,
		CORSAllowedOrigins: origins,
		LoginDefaults:      cfg.Login,
	}, nil
}

// projectCORSOrigins parses a project's config_json and returns its validated
// per-project CORS allow-list, or nil when it configures none. Origins are
// validated with the same rule the global allow-list uses
// (middleware.ParseAllowedOrigins, credentials-mode): the CORS middleware
// always sets Access-Control-Allow-Credentials, so a wildcard/"null"/malformed
// per-project origin is rejected here rather than served to the browser. A bad
// config is a configuration error surfaced to the caller, not silently dropped.
func projectCORSOrigins(projectID string, cfg service.ProjectConfig) ([]string, error) {
	if len(cfg.CORS.AllowedOrigins) == 0 {
		return nil, nil
	}
	origins, err := middleware.ValidateAllowedOrigins(cfg.CORS.AllowedOrigins, true)
	if err != nil {
		return nil, fmt.Errorf("project %q cors: %w", projectID, err)
	}
	return origins, nil
}

// primaryAuthHostname returns the project's primary serving hostname, or ""
// when it has none. When requireVerifiedAuthDomain is set (the safe default),
// an unverified is_primary host is ignored so only a DNS-verified hostname can
// drive branded link URLs — matching the verified-only Host→project resolver
// (GetProjectByAuthHostname) and the proto contract on is_primary. When unset,
// a deployer has opted into letting an unverified is_primary host drive
// branded links.
func (s *ProjectStore) primaryAuthHostname(ctx context.Context, projectID string) (string, error) {
	q := `SELECT hostname FROM project_auth_domains
		WHERE project_id = $1 AND is_primary`
	if s.requireVerifiedAuthDomain {
		q += ` AND verified_at_ms > 0`
	}
	q += ` LIMIT 1`
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
