package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

// This file implements the control-plane ProjectStore for the identity
// redesign. It is a self-contained, additive store layered on top of
// migration 0013's control-plane tables (projects, project_credentials,
// project_auth_domains). It deliberately does NOT touch the existing
// service.Repository interface or the memory/entdb drivers — those gain
// project/tenant support in later slices.
//
// Unlike the data-plane *pgRepository (which scopes every query by
// tenant_id), the control-plane tables are platform-global: projects ARE
// the isolation entity, so the store carries no project/tenant scope. A
// request resolves its project HERE — by credential public_id or by the
// Host header → auth-domain hostname — before any data-plane query runs.
//
// Conventions mirror user.go: caller-supplied TEXT ids (random hex via
// newID when empty), *_at_ms epoch-millis timestamps stamped via nowMs,
// row scanning into the value, and wrapPgErr for SQLSTATE → service
// sentinel translation.

// Project is a control-plane registry row: one logical, control-plane
// isolation entity (a Firebase-style project) mapped onto exactly one
// physical storage scope (shard) via StorageScopeID.
type Project struct {
	ID             string
	StorageScopeID string
	Name           string
	Status         string // active | suspended
	ConfigJSON     string // JSON object; "" is normalised to "{}".
	CreatedAtMs    int64
	UpdatedAtMs    int64
}

// ProjectCredential is a lookup key used to resolve a project on a
// request, by its globally-unique PublicID.
type ProjectCredential struct {
	ID           string
	ProjectID    string
	Kind         string // publishable | secret | mtls
	PublicID     string
	SecretHash   string
	Status       string // active | revoked
	CreatedAtMs  int64
	LastUsedAtMs int64
	RevokedAtMs  int64
}

// ProjectAuthDomain is a per-project serving hostname. One host resolves
// to exactly one project (Hostname is globally unique, case-insensitive),
// so the Host header alone can resolve a project.
type ProjectAuthDomain struct {
	ID           string
	ProjectID    string
	Hostname     string
	IsPrimary    bool
	VerifiedAtMs int64
	CreatedAtMs  int64
}

const (
	projectStatusActive    = "active"
	credentialStatusActive = "active"
)

// ProjectStore is the Postgres-backed, control-plane registry store. It
// is platform-global (not project/tenant-scoped) and shares its caller's
// connection pool.
type ProjectStore struct {
	pool *tracedPool
}

// NewProjectStore builds a control-plane store that shares the given
// repository's connection pool. The store must NOT be closed
// independently — closing the owning *pgRepository releases the pool for
// every derived store.
func NewProjectStore(r *pgRepository) *ProjectStore {
	return &ProjectStore{pool: r.pool}
}

// columnsPrefixed qualifies every comma-separated column in cols with the
// given table alias, so a SELECT over a join stays unambiguous while the
// bare column list remains the single source of scan ordering.
func columnsPrefixed(cols, alias string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = alias + "." + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

// ── projects ──────────────────────────────────────────────────────────

const projectColumns = `
	id, storage_scope_id, name, status, config_json,
	created_at_ms, updated_at_ms`

func scanProject(row pgx.Row) (*Project, error) {
	var p Project
	if err := row.Scan(
		&p.ID, &p.StorageScopeID, &p.Name, &p.Status, &p.ConfigJSON,
		&p.CreatedAtMs, &p.UpdatedAtMs,
	); err != nil {
		return nil, err
	}
	return &p, nil
}

// CreateProject inserts a project. StorageScopeID is required and globally
// unique; a duplicate surfaces service.ErrAlreadyExists. The id is
// caller-supplied (random hex when empty) so it is known without a
// RETURNING round-trip; the assigned id is written back to p.ID.
func (s *ProjectStore) CreateProject(ctx context.Context, p *Project) (string, error) {
	if p == nil {
		return "", errors.New("postgres: CreateProject: nil project")
	}
	if p.StorageScopeID == "" {
		return "", fmt.Errorf("%w: missing storage_scope_id", service.ErrInvalidArgument)
	}
	now := nowMs()
	if p.CreatedAtMs == 0 {
		p.CreatedAtMs = now
	}
	if p.UpdatedAtMs == 0 {
		p.UpdatedAtMs = p.CreatedAtMs
	}
	id := p.ID
	if id == "" {
		id = newID()
	}
	status := p.Status
	if status == "" {
		status = projectStatusActive
	}
	configJSON := p.ConfigJSON
	if configJSON == "" {
		configJSON = "{}"
	}
	const q = `
		INSERT INTO projects (
			id, storage_scope_id, name, status, config_json,
			created_at_ms, updated_at_ms
		) VALUES (
			$1, $2, $3, $4, $5::jsonb, $6, $7
		)`
	if _, err := s.pool.Exec(
		ctx, q,
		id, p.StorageScopeID, p.Name, status, configJSON,
		p.CreatedAtMs, p.UpdatedAtMs,
	); err != nil {
		return "", wrapPgErr("CreateProject", err)
	}
	p.ID = id
	p.Status = status
	p.ConfigJSON = configJSON
	return id, nil
}

// GetProjectByID returns the project with the given id, or (nil, nil) when
// no such project exists.
func (s *ProjectStore) GetProjectByID(ctx context.Context, projectID string) (*Project, error) {
	if projectID == "" {
		return nil, nil
	}
	const q = `SELECT ` + projectColumns + `
		FROM projects
		WHERE id = $1`
	p, err := scanProject(s.pool.QueryRow(ctx, q, projectID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetProjectByID", err)
	}
	return p, nil
}

// GetProjectByStorageScope returns the single project mapped onto the given
// physical storage scope, or (nil, nil) when none is. storage_scope_id is
// globally unique, so this resolves at most one project.
func (s *ProjectStore) GetProjectByStorageScope(ctx context.Context, storageScopeID string) (*Project, error) {
	if storageScopeID == "" {
		return nil, nil
	}
	const q = `SELECT ` + projectColumns + `
		FROM projects
		WHERE storage_scope_id = $1`
	p, err := scanProject(s.pool.QueryRow(ctx, q, storageScopeID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetProjectByStorageScope", err)
	}
	return p, nil
}

// EnsureDefaultProject idempotently ensures the default Project exists,
// mapped onto the given storage scope (typically GATEWAY_DEFAULT_TENANT_ID).
// It is safe to call on every boot and from multiple instances at once: it
// returns the existing project when one is already present (looked up by id,
// then by storage scope), and otherwise creates it, tolerating a concurrent
// creator (an ErrAlreadyExists race is resolved by re-reading the row).
//
// The default project is a logical control-plane entity that POINTS AT the
// storage scope via StorageScopeID — it is not the same value as the storage
// id, and the two must not be conflated.
//
// If the storage scope is already mapped to a project (storage_scope_id is
// globally unique), that existing project is returned even when its id
// differs from projectID — the scope binding wins and no second project is
// created for the same scope.
func (s *ProjectStore) EnsureDefaultProject(ctx context.Context, projectID, storageScopeID, name string) (*Project, error) {
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing default project id", service.ErrInvalidArgument)
	}
	if storageScopeID == "" {
		return nil, fmt.Errorf("%w: missing storage_scope_id", service.ErrInvalidArgument)
	}
	// Already present, by id or by the storage scope it maps onto?
	if existing, err := s.GetProjectByID(ctx, projectID); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}
	if existing, err := s.GetProjectByStorageScope(ctx, storageScopeID); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}
	// Create it. A concurrent creator that inserted between the lookups above
	// and this insert surfaces as ErrAlreadyExists; resolve the race by
	// re-reading and returning the winner's row. Any error from that re-read
	// is propagated, not masked behind the original conflict.
	p := &Project{ID: projectID, StorageScopeID: storageScopeID, Name: name, Status: projectStatusActive}
	if _, err := s.CreateProject(ctx, p); err != nil {
		if !errors.Is(err, service.ErrAlreadyExists) {
			return nil, err
		}
		if existing, gErr := s.GetProjectByID(ctx, projectID); gErr != nil {
			return nil, gErr
		} else if existing != nil {
			return existing, nil
		}
		if existing, gErr := s.GetProjectByStorageScope(ctx, storageScopeID); gErr != nil {
			return nil, gErr
		} else if existing != nil {
			return existing, nil
		}
		// ErrAlreadyExists yet neither lookup resolves the row (a different
		// unique constraint, or the racing row was already removed) — surface
		// the original conflict.
		return nil, err
	}
	return p, nil
}

// ── project_credentials ───────────────────────────────────────────────

// #nosec G101 -- this is a SQL column list (secret_hash is a column name),
// not a hardcoded credential.
const projectCredentialColumns = `
	id, project_id, kind, public_id, secret_hash, status,
	created_at_ms, last_used_at_ms, revoked_at_ms`

func scanProjectCredential(row pgx.Row) (*ProjectCredential, error) {
	var c ProjectCredential
	if err := row.Scan(
		&c.ID, &c.ProjectID, &c.Kind, &c.PublicID, &c.SecretHash, &c.Status,
		&c.CreatedAtMs, &c.LastUsedAtMs, &c.RevokedAtMs,
	); err != nil {
		return nil, err
	}
	return &c, nil
}

// CreateProjectCredential inserts a lookup credential for a project.
// PublicID is required and globally unique; a duplicate surfaces
// service.ErrAlreadyExists. The id is caller-supplied (random hex when
// empty) and written back to c.ID.
func (s *ProjectStore) CreateProjectCredential(ctx context.Context, c *ProjectCredential) (string, error) {
	if c == nil {
		return "", errors.New("postgres: CreateProjectCredential: nil credential")
	}
	if c.ProjectID == "" {
		return "", fmt.Errorf("%w: missing project_id", service.ErrInvalidArgument)
	}
	if c.Kind == "" {
		return "", fmt.Errorf("%w: missing kind", service.ErrInvalidArgument)
	}
	if c.PublicID == "" {
		return "", fmt.Errorf("%w: missing public_id", service.ErrInvalidArgument)
	}
	now := nowMs()
	if c.CreatedAtMs == 0 {
		c.CreatedAtMs = now
	}
	id := c.ID
	if id == "" {
		id = newID()
	}
	status := c.Status
	if status == "" {
		status = credentialStatusActive
	}
	const q = `
		INSERT INTO project_credentials (
			id, project_id, kind, public_id, secret_hash, status,
			created_at_ms, last_used_at_ms, revoked_at_ms
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)`
	if _, err := s.pool.Exec(
		ctx, q,
		id, c.ProjectID, c.Kind, c.PublicID, c.SecretHash, status,
		c.CreatedAtMs, c.LastUsedAtMs, c.RevokedAtMs,
	); err != nil {
		return "", wrapPgErr("CreateProjectCredential", err)
	}
	c.ID = id
	c.Status = status
	return id, nil
}

// GetProjectCredentialByPublicID resolves a credential (and thus its owning
// project_id, kind and status) by its globally-unique public_id, or returns
// (nil, nil) when none matches. This is the key-based per-request
// project-resolution path.
func (s *ProjectStore) GetProjectCredentialByPublicID(ctx context.Context, publicID string) (*ProjectCredential, error) {
	if publicID == "" {
		return nil, nil
	}
	const q = `SELECT ` + projectCredentialColumns + `
		FROM project_credentials
		WHERE public_id = $1`
	c, err := scanProjectCredential(s.pool.QueryRow(ctx, q, publicID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetProjectCredentialByPublicID", err)
	}
	return c, nil
}

// RevokeProjectCredential marks a credential revoked at atMs (defaulting to
// now when zero). Revoking is idempotent: an already-revoked or
// non-existent credential is a no-op that returns nil. A revoked credential
// no longer resolves a project for new requests, though the row is retained
// for audit.
func (s *ProjectStore) RevokeProjectCredential(ctx context.Context, credentialID string, atMs int64) error {
	if credentialID == "" {
		return errors.New("postgres: RevokeProjectCredential: missing credential id")
	}
	if atMs == 0 {
		atMs = nowMs()
	}
	const q = `
		UPDATE project_credentials
		   SET status = 'revoked',
		       revoked_at_ms = $2
		 WHERE id = $1 AND status <> 'revoked'`
	if _, err := s.pool.Exec(ctx, q, credentialID, atMs); err != nil {
		return wrapPgErr("RevokeProjectCredential", err)
	}
	return nil
}

// projectColumnsP is projectColumns qualified with the "p" alias, for the
// auth-domain → projects join in GetProjectByAuthHostname. Computed once at
// init since a function call cannot appear in a const expression.
var projectColumnsP = columnsPrefixed(projectColumns, "p")

// ── project_auth_domains ──────────────────────────────────────────────

const projectAuthDomainColumns = `
	id, project_id, hostname, is_primary, verified_at_ms, created_at_ms`

func scanProjectAuthDomain(row pgx.Row) (*ProjectAuthDomain, error) {
	var d ProjectAuthDomain
	if err := row.Scan(
		&d.ID, &d.ProjectID, &d.Hostname, &d.IsPrimary,
		&d.VerifiedAtMs, &d.CreatedAtMs,
	); err != nil {
		return nil, err
	}
	return &d, nil
}

// CreateProjectAuthDomain inserts a serving hostname for a project.
// Hostname is globally unique on lower(hostname) — a duplicate (in any
// case) surfaces service.ErrAlreadyExists. At most one is_primary domain is
// allowed per project (partial unique index); a second primary for the same
// project likewise surfaces service.ErrAlreadyExists. The id is
// caller-supplied (random hex when empty) and written back to d.ID.
func (s *ProjectStore) CreateProjectAuthDomain(ctx context.Context, d *ProjectAuthDomain) (string, error) {
	if d == nil {
		return "", errors.New("postgres: CreateProjectAuthDomain: nil auth domain")
	}
	if d.ProjectID == "" {
		return "", fmt.Errorf("%w: missing project_id", service.ErrInvalidArgument)
	}
	if d.Hostname == "" {
		return "", fmt.Errorf("%w: missing hostname", service.ErrInvalidArgument)
	}
	now := nowMs()
	if d.CreatedAtMs == 0 {
		d.CreatedAtMs = now
	}
	id := d.ID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO project_auth_domains (
			id, project_id, hostname, is_primary, verified_at_ms, created_at_ms
		) VALUES (
			$1, $2, $3, $4, $5, $6
		)`
	if _, err := s.pool.Exec(
		ctx, q,
		id, d.ProjectID, d.Hostname, d.IsPrimary, d.VerifiedAtMs, d.CreatedAtMs,
	); err != nil {
		return "", wrapPgErr("CreateProjectAuthDomain", err)
	}
	d.ID = id
	return id, nil
}

// GetProjectByAuthHostname resolves a project from a request's Host header.
// The hostname match is case-insensitive (lower(hostname)), matching the
// global unique index, so one host resolves to exactly one project. Returns
// (nil, nil) when no auth domain matches the host.
func (s *ProjectStore) GetProjectByAuthHostname(ctx context.Context, hostname string) (*Project, error) {
	if hostname == "" {
		return nil, nil
	}
	q := `SELECT ` + projectColumnsP + `
		FROM project_auth_domains d
		JOIN projects p ON p.id = d.project_id
		WHERE lower(d.hostname) = lower($1)`
	p, err := scanProject(s.pool.QueryRow(ctx, q, hostname))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetProjectByAuthHostname", err)
	}
	return p, nil
}

// ListProjectAuthDomains returns every auth domain for a project, ordered
// primary-first then by creation time, so callers can pick the
// link-building host deterministically. An unknown project yields an empty
// slice.
func (s *ProjectStore) ListProjectAuthDomains(ctx context.Context, projectID string) ([]*ProjectAuthDomain, error) {
	if projectID == "" {
		return nil, nil
	}
	const q = `SELECT ` + projectAuthDomainColumns + `
		FROM project_auth_domains
		WHERE project_id = $1
		ORDER BY is_primary DESC, created_at_ms ASC, id ASC`
	rows, err := s.pool.Query(ctx, q, projectID)
	if err != nil {
		return nil, wrapPgErr("ListProjectAuthDomains", err)
	}
	defer rows.Close()
	var out []*ProjectAuthDomain
	for rows.Next() {
		d, err := scanProjectAuthDomain(rows)
		if err != nil {
			return nil, wrapPgErr("ListProjectAuthDomains scan", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListProjectAuthDomains rows", err)
	}
	return out, nil
}
