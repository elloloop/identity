package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

// Postgres-backed LoginPolicyStore over migration 0013's login_policies
// table — at most one policy per (project_id, tenant_id), enforced by
// login_policies_project_tenant_uidx. Postgres-only and project-scoped,
// like the other governance stores.

var _ service.LoginPolicyStore = (*LoginPolicyStore)(nil)

// LoginPolicyStore persists per-tenant login policies within a Project.
type LoginPolicyStore struct {
	pool *tracedPool
}

// NewLoginPolicyStore builds a store sharing the repository's pool.
func NewLoginPolicyStore(r *pgRepository) *LoginPolicyStore {
	return &LoginPolicyStore{pool: r.pool}
}

const loginPolicyColumns = `
	id, project_id, tenant_id, allowed_methods, sso_required,
	sso_connection_json, require_2fa, password_min_length,
	session_idle_timeout_seconds,
	session_absolute_timeout_seconds, created_at_ms, updated_at_ms`

func scanLoginPolicy(row pgx.Row) (*service.LoginPolicy, error) {
	var p service.LoginPolicy
	if err := row.Scan(
		&p.ID, &p.ProjectID, &p.TenantID, &p.AllowedMethods, &p.SSORequired,
		&p.SSOConnectionJSON, &p.Require2FA, &p.PasswordMinLength,
		&p.SessionIdleTimeoutSeconds,
		&p.SessionAbsoluteTimeoutSeconds, &p.CreatedAtMs, &p.UpdatedAtMs,
	); err != nil {
		return nil, err
	}
	return &p, nil
}

// UpsertLoginPolicy inserts or replaces the policy for (ProjectID,
// TenantID). On conflict it updates the policy fields and stamps
// updated_at_ms, leaving id and created_at_ms intact. Returns the id of
// the resulting row.
func (s *LoginPolicyStore) UpsertLoginPolicy(ctx context.Context, p *service.LoginPolicy) (string, error) {
	if p == nil {
		return "", errors.New("postgres: UpsertLoginPolicy: nil policy")
	}
	if p.ProjectID == "" || p.TenantID == "" {
		return "", fmt.Errorf("%w: project_id and tenant_id are required", service.ErrInvalidArgument)
	}
	now := nowMs()
	if p.CreatedAtMs == 0 {
		p.CreatedAtMs = now
	}
	id := p.ID
	if id == "" {
		id = newID()
	}
	ssoConn := p.SSOConnectionJSON
	if ssoConn == "" {
		ssoConn = "{}"
	}
	// id and created_at_ms are only used on INSERT; on conflict the
	// existing row keeps its own. RETURNING id yields whichever id won so
	// the caller always learns the row's real id.
	const q = `
		INSERT INTO login_policies (
			id, project_id, tenant_id, allowed_methods, sso_required,
			sso_connection_json, require_2fa, password_min_length,
			session_idle_timeout_seconds,
			session_absolute_timeout_seconds, created_at_ms, updated_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11, $11)
		ON CONFLICT (project_id, tenant_id) DO UPDATE SET
			allowed_methods                  = EXCLUDED.allowed_methods,
			sso_required                     = EXCLUDED.sso_required,
			sso_connection_json              = EXCLUDED.sso_connection_json,
			require_2fa                      = EXCLUDED.require_2fa,
			password_min_length              = EXCLUDED.password_min_length,
			session_idle_timeout_seconds     = EXCLUDED.session_idle_timeout_seconds,
			session_absolute_timeout_seconds = EXCLUDED.session_absolute_timeout_seconds,
			updated_at_ms                    = EXCLUDED.updated_at_ms
		RETURNING id`
	var outID string
	if err := s.pool.QueryRow(
		ctx, q,
		id, p.ProjectID, p.TenantID, p.AllowedMethods, p.SSORequired,
		ssoConn, p.Require2FA, p.PasswordMinLength,
		p.SessionIdleTimeoutSeconds, p.SessionAbsoluteTimeoutSeconds, now,
	).Scan(&outID); err != nil {
		return "", wrapPgErr("UpsertLoginPolicy", err)
	}
	p.ID = outID
	p.SSOConnectionJSON = ssoConn
	p.UpdatedAtMs = now
	return outID, nil
}

// GetLoginPolicy returns the policy for (projectID, tenantID), or
// (nil, nil) when none is set.
func (s *LoginPolicyStore) GetLoginPolicy(ctx context.Context, projectID, tenantID string) (*service.LoginPolicy, error) {
	if projectID == "" || tenantID == "" {
		return nil, nil
	}
	const q = `SELECT ` + loginPolicyColumns + `
		FROM login_policies WHERE project_id = $1 AND tenant_id = $2`
	p, err := scanLoginPolicy(s.pool.QueryRow(ctx, q, projectID, tenantID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("GetLoginPolicy", err)
	}
	return p, nil
}

// DeleteLoginPolicy removes the policy for (projectID, tenantID). It is
// idempotent: deleting an absent policy affects no row and returns nil. Both
// ids are required.
func (s *LoginPolicyStore) DeleteLoginPolicy(ctx context.Context, projectID, tenantID string) error {
	if projectID == "" || tenantID == "" {
		return fmt.Errorf("%w: project_id and tenant_id are required", service.ErrInvalidArgument)
	}
	const q = `DELETE FROM login_policies WHERE project_id = $1 AND tenant_id = $2`
	if _, err := s.pool.Exec(ctx, q, projectID, tenantID); err != nil {
		return wrapPgErr("DeleteLoginPolicy", err)
	}
	return nil
}
