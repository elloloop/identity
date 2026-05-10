package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

func (r *pgRepository) FindUserByProviderID(ctx context.Context, provider, providerUserID string) (*service.User, error) {
	if provider == "" || providerUserID == "" {
		return nil, nil
	}
	const q = `
		SELECT u.id, u.email, u.name, u.role, u.avatar_url, u.status, u.recovery_email,
		       u.password_hash, u.quota_bytes, u.totp_required,
		       u.failed_login_count, u.locked_until_ms,
		       u.email_verified, u.email_verified_at_ms,
		       u.idv_verified, u.idv_verified_at_ms,
		       u.last_login_at_ms,
		       u.created_at_ms, u.updated_at_ms
		  FROM oauth_identities oi
		  JOIN users u ON u.id = oi.user_id AND u.tenant_id = oi.tenant_id
		 WHERE oi.tenant_id = $1
		   AND oi.provider = $2
		   AND oi.provider_user_id = $3
		 LIMIT 1`
	row := r.pool.QueryRow(ctx, q, r.tenantID, provider, providerUserID)
	u, err := scanUser(row)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapPgErr("FindUserByProviderID", err)
	}
	return u, nil
}

func (r *pgRepository) CreateOAuthIdentity(ctx context.Context, oi *service.OAuthIdentity) error {
	if oi == nil {
		return errors.New("postgres: CreateOAuthIdentity: nil record")
	}
	id := oi.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO oauth_identities (
			id, tenant_id, user_id, provider, provider_user_id,
			email_at_link_time, created_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.pool.Exec(ctx, q,
		id, r.tenantID, oi.UserID, oi.Provider, oi.ProviderUserID,
		oi.EmailAtLinkTime, oi.CreatedAt,
	)
	if err != nil {
		return wrapPgErr("CreateOAuthIdentity", err)
	}
	oi.NodeID = id
	return nil
}

func (r *pgRepository) ListOAuthIdentitiesForUser(ctx context.Context, userID string) ([]*service.OAuthIdentity, error) {
	if userID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, user_id, provider, provider_user_id, email_at_link_time, created_at_ms
		  FROM oauth_identities
		 WHERE tenant_id = $1 AND user_id = $2
		 ORDER BY created_at_ms ASC`
	rows, err := r.pool.Query(ctx, q, r.tenantID, userID)
	if err != nil {
		return nil, wrapPgErr("ListOAuthIdentitiesForUser", err)
	}
	defer rows.Close()
	out := make([]*service.OAuthIdentity, 0)
	for rows.Next() {
		var oi service.OAuthIdentity
		if err := rows.Scan(&oi.NodeID, &oi.UserID, &oi.Provider, &oi.ProviderUserID, &oi.EmailAtLinkTime, &oi.CreatedAt); err != nil {
			return nil, wrapPgErr("ListOAuthIdentitiesForUser", err)
		}
		out = append(out, &oi)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr("ListOAuthIdentitiesForUser", err)
	}
	return out, nil
}

// pgx.Rows compile-time assertion for clarity.
var _ pgx.Rows = (pgx.Rows)(nil)
