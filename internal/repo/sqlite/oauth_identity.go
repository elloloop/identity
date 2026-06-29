package sqlite

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

func (r *sqliteRepository) FindUserByProviderID(ctx context.Context, provider, providerUserID string) (*service.User, error) {
	if provider == "" || providerUserID == "" {
		return nil, nil
	}
	q := `
		SELECT ` + userColumnsPrefixed("u") + `
		  FROM oauth_identities oi
		  JOIN users u ON u.id = oi.user_id AND u.project_id = oi.project_id
		 WHERE oi.project_id = $1
		   AND oi.provider = $2
		   AND oi.provider_user_id = $3
		 LIMIT 1`
	u, err := scanUser(r.db.QueryRow(ctx, q, r.projectID, provider, providerUserID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr("FindUserByProviderID", err)
	}
	return u, nil
}

func (r *sqliteRepository) CreateOAuthIdentity(ctx context.Context, oi *service.OAuthIdentity) error {
	if oi == nil {
		return errors.New("sqlite: CreateOAuthIdentity: nil record")
	}
	id := oi.NodeID
	if id == "" {
		id = newID()
	}
	const q = `
		INSERT INTO oauth_identities (
			id, project_id, user_id, provider, provider_user_id, email_at_link_time, created_at_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.db.Exec(ctx, q, id, r.projectID, oi.UserID, oi.Provider, oi.ProviderUserID, oi.EmailAtLinkTime, oi.CreatedAt)
	if err != nil {
		return wrapErr("CreateOAuthIdentity", err)
	}
	oi.NodeID = id
	return nil
}

func (r *sqliteRepository) ListOAuthIdentitiesForUser(ctx context.Context, userID string) ([]*service.OAuthIdentity, error) {
	if userID == "" {
		return nil, nil
	}
	const q = `
		SELECT id, user_id, provider, provider_user_id, email_at_link_time, created_at_ms
		  FROM oauth_identities
		 WHERE project_id = $1 AND user_id = $2
		 ORDER BY created_at_ms ASC`
	rs, err := r.db.Query(ctx, q, r.projectID, userID)
	if err != nil {
		return nil, wrapErr("ListOAuthIdentitiesForUser", err)
	}
	defer rs.Close()
	out := make([]*service.OAuthIdentity, 0)
	for rs.Next() {
		var oi service.OAuthIdentity
		if err := rs.Scan(&oi.NodeID, &oi.UserID, &oi.Provider, &oi.ProviderUserID, &oi.EmailAtLinkTime, &oi.CreatedAt); err != nil {
			return nil, wrapErr("ListOAuthIdentitiesForUser", err)
		}
		out = append(out, &oi)
	}
	if err := rs.Err(); err != nil {
		return nil, wrapErr("ListOAuthIdentitiesForUser", err)
	}
	return out, nil
}

func (r *sqliteRepository) DeleteOAuthIdentity(ctx context.Context, userID, provider, providerUserID string) error {
	if userID == "" || provider == "" || providerUserID == "" {
		return service.ErrNotFound
	}
	const q = `
		DELETE FROM oauth_identities
		 WHERE project_id = $1 AND user_id = $2 AND provider = $3 AND provider_user_id = $4`
	tag, err := r.db.Exec(ctx, q, r.projectID, userID, provider, providerUserID)
	if err != nil {
		return wrapErr("DeleteOAuthIdentity", err)
	}
	if tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	return nil
}
