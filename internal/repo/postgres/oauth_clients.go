package postgres

import (
	"context"
	"encoding/json"

	"github.com/elloloop/identity/internal/service"
)

const oauthClientColumns = "id, kind, registration_json, revision, created_at_ms, updated_at_ms"

func scanOAuthClient(row interface{ Scan(...any) error }) (*service.OAuthClient, error) {
	var client service.OAuthClient
	var registration []byte
	if err := row.Scan(&client.ID, &client.Kind, &registration, &client.Revision, &client.CreatedAt, &client.UpdatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(registration, &client.Registration); err != nil {
		return nil, err
	}
	return &client, nil
}

func (r *pgRepository) CreateOAuthClient(ctx context.Context, client *service.OAuthClient) error {
	if err := service.ValidateNewOAuthClient(client); err != nil {
		return err
	}
	registration, err := json.Marshal(client.Registration)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `INSERT INTO oauth_clients (project_id, `+oauthClientColumns+`) VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7)`, r.projectID, client.ID, client.Kind, string(registration), client.Revision, client.CreatedAt, client.UpdatedAt)
	return wrapPgErr("CreateOAuthClient", err)
}

func (r *pgRepository) GetOAuthClient(ctx context.Context, id string) (*service.OAuthClient, error) {
	client, err := scanOAuthClient(r.pool.QueryRow(ctx, `SELECT `+oauthClientColumns+` FROM oauth_clients WHERE project_id=$1 AND id=$2`, r.projectID, id))
	if noRows(err) {
		return nil, nil
	}
	return client, wrapPgErr("GetOAuthClient", err)
}

func (r *pgRepository) UpdateOAuthClient(ctx context.Context, id string, expected int64, registration *service.OAuthClientRegistration, atMs int64) (*service.OAuthClient, error) {
	if err := service.ValidateOAuthClientUpdate(id, expected, registration, atMs); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(registration)
	if err != nil {
		return nil, err
	}
	client, err := scanOAuthClient(r.pool.QueryRow(ctx, `UPDATE oauth_clients SET registration_json=$4::jsonb, revision=revision+1, updated_at_ms=$5 WHERE project_id=$1 AND id=$2 AND revision=$3 RETURNING `+oauthClientColumns, r.projectID, id, expected, string(encoded), atMs))
	if noRows(err) {
		return nil, nil
	}
	return client, wrapPgErr("UpdateOAuthClient", err)
}

func (r *pgRepository) ListOAuthClients(ctx context.Context, afterID string, limit int) ([]*service.OAuthClient, error) {
	if err := service.ValidateOAuthClientPage(afterID, limit); err != nil {
		return nil, err
	}
	rows, err := r.pool.Query(ctx, `SELECT `+oauthClientColumns+` FROM oauth_clients WHERE project_id=$1 AND id COLLATE "C">$2 ORDER BY id COLLATE "C" ASC LIMIT $3`, r.projectID, afterID, limit)
	if err != nil {
		return nil, wrapPgErr("ListOAuthClients", err)
	}
	defer rows.Close()
	clients := make([]*service.OAuthClient, 0)
	for rows.Next() {
		client, err := scanOAuthClient(rows)
		if err != nil {
			return nil, wrapPgErr("ListOAuthClients", err)
		}
		clients = append(clients, client)
	}
	return clients, wrapPgErr("ListOAuthClients", rows.Err())
}
