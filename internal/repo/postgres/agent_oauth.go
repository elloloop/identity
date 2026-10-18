package postgres

import (
	"context"
	"encoding/json"

	"github.com/elloloop/identity/internal/service"
	"github.com/jackc/pgx/v5"
)

var _ service.AgentOAuthRepository = (*pgRepository)(nil)

const agentAuthorizationColumns = "data_json,revision,revoked_at_ms"

func scanAgentAuthorization(row pgx.Row) (*service.AgentAuthorization, error) {
	var encoded []byte
	var revision, revoked int64
	if err := row.Scan(&encoded, &revision, &revoked); err != nil {
		return nil, err
	}
	var out service.AgentAuthorization
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, err
	}
	out.Revision = revision
	out.RevokedAtMs = revoked
	return &out, nil
}

func (r *pgRepository) CreateAgentAuthorization(ctx context.Context, request *service.AgentAuthorization) error {
	if err := service.ValidateAgentAuthorization(request); err != nil {
		return err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	client, err := scanOAuthClient(tx.QueryRow(ctx, `SELECT `+oauthClientColumns+` FROM oauth_clients WHERE project_id=$1 AND id=$2 FOR UPDATE`, r.projectID, request.ClientID))
	if noRows(err) {
		return service.ErrPermissionDenied
	}
	if err != nil {
		return err
	}
	if client.Revision != request.ClientRevision || client.ValidateOAuthRequest(request.RedirectURI, request.Resource, request.Scopes, service.OAuthGrantAuthorizationCode) != nil {
		return service.ErrPermissionDenied
	}
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_authorizations(project_id,id,client_id,data_json,revision,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6)`, r.projectID, request.ID, request.ClientID, string(data), request.Revision, request.ExpiresAtMs)
	if err != nil {
		return wrapPgErr("CreateAgentAuthorization", err)
	}
	return tx.Commit(ctx)
}

func (r *pgRepository) GetAgentAuthorization(ctx context.Context, id string) (*service.AgentAuthorization, error) {
	out, err := scanAgentAuthorization(r.pool.QueryRow(ctx, `SELECT `+agentAuthorizationColumns+` FROM agent_authorizations WHERE project_id=$1 AND id=$2`, r.projectID, id))
	if noRows(err) {
		return nil, nil
	}
	return out, wrapPgErr("GetAgentAuthorization", err)
}

func (r *pgRepository) FindAgentAuthorizationByCode(ctx context.Context, hash string) (*service.AgentAuthorization, error) {
	out, err := scanAgentAuthorization(r.pool.QueryRow(ctx, `SELECT `+agentAuthorizationColumns+` FROM agent_authorizations WHERE project_id=$1 AND code_hash=$2 AND code_hash<>''`, r.projectID, hash))
	if noRows(err) {
		return nil, nil
	}
	return out, wrapPgErr("FindAgentAuthorizationByCode", err)
}

func (r *pgRepository) FindAgentAuthorizationByRefresh(ctx context.Context, hash string) (*service.AgentAuthorization, error) {
	out, err := scanAgentAuthorization(r.pool.QueryRow(ctx, `SELECT a.data_json,a.revision,a.revoked_at_ms FROM agent_authorizations a JOIN agent_oauth_refresh_tokens t ON t.project_id=a.project_id AND t.authorization_id=a.id WHERE a.project_id=$1 AND t.token_hash=$2`, r.projectID, hash))
	if noRows(err) {
		return nil, nil
	}
	return out, wrapPgErr("FindAgentAuthorizationByRefresh", err)
}

func (r *pgRepository) AgentOAuthAuthority(ctx context.Context, owner, agent, sid, client string) (service.AgentOAuthAuthority, error) {
	var a service.AgentOAuthAuthority
	var err error
	a.Owner, err = r.GetUser(ctx, owner)
	if err != nil {
		return a, err
	}
	if agent != "" {
		a.Agent, err = r.GetUser(ctx, agent)
		if err != nil {
			return a, err
		}
	}
	a.HumanSession, err = r.GetSessionBySid(ctx, sid)
	if err != nil {
		return a, err
	}
	a.Client, err = r.GetOAuthClient(ctx, client)
	if err != nil {
		return a, err
	}
	guardians, err := r.ListGuardiansOfChild(ctx, owner, 1, 0)
	a.HasGuardian = len(guardians) > 0
	return a, err
}

func (r *pgRepository) agentOAuthLockedAuthority(ctx context.Context, tx pgx.Tx, owner, agent, sid, client string, readOnly bool) (service.AgentOAuthAuthority, error) {
	lock := " FOR UPDATE"
	if readOnly {
		lock = " FOR SHARE"
	}
	var a service.AgentOAuthAuthority
	var err error
	a.Owner, err = scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE project_id=$1 AND id=$2 `+lock, r.projectID, owner))
	if noRows(err) {
		return a, nil
	}
	if err != nil {
		return a, err
	}
	guardians, err := tx.Query(ctx, `SELECT guardian_user_id FROM guardian_edges WHERE project_id=$1 AND child_user_id=$2 ORDER BY guardian_user_id FOR SHARE`, r.projectID, owner)
	if err != nil {
		return a, err
	}
	for guardians.Next() {
		a.HasGuardian = true
		var guardian string
		if err = guardians.Scan(&guardian); err != nil {
			guardians.Close()
			return a, err
		}
	}
	err = guardians.Err()
	guardians.Close()
	if err != nil {
		return a, err
	}
	if agent != "" {
		a.Agent, err = scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE project_id=$1 AND id=$2 `+lock, r.projectID, agent))
		if noRows(err) {
			return a, nil
		}
		if err != nil {
			return a, err
		}
	}
	a.Client, err = scanOAuthClient(tx.QueryRow(ctx, `SELECT `+oauthClientColumns+` FROM oauth_clients WHERE project_id=$1 AND id=$2 `+lock, r.projectID, client))
	if noRows(err) {
		return a, nil
	}
	if err != nil {
		return a, err
	}
	a.HumanSession, err = scanSession(tx.QueryRow(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE project_id=$1 AND sid=$2 `+lock, r.projectID, sid))
	if noRows(err) {
		return a, nil
	}
	return a, err
}

func (r *pgRepository) MutateAgentAuthorization(ctx context.Context, id string, m service.AgentOAuthMutation) (*service.AgentAuthorization, error) {
	initial, err := r.GetAgentAuthorization(ctx, id)
	if err != nil {
		return nil, err
	}
	if initial == nil {
		return nil, service.ErrAgentOAuthGrant
	}
	owner, agent, sid := initial.OwnerID, initial.AgentID, initial.HumanSID
	if m.Operation == service.AgentOAuthApprove || m.Operation == service.AgentOAuthDeny {
		owner, agent, sid = m.OwnerID, m.AgentID, m.HumanSID
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	authority, err := r.agentOAuthLockedAuthority(ctx, tx, owner, agent, sid, initial.ClientID, m.Operation == service.AgentOAuthValidate)
	if err != nil {
		return nil, err
	}
	lock := " FOR UPDATE"
	if m.Operation == service.AgentOAuthValidate {
		lock = " FOR SHARE"
	}
	if initial.MachineID != "" {
		machineLock := ""
		if m.Operation == service.AgentOAuthValidate {
			machineLock = " FOR SHARE"
		} else {
			machineLock = " FOR UPDATE"
		}
		authority.Machine, err = scanAgentMachine(tx.QueryRow(ctx, `SELECT `+agentMachineColumns+` FROM agent_machines WHERE project_id=$1 AND id=$2`+machineLock, r.projectID, initial.MachineID))
		if noRows(err) {
			return nil, service.ErrAgentOAuthGrant
		}
		if err != nil {
			return nil, err
		}
	}
	current, err := scanAgentAuthorization(tx.QueryRow(ctx, `SELECT `+agentAuthorizationColumns+` FROM agent_authorizations WHERE project_id=$1 AND id=$2`+lock, r.projectID, id))
	if noRows(err) {
		return nil, service.ErrAgentOAuthGrant
	}
	if err != nil {
		return nil, err
	}
	var refresh *service.AgentOAuthRefresh
	if m.RefreshHash != "" {
		refresh = &service.AgentOAuthRefresh{}
		err = tx.QueryRow(ctx, `SELECT token_hash,authorization_id,expires_at_ms,consumed_at_ms FROM agent_oauth_refresh_tokens WHERE project_id=$1 AND token_hash=$2 FOR UPDATE`, r.projectID, m.RefreshHash).Scan(&refresh.Hash, &refresh.AuthorizationID, &refresh.ExpiresAtMs, &refresh.ConsumedAtMs)
		if noRows(err) {
			refresh = nil
		} else if err != nil {
			return nil, err
		}
	}
	next, applyErr := service.ApplyAgentOAuthMutation(current, authority, refresh, m)
	if next == nil {
		return nil, applyErr
	}
	if m.Operation == service.AgentOAuthValidate {
		return next, nil
	}
	data, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE agent_authorizations SET owner_id=$3,agent_id=$4,human_sid=$5,code_hash=$6,data_json=$7,revision=$8,revoked_at_ms=$9,expires_at_ms=$10 WHERE project_id=$1 AND id=$2`, r.projectID, id, next.OwnerID, next.AgentID, next.HumanSID, next.CodeHash, string(data), next.Revision, next.RevokedAtMs, max(next.ExpiresAtMs, next.GrantExpiresAtMs))
	if err != nil {
		return nil, wrapPgErr("MutateAgentAuthorization", err)
	}
	if applyErr == nil && m.Operation == service.AgentOAuthRotate {
		_, err = tx.Exec(ctx, `UPDATE agent_oauth_refresh_tokens SET consumed_at_ms=$3 WHERE project_id=$1 AND token_hash=$2 AND consumed_at_ms=0`, r.projectID, m.RefreshHash, m.AtMs)
		if err != nil {
			return nil, err
		}
	}
	if applyErr == nil && m.NextRefreshHash != "" {
		_, err = tx.Exec(ctx, `INSERT INTO agent_oauth_refresh_tokens(project_id,token_hash,authorization_id,expires_at_ms) VALUES($1,$2,$3,$4)`, r.projectID, m.NextRefreshHash, id, m.RefreshExpiresAtMs)
		if err != nil {
			return nil, wrapPgErr("MutateAgentAuthorization", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return next, applyErr
}

func (r *pgRepository) ListAgentAuthorizations(ctx context.Context, owner, after string, limit int) ([]*service.AgentAuthorization, error) {
	if owner == "" || limit < 1 || limit > service.MaxAgentOAuthListLimit {
		return nil, service.ErrInvalidArgument
	}
	rows, err := r.pool.Query(ctx, `SELECT `+agentAuthorizationColumns+` FROM agent_authorizations WHERE project_id=$1 AND owner_id=$2 AND id COLLATE "C">$3 ORDER BY id COLLATE "C" ASC LIMIT $4`, r.projectID, owner, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*service.AgentAuthorization, 0)
	for rows.Next() {
		record, err := scanAgentAuthorization(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func (r *pgRepository) DeleteExpiredAgentAuthorizations(ctx context.Context, beforeMs int64, limit int) error {
	if limit < 1 || limit > service.MaxUserListLimit {
		return service.ErrInvalidArgument
	}
	_, err := r.pool.Exec(ctx, `DELETE FROM agent_authorizations WHERE project_id=$1 AND id IN(SELECT id FROM agent_authorizations WHERE project_id=$1 AND machine_id IS NULL AND expires_at_ms>0 AND expires_at_ms<$2 ORDER BY expires_at_ms,id LIMIT $3)`, r.projectID, beforeMs, limit)
	return err
}
