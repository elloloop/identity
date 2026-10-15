package sqlite

import (
	"context"

	"github.com/elloloop/identity/internal/service"
)

func (r *sqliteRepository) CreateAgent(ctx context.Context, request service.AgentCreation) (*service.User, bool, error) {
	if err := service.ValidateAgentCreation(request); err != nil {
		return nil, false, err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Become the SQLite writer before reading; a deferred read transaction
	// cannot safely upgrade after another writer commits the same retry key.
	if _, err = tx.Exec(ctx, `UPDATE users SET id=id WHERE project_id=$1 AND id=$2`, r.projectID, request.CallerID); err != nil {
		return nil, false, err
	}
	people := make(map[string]*service.User, 2)
	for _, id := range []string{request.CallerID, request.Agent.OwnerUserID} {
		person, readErr := scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE project_id=$1 AND id=$2`, r.projectID, id))
		if readErr != nil && !noRows(readErr) {
			return nil, false, readErr
		}
		people[id] = person
	}

	if err = service.CheckAgentCreationAuthority(people[request.CallerID], people[request.Agent.OwnerUserID]); err != nil {
		return nil, false, err
	}
	if request.RequestID != "" {
		receipt := service.AgentCreationReceipt{CallerID: request.CallerID, RequestID: request.RequestID}
		const lookup = `SELECT fingerprint,agent_id,owner_id,invalidated FROM agent_creation_receipts WHERE project_id=$1 AND caller_id=$2 AND request_id=$3`
		err = tx.QueryRow(ctx, lookup, r.projectID, request.CallerID, request.RequestID).Scan(&receipt.Fingerprint, &receipt.AgentID, &receipt.OwnerID, &receipt.Invalidated)
		if err == nil {
			agent, readErr := scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE project_id=$1 AND id=$2`, r.projectID, receipt.AgentID))
			if readErr != nil && !noRows(readErr) {
				return nil, false, readErr
			}
			if err = service.CheckAgentCreationReplay(receipt, request, agent); err != nil {
				return nil, false, err
			}
			if err = tx.Commit(ctx); err != nil {
				return nil, false, err
			}
			return agent, false, nil
		}
		if !noRows(err) {
			return nil, false, err
		}
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE project_id=$1 AND kind='agent' AND owner_user_id<>'' AND owner_user_id=$2`, r.projectID, request.Agent.OwnerUserID).Scan(&count); err != nil {
		return nil, false, err
	}
	if count >= request.OwnerLimit {
		return nil, false, service.ErrAgentLimitReached
	}
	agent := *request.Agent
	id, role, status := defaultNewUserFields(&agent)
	if _, err = tx.Exec(ctx, insertUserQuery, insertUserArgs(r.projectID, id, role, status, &agent)...); err != nil {
		return nil, false, wrapErr("create agent subject", err)
	}
	if request.RequestID != "" {
		if _, err = tx.Exec(ctx, `INSERT INTO agent_creation_receipts(project_id,caller_id,request_id,fingerprint,agent_id,owner_id,invalidated) VALUES($1,$2,$3,$4,$5,$6,false)`, r.projectID, request.CallerID, request.RequestID, request.Fingerprint, id, agent.OwnerUserID); err != nil {
			return nil, false, wrapErr("create agent receipt", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	agent.ID = id
	return &agent, true, nil
}
