package postgres

import (
	"context"
	"sort"

	"github.com/elloloop/identity/internal/service"
)

func (r *pgRepository) CreateAgent(ctx context.Context, request service.AgentCreation) (*service.User, bool, error) {
	if err := service.ValidateAgentCreation(request); err != nil {
		return nil, false, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// A row lock serializes retries by caller and creations against the same
	// owner, across replicas. Stable ordering avoids opposite-owner deadlocks.
	ids := []string{request.CallerID, request.Agent.OwnerUserID}
	sort.Strings(ids)
	people := make(map[string]*service.User, 2)
	for _, id := range ids {
		if people[id] != nil {
			continue
		}
		person, readErr := scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE project_id=$1 AND id=$2 FOR UPDATE`, r.projectID, id))
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
			agent, readErr := scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE project_id=$1 AND id=$2 FOR UPDATE`, r.projectID, receipt.AgentID))
			if readErr != nil && !noRows(readErr) {
				return nil, false, readErr
			}
			// A concurrent lifecycle writer may have invalidated the receipt while
			// we waited for the subject lock; read its committed tombstone again.
			if err = tx.QueryRow(ctx, lookup, r.projectID, request.CallerID, request.RequestID).Scan(&receipt.Fingerprint, &receipt.AgentID, &receipt.OwnerID, &receipt.Invalidated); err != nil {
				return nil, false, err
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
		return nil, false, wrapPgErr("create agent subject", err)
	}
	if request.RequestID != "" {
		if _, err = tx.Exec(ctx, `INSERT INTO agent_creation_receipts(project_id,caller_id,request_id,fingerprint,agent_id,owner_id,invalidated) VALUES($1,$2,$3,$4,$5,$6,false)`, r.projectID, request.CallerID, request.RequestID, request.Fingerprint, id, agent.OwnerUserID); err != nil {
			return nil, false, wrapPgErr("create agent receipt", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	agent.ID = id
	return &agent, true, nil
}
