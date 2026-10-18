package postgres

import (
	"context"
	"encoding/json"

	"github.com/elloloop/identity/internal/service"
)

func (r *pgRepository) GetAgentMachineDelegation(ctx context.Context, machine, agent string) (*service.AgentAuthorization, error) {
	grant, err := scanAgentAuthorization(r.pool.QueryRow(ctx, `SELECT `+agentAuthorizationColumns+` FROM agent_authorizations WHERE project_id=$1 AND machine_id=$2 AND agent_id=$3`, r.projectID, machine, agent))
	if noRows(err) {
		return nil, nil
	}
	return grant, err
}

func (r *pgRepository) CreateAgentMachineChallenge(ctx context.Context, input *service.AgentMachineChallenge) error {
	if !service.ValidAgentMachineChallenge(input) {
		return service.ErrInvalidArgument
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var revoked int64
	err = tx.QueryRow(ctx, `SELECT revoked_at_ms FROM agent_machines WHERE project_id=$1 AND id=$2 FOR UPDATE`, r.projectID, input.MachineID).Scan(&revoked)
	if noRows(err) {
		return service.ErrAgentOAuthGrant
	}
	if err != nil {
		return err
	}
	if revoked != 0 {
		return service.ErrAgentOAuthGrant
	}
	if _, err = tx.Exec(ctx, `DELETE FROM agent_machine_challenges WHERE project_id=$1 AND machine_id=$2 AND expires_at_ms<=$3`, r.projectID, input.MachineID, input.CreatedAtMs); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT COUNT(*) FROM agent_machine_challenges WHERE project_id=$1 AND machine_id=$2`, r.projectID, input.MachineID).Scan(&count); err != nil {
		return err
	}
	if count >= service.MaxAgentMachineChallenges {
		return service.ErrAgentMachineChallengeLimit
	}
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO agent_machine_challenges(project_id,id,machine_id,data_json,created_at_ms,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6)`, r.projectID, input.ID, input.MachineID, string(data), input.CreatedAtMs, input.ExpiresAtMs); err != nil {
		return wrapPgErr("CreateAgentMachineChallenge", err)
	}
	return tx.Commit(ctx)
}

func (r *pgRepository) GetAgentMachineChallenge(ctx context.Context, id string) (*service.AgentMachineChallenge, error) {
	var data []byte
	err := r.pool.QueryRow(ctx, `SELECT data_json FROM agent_machine_challenges WHERE project_id=$1 AND id=$2`, r.projectID, id).Scan(&data)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var challenge service.AgentMachineChallenge
	if err = json.Unmarshal(data, &challenge); err != nil {
		return nil, err
	}
	return &challenge, nil
}

func (r *pgRepository) ConsumeAgentMachineChallenge(ctx context.Context, id string, now int64) (bool, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM agent_machine_challenges WHERE project_id=$1 AND id=$2 AND created_at_ms<=$3 AND expires_at_ms>$3`, r.projectID, id, now)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (r *pgRepository) DeleteExpiredAgentMachineChallenges(ctx context.Context, before int64, limit int) error {
	if limit < 1 || limit > 10000 {
		return service.ErrInvalidArgument
	}
	_, err := r.pool.Exec(ctx, `DELETE FROM agent_machine_challenges WHERE project_id=$1 AND id IN (SELECT id FROM agent_machine_challenges WHERE project_id=$1 AND expires_at_ms<=$2 ORDER BY expires_at_ms,id LIMIT $3)`, r.projectID, before, limit)
	return err
}
