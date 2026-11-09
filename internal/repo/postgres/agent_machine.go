package postgres

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

var _ service.AgentMachineRepository = (*pgRepository)(nil)

const agentMachineColumns = "data_json,revision,revoked_at_ms"

func scanAgentMachine(row interface{ Scan(...any) error }) (*service.AgentMachine, error) {
	var data []byte
	var revision, revoked int64
	if err := row.Scan(&data, &revision, &revoked); err != nil {
		return nil, err
	}
	var m service.AgentMachine
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	m.Revision, m.RevokedAtMs = revision, revoked
	return &m, nil
}

func (r *pgRepository) GetAgentMachine(ctx context.Context, id string) (*service.AgentMachine, error) {
	m, err := scanAgentMachine(r.pool.QueryRow(ctx, `SELECT `+agentMachineColumns+` FROM agent_machines WHERE project_id=$1 AND id=$2`, r.projectID, id))
	if noRows(err) {
		return nil, nil
	}
	return m, wrapPgErr("GetAgentMachine", err)
}

func (r *pgRepository) CreateAgentMachine(ctx context.Context, input *service.AgentMachine, fingerprint string) (*service.AgentMachine, error) {
	if err := service.ValidateAgentMachine(input); err != nil {
		return nil, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	a, err := r.agentOAuthLockedAuthority(ctx, tx, input.OwnerID, "", input.RegistrationSID, input.ClientID, false)
	if err != nil {
		return nil, err
	}
	if !a.ValidMachineRegistration(input) || a.Fingerprint() != fingerprint {
		return nil, service.ErrAgentOAuthGrant
	}
	current, err := scanAgentMachine(tx.QueryRow(ctx, `SELECT `+agentMachineColumns+` FROM agent_machines WHERE project_id=$1 AND id=$2 FOR UPDATE`, r.projectID, input.ID))
	if err != nil && !noRows(err) {
		return nil, err
	}
	if current != nil {
		var data []byte
		if err = tx.QueryRow(ctx, `SELECT registration_json FROM agent_machines WHERE project_id=$1 AND id=$2`, r.projectID, input.ID).Scan(&data); err != nil {
			return nil, err
		}
		var original service.AgentMachine
		if err = json.Unmarshal(data, &original); err != nil {
			return nil, err
		}
		if service.SameAgentMachineRegistration(&original, input) {
			return current, tx.Commit(ctx)
		}
		// A revoked registration is replaced when the same owner registers the
		// installation again with a new key on a fresh sign-in. Another owner, a
		// registration still active, or the revoked key itself never comes back.
		if current.RevokedAtMs == 0 || current.OwnerID != input.OwnerID || current.PublicKey == input.PublicKey {
			return nil, service.ErrAlreadyExists
		}
		return r.replaceRevokedAgentMachine(ctx, tx, current, input)
	}
	data, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_machines(project_id,id,owner_id,client_id,data_json,registration_json,revision,revoked_at_ms) VALUES($1,$2,$3,$4,$5,$5,$6,$7)`, r.projectID, input.ID, input.OwnerID, input.ClientID, string(data), input.Revision, input.RevokedAtMs)
	if err != nil {
		return nil, wrapPgErr("CreateAgentMachine", err)
	}
	return input.Clone(), tx.Commit(ctx)
}

func (r *pgRepository) ListAgentMachines(ctx context.Context, owner, after string, limit int) ([]*service.AgentMachine, error) {
	if owner == "" || limit < 1 || limit > service.MaxAgentOAuthListLimit {
		return nil, service.ErrInvalidArgument
	}
	rows, err := r.pool.Query(ctx, `SELECT `+agentMachineColumns+` FROM agent_machines WHERE project_id=$1 AND owner_id=$2 AND id COLLATE "C">$3 ORDER BY id COLLATE "C" LIMIT $4`, r.projectID, owner, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*service.AgentMachine, 0)
	for rows.Next() {
		m, err := scanAgentMachine(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (r *pgRepository) AgentMachineAuthority(ctx context.Context, id, agent string) (service.AgentOAuthAuthority, error) {
	m, err := r.GetAgentMachine(ctx, id)
	if err != nil || m == nil {
		return service.AgentOAuthAuthority{}, err
	}
	a, err := r.AgentOAuthAuthority(ctx, m.OwnerID, agent, "", m.ClientID)
	a.Machine = m
	return a, err
}

func (r *pgRepository) MutateAgentMachine(ctx context.Context, id string, mutation service.AgentMachineMutation) (*service.AgentMachine, error) {
	initial, err := r.GetAgentMachine(ctx, id)
	if err != nil {
		return nil, err
	}
	if initial == nil {
		return nil, service.ErrPermissionDenied
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	a, err := r.agentOAuthLockedAuthority(ctx, tx, initial.OwnerID, "", "", initial.ClientID, false)
	if err != nil {
		return nil, err
	}
	current, err := scanAgentMachine(tx.QueryRow(ctx, `SELECT `+agentMachineColumns+` FROM agent_machines WHERE project_id=$1 AND id=$2 FOR UPDATE`, r.projectID, id))
	if noRows(err) {
		return nil, service.ErrPermissionDenied
	}
	if err != nil {
		return nil, err
	}
	next, err := service.ApplyAgentMachineMutation(current, mutation)
	if err != nil {
		return nil, err
	}
	if mutation.Operation != service.AgentMachineRevoke && !a.ValidMachine(current) {
		return nil, service.ErrAgentOAuthGrant
	}
	data, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE agent_machines SET data_json=$3,revision=$4,revoked_at_ms=$5 WHERE project_id=$1 AND id=$2`, r.projectID, id, string(data), next.Revision, next.RevokedAtMs)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT `+agentAuthorizationColumns+` FROM agent_authorizations WHERE project_id=$1 AND machine_id=$2 AND revoked_at_ms=0 ORDER BY id FOR UPDATE`, r.projectID, id)
	if err != nil {
		return nil, err
	}
	var revoked []string
	for rows.Next() {
		child, err := scanAgentAuthorization(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if !next.Allows(child.AgentID) {
			revoked = append(revoked, child.ID)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, child := range revoked {
		if _, err = tx.Exec(ctx, `UPDATE agent_authorizations SET revoked_at_ms=$3,revision=revision+1 WHERE project_id=$1 AND id=$2 AND revoked_at_ms=0`, r.projectID, child, mutation.AtMs); err != nil {
			return nil, err
		}
	}
	return next, tx.Commit(ctx)
}

func (r *pgRepository) EnsureAgentMachineDelegation(ctx context.Context, id string, candidate *service.AgentAuthorization, hash, fingerprint string) (*service.AgentAuthorization, error) {
	if candidate == nil {
		return nil, service.ErrAgentOAuthGrant
	}
	initial, err := r.GetAgentMachine(ctx, id)
	if err != nil {
		return nil, err
	}
	if initial == nil {
		return nil, service.ErrAgentOAuthGrant
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	a, err := r.agentOAuthLockedAuthority(ctx, tx, initial.OwnerID, candidate.AgentID, "", initial.ClientID, false)
	if err != nil {
		return nil, err
	}
	machine, err := scanAgentMachine(tx.QueryRow(ctx, `SELECT `+agentMachineColumns+` FROM agent_machines WHERE project_id=$1 AND id=$2 FOR UPDATE`, r.projectID, id))
	if noRows(err) {
		return nil, service.ErrAgentOAuthGrant
	}
	if err != nil {
		return nil, err
	}
	a.Machine = machine
	if err = service.ValidateMachineDelegation(machine, a, candidate, hash, fingerprint); err != nil {
		return nil, err
	}
	existing, err := scanAgentAuthorization(tx.QueryRow(ctx, `SELECT `+agentAuthorizationColumns+` FROM agent_authorizations WHERE project_id=$1 AND machine_id=$2 AND agent_id=$3 FOR UPDATE`, r.projectID, id, candidate.AgentID))
	if err != nil && !noRows(err) {
		return nil, err
	}
	if existing != nil {
		// The revocation that ended this delegation is the one the machine
		// registered again after (CreateAgentMachine): the delegation is renewed
		// for the new registration, under a new agent key. One ended at another
		// time, such as by the owner excluding the agent, stays ended.
		if existing.RevokedAtMs != 0 && machine.RenewedAfterRevokedAtMs != 0 &&
			existing.RevokedAtMs == machine.RenewedAfterRevokedAtMs {
			if existing.MachinePublicKey == candidate.MachinePublicKey {
				return nil, service.ErrAgentOAuthGrant
			}
			return r.renewRevokedAgentDelegation(ctx, tx, existing, candidate)
		}
		if !a.Valid(existing) || existing.MachinePublicKey != candidate.MachinePublicKey {
			return nil, service.ErrAgentOAuthGrant
		}
		return existing, tx.Commit(ctx)
	}
	data, err := json.Marshal(candidate)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_authorizations(project_id,id,client_id,owner_id,agent_id,machine_id,data_json,revision,revoked_at_ms,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,0,0)`, r.projectID, candidate.ID, candidate.ClientID, candidate.OwnerID, candidate.AgentID, candidate.MachineID, string(data), candidate.Revision)
	if err != nil {
		return nil, wrapPgErr("EnsureAgentMachineDelegation", err)
	}
	return candidate.Clone(), tx.Commit(ctx)
}

// replaceRevokedAgentMachine registers a revoked machine of the same owner again
// under its installation id: the new registration takes the row with the next
// revision and no revocation, remembers the revocation it recovered from, and
// drops the challenges issued to the old key. Delegations the revocation ended
// stay ended until each is ensured again for the new registration.
func (r *pgRepository) replaceRevokedAgentMachine(ctx context.Context, tx pgx.Tx, current, input *service.AgentMachine) (*service.AgentMachine, error) {
	renewed := input.Clone()
	renewed.Revision, renewed.RevokedAtMs, renewed.RenewedAfterRevokedAtMs = current.Revision+1, 0, current.RevokedAtMs
	data, err := json.Marshal(renewed)
	if err != nil {
		return nil, err
	}
	// registration_json keeps the request as presented, so a replay of this
	// renewal reads as the same registration.
	requested, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_machines SET owner_id=$3,client_id=$4,data_json=$5,registration_json=$6,revision=$7,revoked_at_ms=0 WHERE project_id=$1 AND id=$2`,
		r.projectID, renewed.ID, renewed.OwnerID, renewed.ClientID, string(data), string(requested), renewed.Revision); err != nil {
		return nil, wrapPgErr("CreateAgentMachine", err)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM agent_machine_challenges WHERE project_id=$1 AND machine_id=$2`, r.projectID, renewed.ID); err != nil {
		return nil, wrapPgErr("CreateAgentMachine", err)
	}
	// A delegation left at the revocation this registration had itself recovered
	// from, never ensured again since, follows to the latest one, so it is not
	// stranded behind two renewals.
	if current.RenewedAfterRevokedAtMs != 0 {
		if _, err = tx.Exec(ctx, `UPDATE agent_authorizations SET revoked_at_ms=$3,revision=revision+1 WHERE project_id=$1 AND machine_id=$2 AND revoked_at_ms=$4`,
			r.projectID, renewed.ID, current.RevokedAtMs, current.RenewedAfterRevokedAtMs); err != nil {
			return nil, wrapPgErr("CreateAgentMachine", err)
		}
	}
	return renewed, tx.Commit(ctx)
}

// renewRevokedAgentDelegation gives the delegation a machine's renewed
// registration ended back to that agent, in place: the row keeps its id and
// takes the candidate's key and terms with the next revision and no revocation.
func (r *pgRepository) renewRevokedAgentDelegation(ctx context.Context, tx pgx.Tx, existing, candidate *service.AgentAuthorization) (*service.AgentAuthorization, error) {
	renewed := candidate.Clone()
	renewed.ID, renewed.Revision, renewed.RevokedAtMs, renewed.ExpiresAtMs = existing.ID, existing.Revision+1, 0, 0
	data, err := json.Marshal(renewed)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_authorizations SET client_id=$3,owner_id=$4,agent_id=$5,machine_id=$6,data_json=$7,revision=$8,revoked_at_ms=0,expires_at_ms=0 WHERE project_id=$1 AND id=$2`,
		r.projectID, renewed.ID, renewed.ClientID, renewed.OwnerID, renewed.AgentID, renewed.MachineID, string(data), renewed.Revision); err != nil {
		return nil, wrapPgErr("EnsureAgentMachineDelegation", err)
	}
	return renewed, tx.Commit(ctx)
}
