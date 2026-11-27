package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

var _ service.ManagedHelpStore = (*MembershipStore)(nil)

// managedHelpLockKey serialises the help requests about one tenant's managed
// accounts, so its daily caps and its one-notice-per-account rule hold under
// concurrent requests.
func managedHelpLockKey(projectID, tenantID string) string {
	return advisoryKey("managed_help", projectID, tenantID)
}

// RecordManagedHelp implements service.ManagedHelpStore.
func (s *MembershipStore) RecordManagedHelp(ctx context.Context, req service.ManagedHelpRequest) (*service.ManagedHelpRecorded, error) {
	const op = "RecordManagedHelp"
	if req.ProjectID == "" || req.Address == "" || req.MaxPerTenant <= 0 || req.MaxPerTenantSource <= 0 {
		return nil, fmt.Errorf("%w: project, address and positive caps are required", service.ErrInvalidArgument)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, wrapPgErr(op, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := bindProject(ctx, tx, req.ProjectID); err != nil {
		return nil, wrapPgErr(op+"(bind)", err)
	}
	account, err := scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+`
		FROM users
		WHERE project_id = $1 AND email <> '' AND email_fold = $2 AND managed_by_tenant_id <> ''`,
		req.ProjectID, service.FoldEmail(req.Address)))
	if noRows(err) {
		return nil, fmt.Errorf("%w: no managed account at the address", service.ErrNotFound)
	}
	if err != nil {
		return nil, wrapPgErr(op+"(account)", err)
	}
	tenantID := account.ManagedByTenantID
	if err := lockXact(ctx, tx, op, managedHelpLockKey(req.ProjectID, tenantID)); err != nil {
		return nil, err
	}
	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM tenant_memberships
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3`, req.ProjectID, tenantID, account.ID).Scan(&status)
	if noRows(err) || (err == nil && status != service.MembershipStatusActive && status != service.MembershipStatusSuspended) {
		return nil, fmt.Errorf("%w: the managed account has no active or suspended membership", service.ErrNotFound)
	}
	if err != nil {
		return nil, wrapPgErr(op+"(membership)", err)
	}
	recipients, err := tenantGovernorAccounts(ctx, tx, req.ProjectID, tenantID, account.ID)
	if err != nil {
		return nil, wrapPgErr(op+"(recipients)", err)
	}
	if len(recipients) == 0 {
		return &service.ManagedHelpRecorded{Account: account, TenantID: tenantID, Outcome: service.ManagedHelpNoRecipients}, nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM managed_help_notices
		WHERE project_id = $1 AND tenant_id = $2 AND created_at_ms < $3`, req.ProjectID, tenantID, req.SinceMs); err != nil {
		return nil, wrapPgErr(op+"(expire)", err)
	}
	var forAccount, forTenant, forSource int
	if err := tx.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE user_id = $4),
			count(*),
			count(*) FILTER (WHERE source_key = $5)
		FROM managed_help_notices
		WHERE project_id = $1 AND tenant_id = $2 AND created_at_ms >= $3`,
		req.ProjectID, tenantID, req.SinceMs, account.ID, req.SourceKey).Scan(&forAccount, &forTenant, &forSource); err != nil {
		return nil, wrapPgErr(op+"(count)", err)
	}
	rec := &service.ManagedHelpRecorded{Account: account, TenantID: tenantID}
	switch {
	case forAccount > 0:
		rec.Outcome = service.ManagedHelpDuplicate
	case forTenant >= req.MaxPerTenant:
		rec.Outcome = service.ManagedHelpTenantLimited
	case forSource >= req.MaxPerTenantSource:
		rec.Outcome = service.ManagedHelpSourceLimited
	default:
		rec.Outcome = service.ManagedHelpNotify
	}
	if rec.Outcome == service.ManagedHelpNotify {
		if _, err := tx.Exec(ctx, `INSERT INTO managed_help_notices (
				id, project_id, tenant_id, user_id, source_key, created_at_ms
			) VALUES ($1, $2, $3, $4, $5, $6)`,
			newID(), req.ProjectID, tenantID, account.ID, req.SourceKey, req.NowMs); err != nil {
			return nil, wrapPgErr(op+"(record)", err)
		}
		rec.Recipients = recipients
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, wrapPgErr(op+"(commit)", err)
	}
	return rec, nil
}

// tenantGovernorAccounts returns the accounts of tenantID's active owners and
// admins that are active people with an address, other than except, in id
// order. tx must be bound to projectID.
func tenantGovernorAccounts(ctx context.Context, tx pgx.Tx, projectID, tenantID, except string) ([]*service.User, error) {
	rows, err := tx.Query(ctx, `SELECT `+userColumnsPrefixed("u")+`
		FROM tenant_memberships m
		JOIN users u ON u.project_id = m.project_id AND u.id = m.user_id
		WHERE m.project_id = $1 AND m.tenant_id = $2 AND m.status = $3 AND m.role IN ($4, $5)
		  AND u.id <> $6 AND u.status = $7 AND u.kind = $8 AND u.email <> ''
		ORDER BY u.id`,
		projectID, tenantID, service.MembershipStatusActive, service.RoleOwner, service.RoleAdmin,
		except, service.StatusActive, service.UserKindPerson)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*service.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
