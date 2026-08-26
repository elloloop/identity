package postgres

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

// CreateManagedChildAccount persists the three artifacts of the
// parent-creates-child flow — the child user row, the (guardian -> child)
// edge, and the parental-consent record — in ONE transaction, so a partial
// state (an account without its edge, an edge without its consent record) is
// never reachable. A duplicate username violates the partial unique index
// (0032) and surfaces as service.ErrAlreadyExists with NOTHING committed.
//
// The transaction runs on the pool connection the PrepareConn hook already
// bound to this repository's project (the app.current_project_id GUC), so the
// RLS policies on users / guardian_edges / parental_consents admit the writes.
func (r *pgRepository) CreateManagedChildAccount(ctx context.Context, u *service.User, edge *service.GuardianEdge, consent *service.ParentalConsentRecord) error {
	if u == nil || edge == nil || consent == nil {
		return errors.New("postgres: CreateManagedChildAccount: nil user, edge, or consent")
	}
	if edge.GuardianUserID == "" {
		return errors.New("postgres: CreateManagedChildAccount: missing guardian user id")
	}
	if consent.ConsentID == "" {
		return errors.New("postgres: CreateManagedChildAccount: missing consent id")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return wrapPgErr("CreateManagedChildAccount", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	id, role, status := defaultNewUserFields(u)
	if _, err := tx.Exec(ctx, insertUserQuery, insertUserArgs(r.projectID, id, role, status, u)...); err != nil {
		return wrapPgErr("CreateManagedChildAccount(user)", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO guardian_edges (project_id, guardian_user_id, child_user_id, created_at_ms)
		VALUES ($1, $2, $3, $4)`,
		r.projectID, edge.GuardianUserID, id, edge.CreatedAtMs); err != nil {
		return wrapPgErr("CreateManagedChildAccount(edge)", err)
	}

	if _, err := tx.Exec(ctx, insertParentalConsentQuery,
		insertParentalConsentArgs(r.projectID, id, consent)...); err != nil {
		return wrapPgErr("CreateManagedChildAccount(consent)", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return wrapPgErr("CreateManagedChildAccount", err)
	}
	u.ID = id
	edge.ProjectID = r.projectID
	edge.ChildUserID = id
	consent.ProjectID = r.projectID
	consent.ChildUserID = id
	return nil
}
