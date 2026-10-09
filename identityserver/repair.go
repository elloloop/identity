package identityserver

import (
	"context"
	"errors"

	"github.com/elloloop/identity/internal/service"
)

// EmailRepairReport is one stored-email repair run: a decision per account
// stored under a non-canonical spelling, and whether it was applied.
type EmailRepairReport = service.EmailRepairReport

// EmailRepairItem is the repair's decision for one account.
type EmailRepairItem = service.EmailRepairItem

// EmailRepairAction is what the repair does to one account.
type EmailRepairAction = service.EmailRepairAction

// The repair's actions.
const (
	EmailRepairRewrite = service.EmailRepairRewrite
	EmailRepairMerge   = service.EmailRepairMerge
	EmailRepairSkip    = service.EmailRepairSkip
)

// RepairStoredEmails moves every account's stored email to its canonical
// form, in every project, planning per mailbox. Two accounts of one Gmail
// mailbox, both verified, are merged, keeping the account a sign-in provider
// is linked to; anything it cannot decide safely is reported, not touched.
// With apply false it writes nothing and reports what it would do, which is
// exactly what apply then does. Merges are audited, announced to the person
// and emitted as user.merged events like any other. It is idempotent.
//
// Call it on a Server built by New; Start is not needed. A process that exits
// afterwards calls DrainEvents first, or the user.merged events it queued are
// lost with it.
func (s *Server) RepairStoredEmails(ctx context.Context, apply bool) (*EmailRepairReport, error) {
	if s.built == nil {
		return nil, errors.New("identityserver: RepairStoredEmails on a server New did not build")
	}
	return s.built.RepairStoredEmails(ctx, apply)
}

// DrainEvents delivers the webhook events this Server has queued, retrying as
// its worker does, until none is left or ctx ends, and returns how many were
// not delivered: still queued, or abandoned after the last attempt. A serving process does not need it: Start's worker
// delivers. With webhooks off it returns 0 at once.
func (s *Server) DrainEvents(ctx context.Context) (int, error) {
	if s.built == nil {
		return 0, errors.New("identityserver: DrainEvents on a server New did not build")
	}
	return s.built.DrainEvents(ctx)
}
