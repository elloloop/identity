package service

import (
	"context"
	"errors"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/emailaddr"
)

// Accounts stored before every write path canonicalized can still hold
// another spelling of their mailbox ("first.last@gmail.com" for the canonical
// "firstlast@gmail.com"). Every lookup canonicalizes what it is given, so such
// an account is found only by its own spelling: a code or password sign-in
// with the canonical spelling misses it and signs up a second account, and
// LookupUsers never finds it. storeCanonicalEmail moves the stored address to
// the canonical form, the one form every lookup can reach.

// errCanonicalEmailHeld reports that another live account already holds the
// canonical form of an account's stored email: two accounts for one mailbox.
// Rewriting is left alone; the pair is merged first (see
// AdminService.RepairStoredEmails).
var errCanonicalEmailHeld = errors.New("another account holds the canonical form of this account's email")

// canonicalEmailRewrite is what storeCanonicalEmail changed.
type canonicalEmailRewrite struct {
	// Rewritten is true when the account's stored email changed.
	Rewritten bool
	// FreedFrom names the account merged into this one that held the
	// canonical spelling and gave it up, or "".
	FreedFrom string
}

// storeCanonicalEmail rewrites u's stored email to its canonical form when it
// is stored as another spelling of the same mailbox, and updates u in place.
// The verified state carries over: the mailbox is the same one.
//
// When an account already merged into u holds the canonical spelling, it gives
// it up first; a merged-away account never signs in again, so the address is
// u's. Any other holder is errCanonicalEmailHeld and nothing is written. A
// rewrite interrupted between the two writes leaves the canonical spelling
// unheld and u unchanged, which the next call completes.
func storeCanonicalEmail(ctx context.Context, repo Repository, u *User, nowMs int64) (canonicalEmailRewrite, error) {
	var out canonicalEmailRewrite
	if u == nil || u.ID == "" || u.Email == "" {
		return out, nil
	}
	canonical := emailaddr.Canonicalize(u.Email)
	if canonical == u.Email {
		return out, nil
	}
	holder, err := repo.FindUserByEmail(ctx, canonical)
	if err != nil {
		return out, err
	}
	if holder != nil && holder.ID != u.ID {
		if holder.MergedIntoUserID != u.ID {
			return out, errCanonicalEmailHeld
		}
		if err := repo.UpdateUser(ctx, holder.ID, map[string]any{
			"email": "", "email_verified": false, "email_verified_at": int64(0), "updated_at": nowMs,
		}); err != nil {
			return out, err
		}
		out.FreedFrom = holder.ID
	}
	if err := repo.UpdateUser(ctx, u.ID, map[string]any{"email": canonical, "updated_at": nowMs}); err != nil {
		return out, err
	}
	u.Email = canonical
	out.Rewritten = true
	return out, nil
}

// auditEmailCanonicalized records a stored email moved to its canonical form.
// It carries no address: the account id and what prompted the rewrite are
// enough to trace it, and the address itself is on the account.
func auditEmailCanonicalized(ctx context.Context, log *audit.Logger, actorID, userID, source string, rw canonicalEmailRewrite) {
	details := map[string]any{"source": source}
	if rw.FreedFrom != "" {
		details["freed_from"] = rw.FreedFrom
	}
	log.Log(ctx, audit.EventEmailCanonicalized,
		audit.WithActor(actorID), audit.WithTarget(userID),
		audit.WithSuccess(true), audit.WithDetails(details))
}

// ensureCanonicalEmail moves a signing-in account's stored email to its
// canonical form, so the next sign-in by any spelling of the mailbox finds
// this account. It runs at the token chokepoint, so every sign-in reaches it,
// a provider sign-in that found the account by its provider id included. It
// never fails the sign-in: a canonical spelling another account holds is
// logged and left for an operator to merge.
func (s *AuthService) ensureCanonicalEmail(ctx context.Context, u *User) {
	rw, err := storeCanonicalEmail(ctx, s.repo(ctx), u, s.nowMs())
	switch {
	case errors.Is(err, errCanonicalEmailHeld):
		s.logger.Info("email_canonical_form_held", zap.String("project_id", s.projectID(ctx)), zap.String("user_id", u.ID))
	case err != nil:
		s.logger.Warn("email_canonicalize_failed", zap.String("project_id", s.projectID(ctx)), zap.String("user_id", u.ID), zap.Error(err))
	case rw.Rewritten:
		auditEmailCanonicalized(ctx, s.audit, u.ID, u.ID, "sign_in", rw)
	}
}
