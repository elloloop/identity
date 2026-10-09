package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/emailaddr"
)

// Repairing stored emails.
//
// A sign-in moves its own account's email to the canonical form
// (ensureCanonicalEmail), but only an account that signs in, and never one
// whose canonical form another account holds: two accounts for one mailbox,
// typically a provider sign-up stored under a dotted Gmail spelling and a later
// code or password sign-up under the canonical one. The repair is the
// operator's one-time pass over every project.
//
// It plans per mailbox: every account whose stored email canonicalizes to the
// same address is one group, decided once, from one snapshot read before
// anything is written. Groups are disjoint, so applying one decision cannot
// change another, and --apply does exactly what the dry run listed. A group
// that holds a non-canonical spelling is:
//
//   - one account: its email is rewritten (the canonical form is free, or held
//     by an account already merged into it);
//   - two active accounts of one Gmail mailbox, both with a verified email,
//     neither managed by an identity provider, exactly one linked to a sign-in
//     provider: merged, keeping the provider-linked account, and the survivor's
//     email rewritten;
//   - anything else: left as it is, with the reason, for MergeUsers.
//
// Merging needs both emails verified because nobody proves control of either
// account here: an unverified account under one spelling could have been
// planted by someone who does not own the mailbox, and a merge would hand its
// password to the owner's account. It is limited to Gmail, the provider known
// to deliver every spelling it folds (dots and "+tag") to one inbox; elsewhere
// a "+tag" can be a different person's mailbox.
//
// It is idempotent: a group is planned only while it holds a non-canonical
// spelling, and a decided group no longer does.

// EmailRepairAction is what the repair does, or would do, to one mailbox.
type EmailRepairAction string

const (
	// EmailRepairRewrite moves the stored email to its canonical form.
	EmailRepairRewrite EmailRepairAction = "rewrite"
	// EmailRepairMerge merges two accounts of one mailbox, then rewrites the
	// survivor's email when it is the non-canonical one.
	EmailRepairMerge EmailRepairAction = "merge"
	// EmailRepairSkip leaves the mailbox's accounts as they are; Reason says
	// why.
	EmailRepairSkip EmailRepairAction = "skip"
)

// EmailRepairItem is the repair's decision for one mailbox. It names accounts
// by id only, never by address.
type EmailRepairItem struct {
	ProjectID string
	// UserID is the account stored under a non-canonical spelling (the first,
	// by id, when there are several).
	UserID string
	Action EmailRepairAction
	// SurvivorID and RetiredID name the pair of a merge.
	SurvivorID, RetiredID string
	// OtherIDs are the mailbox's other unmerged accounts, for a skip.
	OtherIDs []string
	// Reason says why a mailbox was skipped.
	Reason string
	// Error is set when deciding or applying failed on a store error; the
	// mailbox is left for the next run.
	Error string
}

// EmailRepairReport is one repair run: a decision per mailbox, and whether
// the decisions were applied.
type EmailRepairReport struct {
	Applied bool
	Items   []EmailRepairItem
}

// Count returns how many items have the given action.
func (r *EmailRepairReport) Count(action EmailRepairAction) int {
	n := 0
	for _, it := range r.Items {
		if it.Action == action {
			n++
		}
	}
	return n
}

// Failed returns how many items failed on a store error.
func (r *EmailRepairReport) Failed() int {
	n := 0
	for _, it := range r.Items {
		if it.Error != "" {
			n++
		}
	}
	return n
}

// ProjectLister lists the id of every project in the control plane, the
// projects the repair walks, suspended ones included: their accounts sign in
// again once the project is resumed.
type ProjectLister interface {
	ListProjectIDs(ctx context.Context) ([]string, error)
}

// Skip reasons.
const (
	repairReasonMergedElsewhere = "the canonical form belongs to an account merged into another account"
	repairReasonNotRewritable   = "no mailbox is left once canonical, or a +tag outside Gmail would be dropped"
	repairReasonInactive        = "one of the accounts is not active"
	repairReasonTooMany         = "more than two accounts share the mailbox"
	repairReasonNotGmail        = "the spellings differ by a +tag outside Gmail, which can be another person's mailbox"
	repairReasonUnverified      = "an account's email is not verified, so nothing proves it belongs to the mailbox's owner"
	repairReasonIDPManaged      = "an identity provider manages one of the accounts"
	repairReasonNoProviderSplit = "neither or both accounts are linked to a sign-in provider"
	repairSourceMerge           = "email_repair"
	gmailCanonicalDomain        = "@gmail.com"
)

// RepairStoredEmails runs the repair over projectIDs. With apply false it
// writes nothing and reports what it would do. It returns an error only when
// it cannot read a project; a store failure on one mailbox is recorded on its
// item and the run continues.
func (s *AdminService) RepairStoredEmails(ctx context.Context, projectIDs []string, apply bool) (*EmailRepairReport, error) {
	report := &EmailRepairReport{Applied: apply}
	for _, projectID := range projectIDs {
		pctx := WithProjectScope(ctx, &ProjectScope{ProjectID: projectID})
		repo := s.repo(pctx)
		groups, err := mailboxGroups(pctx, repo)
		if err != nil {
			return report, fmt.Errorf("project %s: %w", projectID, err)
		}
		for _, g := range groups {
			item := s.planMailbox(pctx, repo, g)
			item.ProjectID = projectID
			if apply && item.Error == "" {
				s.applyMailbox(pctx, repo, g, &item)
			}
			report.Items = append(report.Items, item)
		}
	}
	return report, nil
}

// mailboxGroup is every account of one project whose stored email
// canonicalizes to canonical.
type mailboxGroup struct {
	canonical string
	// live are the accounts not merged away, by id.
	live []*User
	// mergedHolder is an account merged away that still holds the canonical
	// spelling, or nil.
	mergedHolder *User
}

// mailboxGroups reads every account of the project, all pages before
// anything changes, and returns the groups that hold a non-canonical spelling
// on an account not merged away, ordered by canonical address.
func mailboxGroups(ctx context.Context, repo Repository) ([]*mailboxGroup, error) {
	byMailbox := map[string]*mailboxGroup{}
	for offset := 0; ; offset += MaxUserListLimit {
		page, err := repo.ListUsers(ctx, UserListFilter{Offset: offset, Limit: MaxUserListLimit})
		if err != nil {
			return nil, err
		}
		for _, u := range page {
			if u.Email == "" {
				continue
			}
			c := emailaddr.Canonicalize(u.Email)
			g := byMailbox[c]
			if g == nil {
				g = &mailboxGroup{canonical: c}
				byMailbox[c] = g
			}
			switch {
			case u.MergedIntoUserID == "":
				g.live = append(g.live, u)
			case FoldEmail(u.Email) == FoldEmail(c):
				g.mergedHolder = u
			}
		}
		if len(page) < MaxUserListLimit {
			break
		}
	}
	var out []*mailboxGroup
	for _, g := range byMailbox {
		if g.needsRepair() {
			sort.Slice(g.live, func(i, j int) bool { return g.live[i].ID < g.live[j].ID })
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].canonical < out[j].canonical })
	return out, nil
}

func (g *mailboxGroup) needsRepair() bool {
	for _, u := range g.live {
		if u.Email != g.canonical {
			return true
		}
	}
	return false
}

// firstNonCanonical is the account the item names.
func (g *mailboxGroup) firstNonCanonical() *User {
	for _, u := range g.live {
		if u.Email != g.canonical {
			return u
		}
	}
	return nil
}

// planMailbox decides one mailbox from the snapshot. It reads only the
// accounts' provider links and the merge preconditions.
func (s *AdminService) planMailbox(ctx context.Context, repo Repository, g *mailboxGroup) EmailRepairItem {
	item := EmailRepairItem{UserID: g.firstNonCanonical().ID, Action: EmailRepairSkip}
	for _, u := range g.live {
		if u.ID != item.UserID {
			item.OtherIDs = append(item.OtherIDs, u.ID)
		}
	}
	// releasable reports whether the merged-away holder of the canonical
	// spelling, if any, gives it up to survivor.
	releasable := func(survivor *User) bool {
		return g.mergedHolder == nil || g.mergedHolder.MergedIntoUserID == survivor.ID
	}
	if len(g.live) == 1 {
		if _, err := canonicalRewriteTarget(g.live[0].Email); err != nil {
			item.Reason = repairReasonNotRewritable
			return item
		}
		if !releasable(g.live[0]) {
			item.Reason = repairReasonMergedElsewhere
			return item
		}
		item.Action = EmailRepairRewrite
		return item
	}
	if reason := mergeableMailbox(g); reason != "" {
		item.Reason = reason
		return item
	}
	survivor, retired, err := chooseRepairSurvivor(ctx, repo, g.live[0], g.live[1])
	switch {
	case err != nil:
		item.Error = err.Error()
		return item
	case survivor == nil:
		item.Reason = repairReasonNoProviderSplit
		return item
	case survivor.Email != g.canonical && !releasable(survivor):
		item.Reason = repairReasonMergedElsewhere
		return item
	}
	if survivor.Email != g.canonical {
		if _, err := canonicalRewriteTarget(survivor.Email); err != nil {
			item.Reason = repairReasonNotRewritable
			return item
		}
	}
	if err := checkMergeable(ctx, repo, survivor, retired); err != nil {
		if errors.Is(err, ErrMergeRefused) {
			item.Reason = err.Error()
		} else {
			item.Error = err.Error()
		}
		return item
	}
	item.Action, item.SurvivorID, item.RetiredID = EmailRepairMerge, survivor.ID, retired.ID
	return item
}

// mergeableMailbox returns why two or more accounts of one mailbox cannot be
// merged here, or "" when the pair can.
func mergeableMailbox(g *mailboxGroup) string {
	if len(g.live) > 2 {
		return repairReasonTooMany
	}
	a, b := g.live[0], g.live[1]
	switch {
	case a.Status != StatusActive || b.Status != StatusActive:
		return repairReasonInactive
	case !strings.HasSuffix(g.canonical, gmailCanonicalDomain):
		return repairReasonNotGmail
	case !a.EmailVerified || !b.EmailVerified:
		return repairReasonUnverified
	case a.ExternalID != "" || b.ExternalID != "":
		return repairReasonIDPManaged
	}
	return ""
}

// chooseRepairSurvivor keeps the account a sign-in provider is linked to: the
// provider resolves its sign-ins by that link, and the account the person
// signs in to that way is the one they use. It returns a nil survivor when
// both or neither are linked.
func chooseRepairSurvivor(ctx context.Context, repo Repository, a, b *User) (survivor, retired *User, err error) {
	aLinks, err := repo.ListOAuthIdentitiesForUser(ctx, a.ID)
	if err != nil {
		return nil, nil, err
	}
	bLinks, err := repo.ListOAuthIdentitiesForUser(ctx, b.ID)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case len(aLinks) > 0 && len(bLinks) == 0:
		return a, b, nil
	case len(bLinks) > 0 && len(aLinks) == 0:
		return b, a, nil
	}
	return nil, nil, nil
}

// applyMailbox carries out a planned rewrite or merge. A merge goes through
// the same transaction as every merge and is audited and announced like one;
// the survivor's email is rewritten after it, in a second write a re-run
// completes if it is interrupted.
func (s *AdminService) applyMailbox(ctx context.Context, repo Repository, g *mailboxGroup, item *EmailRepairItem) {
	switch item.Action {
	case EmailRepairRewrite:
		s.applyRewrite(ctx, repo, g.live[0], item)
	case EmailRepairMerge:
		survivor, retired := g.live[0], g.live[1]
		if survivor.ID != item.SurvivorID {
			survivor, retired = retired, survivor
		}
		merged, retiredAfter, err := mergeAccounts(ctx, repo, survivor, retired, false, nowMs())
		if err != nil {
			item.Error = err.Error()
			return
		}
		s.audit.Log(ctx, audit.EventAccountMerged,
			audit.WithTarget(retiredAfter.ID), audit.WithSuccess(true),
			audit.WithDetails(map[string]any{"survivor": merged.ID, "source": repairSourceMerge}))
		announceMerge(ctx, s.mergeAnnouncer(ctx), retired, merged, retiredAfter)
		s.applyRewrite(ctx, repo, merged, item)
	}
}

func (s *AdminService) applyRewrite(ctx context.Context, repo Repository, u *User, item *EmailRepairItem) {
	rw, err := storeCanonicalEmail(ctx, repo, u, nowMs())
	if err != nil {
		item.Error = err.Error()
		return
	}
	if rw.Rewritten {
		auditEmailCanonicalized(ctx, s.audit, "", u.ID, canonicalSourceRepair, rw)
	}
}
