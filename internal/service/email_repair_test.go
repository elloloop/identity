package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

const repairProject = "test-tenant"

func repairFixture(t *testing.T) (*AdminService, *fakeRepo, *recordingAuditWriter) {
	t.Helper()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	return newTestAdminServiceWithAudit(newFakeDB(), repo, writer), repo, writer
}

// seedVerified seeds an active account whose email is verified.
func seedVerified(repo *fakeRepo, email, passwordHash string) *User {
	u := seedUser(repo, email, passwordHash, StatusActive)
	u.EmailVerified = true
	return u
}

func linkProvider(t *testing.T, repo *fakeRepo, u *User, sub string) {
	t.Helper()
	require.NoError(t, repo.CreateOAuthIdentity(context.Background(), &OAuthIdentity{
		UserID: u.ID, Provider: "google", ProviderUserID: sub, CreatedAt: 1,
	}))
}

func storedUser(t *testing.T, repo *fakeRepo, id string) *User {
	t.Helper()
	u, err := repo.GetUser(context.Background(), id)
	require.NoError(t, err)
	return u
}

func runRepair(t *testing.T, svc *AdminService, apply bool) *EmailRepairReport {
	t.Helper()
	report, err := svc.RepairStoredEmails(context.Background(), []string{repairProject}, apply)
	require.NoError(t, err)
	require.Equal(t, apply, report.Applied)
	return report
}

// dryThenApply runs the repair as an operator does and checks that --apply
// did exactly what the dry run listed.
func dryThenApply(t *testing.T, svc *AdminService) *EmailRepairReport {
	t.Helper()
	dry := runRepair(t, svc, false)
	applied := runRepair(t, svc, true)
	require.Equal(t, dry.Items, applied.Items, "--apply does what the dry run listed")
	require.Zero(t, applied.Failed())
	require.Empty(t, runRepair(t, svc, false).Items, "a second run finds nothing to do")
	return applied
}

// The case that splits one person into two accounts: a provider sign-up
// stored under a dotted Gmail spelling, then a code sign-up stored under the
// canonical one.
func TestRepairStoredEmails_MergesTwoAccountsOfOneMailbox(t *testing.T) {
	svc, repo, writer := repairFixture(t)
	legacy := seedVerified(repo, "first.last@gmail.com", "")
	linkProvider(t, repo, legacy, "g-1")
	duplicate := seedVerified(repo, "firstlast@gmail.com", "")
	seedVerified(repo, "someone@example.com", "")

	dry := runRepair(t, svc, false)
	require.Equal(t, []EmailRepairItem{{
		ProjectID: repairProject, UserID: legacy.ID, Action: EmailRepairMerge,
		SurvivorID: legacy.ID, RetiredID: duplicate.ID, OtherIDs: []string{duplicate.ID},
	}}, dry.Items, "only the mailbox with a non-canonical spelling is planned")
	require.Equal(t, "first.last@gmail.com", storedUser(t, repo, legacy.ID).Email, "a dry run writes nothing")
	require.Zero(t, writer.countByEventType("account_merged"))

	dryThenApply(t, svc)
	survivor := storedUser(t, repo, legacy.ID)
	require.Equal(t, "firstlast@gmail.com", survivor.Email)
	require.Equal(t, StatusActive, survivor.Status)
	retired := storedUser(t, repo, duplicate.ID)
	require.Equal(t, StatusDeactivated, retired.Status)
	require.Equal(t, legacy.ID, retired.MergedIntoUserID)
	require.Empty(t, retired.Email, "the retired account gave the canonical spelling up")
	require.Equal(t, 1, writer.countByEventTypeAndDetail("account_merged", "source", "email_repair"))
	require.Equal(t, 1, writer.countByEventTypeAndDetail("email_canonicalized", "freed_from", duplicate.ID))
}

// When the canonical account is the provider-linked one, the non-canonical
// account is the one retired, and nothing is left to rewrite.
func TestRepairStoredEmails_KeepsTheProviderLinkedAccount(t *testing.T) {
	svc, repo, writer := repairFixture(t)
	legacy := seedVerified(repo, "first.last@gmail.com", hashPW(t, accessTestPassword))
	linked := seedVerified(repo, "firstlast@gmail.com", "")
	linkProvider(t, repo, linked, "g-1")

	report := dryThenApply(t, svc)
	require.Equal(t, linked.ID, report.Items[0].SurvivorID)
	survivor := storedUser(t, repo, linked.ID)
	require.Equal(t, "firstlast@gmail.com", survivor.Email)
	require.NotEmpty(t, survivor.PasswordHash, "a verified account's password moves to the survivor")
	require.Equal(t, linked.ID, storedUser(t, repo, legacy.ID).MergedIntoUserID)
	require.Zero(t, writer.countByEventType("email_canonicalized"))
}

// An unverified account under one spelling may have been planted by someone
// who does not own the mailbox: merging it would hand its password to the
// owner's provider-linked account.
func TestRepairStoredEmails_NeverMergesAnUnverifiedAccount(t *testing.T) {
	svc, repo, writer := repairFixture(t)
	owner := seedVerified(repo, "first.last@gmail.com", "")
	linkProvider(t, repo, owner, "g-1")
	planted := seedUser(repo, "firstlast@gmail.com", hashPW(t, accessTestPassword), StatusActive)

	report := dryThenApplySkips(t, svc)
	require.Equal(t, repairReasonUnverified, report.Items[0].Reason)
	require.Empty(t, storedUser(t, repo, owner.ID).PasswordHash, "no password reaches the owner's account")
	require.Equal(t, StatusActive, storedUser(t, repo, planted.ID).Status)
	require.Zero(t, writer.countByEventType("account_merged"))
}

// dryThenApplySkips is dryThenApply for a run that only skips: the skip is
// reported again on every run.
func dryThenApplySkips(t *testing.T, svc *AdminService) *EmailRepairReport {
	t.Helper()
	dry := runRepair(t, svc, false)
	applied := runRepair(t, svc, true)
	require.Equal(t, dry.Items, applied.Items)
	for _, it := range applied.Items {
		require.Equal(t, EmailRepairSkip, it.Action, it.UserID)
	}
	return applied
}

// Two non-canonical spellings of one free canonical form are one mailbox,
// decided once: the dry run lists the merge the apply performs.
func TestRepairStoredEmails_TwoNonCanonicalSpellingsAreOneMailbox(t *testing.T) {
	svc, repo, _ := repairFixture(t)
	a := seedVerified(repo, "first.last@gmail.com", "")
	linkProvider(t, repo, a, "g-1")
	b := seedVerified(repo, "First.Last+news@googlemail.com", "")

	report := dryThenApply(t, svc)
	require.Len(t, report.Items, 1)
	require.Equal(t, EmailRepairMerge, report.Items[0].Action)
	require.Equal(t, "firstlast@gmail.com", storedUser(t, repo, a.ID).Email)
	require.Equal(t, a.ID, storedUser(t, repo, b.ID).MergedIntoUserID)
}

func TestRepairStoredEmails_RewritesAFreeOrReleasedSpelling(t *testing.T) {
	svc, repo, writer := repairFixture(t)
	free := seedUser(repo, "a.b+tag@googlemail.com", "", StatusActive)
	survivor := seedUser(repo, "c.d@gmail.com", "", StatusActive)
	retired := seedUser(repo, "cd@gmail.com", "", StatusDeactivated)
	retired.MergedIntoUserID = survivor.ID
	elsewhere := seedUser(repo, "e.f@gmail.com", "", StatusActive)
	mergedElsewhere := seedUser(repo, "ef@gmail.com", "", StatusDeactivated)
	mergedElsewhere.MergedIntoUserID = free.ID

	report := dryThenApplyAllowingSkips(t, svc)
	require.Equal(t, 2, report.Count(EmailRepairRewrite))
	require.Equal(t, "ab@gmail.com", storedUser(t, repo, free.ID).Email)
	require.Equal(t, "cd@gmail.com", storedUser(t, repo, survivor.ID).Email)
	require.Empty(t, storedUser(t, repo, retired.ID).Email)
	require.Equal(t, 2, writer.countByEventTypeAndDetail("email_canonicalized", "source", "repair"))

	require.Equal(t, 1, report.Count(EmailRepairSkip))
	require.Equal(t, "e.f@gmail.com", storedUser(t, repo, elsewhere.ID).Email,
		"a canonical spelling an account merged into ANOTHER account holds is not taken")
	require.Equal(t, "ef@gmail.com", storedUser(t, repo, mergedElsewhere.ID).Email)
}

// dryThenApplyAllowingSkips is dryThenApply for a run that also skips: the
// skips remain, everything else is done.
func dryThenApplyAllowingSkips(t *testing.T, svc *AdminService) *EmailRepairReport {
	t.Helper()
	dry := runRepair(t, svc, false)
	applied := runRepair(t, svc, true)
	require.Equal(t, dry.Items, applied.Items)
	require.Zero(t, applied.Failed())
	for _, it := range runRepair(t, svc, false).Items {
		require.Equal(t, EmailRepairSkip, it.Action, "only skips remain")
	}
	return applied
}

func TestRepairStoredEmails_LeavesWhatItCannotDecide(t *testing.T) {
	svc, repo, writer := repairFixture(t)
	reasonFor := map[string]string{}
	pair := func(dotted, canonical string, reason string, tweak func(dotted, canonical *User)) {
		d := seedVerified(repo, dotted, "")
		c := seedVerified(repo, canonical, "")
		tweak(d, c)
		reasonFor[d.ID] = reason
	}
	link := func(u *User) { linkProvider(t, repo, u, "sub-"+u.ID) }
	pair("n.one@gmail.com", "none@gmail.com", repairReasonNoProviderSplit, func(_, _ *User) {})
	pair("b.oth@gmail.com", "both@gmail.com", repairReasonNoProviderSplit, func(d, c *User) { link(d); link(c) })
	pair("i.n@gmail.com", "in@gmail.com", repairReasonInactive, func(d, c *User) { link(d); c.Status = StatusDeactivated })
	pair("i.d@gmail.com", "id@gmail.com", repairReasonIDPManaged, func(d, c *User) { link(d); c.ExternalID = "idp-1" })
	pair("ann+work@corp.example", "ann@corp.example", repairReasonNotGmail, func(d, _ *User) { link(d) })
	pair("r.e@gmail.com", "re@gmail.com", "managed child", func(d, c *User) {
		link(d)
		seedGuardianEdge(context.Background(), t, repo, seedUser(repo, "", "", StatusActive).ID, c.ID)
	})
	three := seedVerified(repo, "t.hree@gmail.com", "")
	link(three)
	seedVerified(repo, "th.ree@gmail.com", "")
	seedVerified(repo, "three@gmail.com", "")
	reasonFor[three.ID] = repairReasonTooMany

	report := dryThenApplySkips(t, svc)
	require.Len(t, report.Items, len(reasonFor))
	for _, it := range report.Items {
		require.Contains(t, it.Reason, reasonFor[it.UserID], it.UserID)
		require.Equal(t, StatusActive, storedUser(t, repo, it.UserID).Status)
	}
	require.Zero(t, writer.countByEventType("account_merged"))
	require.Zero(t, writer.countByEventType("email_canonicalized"))
}

// A store failure on one mailbox is that item's error, and the run goes on.
func TestRepairStoredEmails_StoreFailureIsAnItemError(t *testing.T) {
	svc, repo, _ := repairFixture(t)
	seedUser(repo, "first.last@gmail.com", "", StatusActive)
	repo.updateUserErr = errors.New("disk full")

	report := runRepair(t, svc, true)
	require.Equal(t, 1, report.Failed())
	require.Equal(t, "disk full", report.Items[0].Error)
}

func TestRepairStoredEmails_SkipsSpellingsItCannotProve(t *testing.T) {
	svc, repo, writer := repairFixture(t)
	tagOnly := seedVerified(repo, "+x@corp.example", "")
	tagged := seedVerified(repo, "ann+work@corp.example", "")

	report := dryThenApplySkips(t, svc)
	require.Len(t, report.Items, 2)
	for _, it := range report.Items {
		require.Equal(t, repairReasonNotRewritable, it.Reason)
	}
	require.Equal(t, "+x@corp.example", storedUser(t, repo, tagOnly.ID).Email)
	require.Equal(t, "ann+work@corp.example", storedUser(t, repo, tagged.ID).Email)
	require.Zero(t, writer.countByEventType("email_canonicalized"))
}
