package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/elloloop/identity/pkg/audit"
)

// seedGuardianEdge inserts a (guardian -> child) edge directly into the fake
// repository, bypassing the consent flow.
func seedGuardianEdge(ctx context.Context, t *testing.T, repo *fakeRepo, guardianUserID, childUserID string) {
	t.Helper()
	if err := repo.UpsertGuardianEdge(ctx, &GuardianEdge{
		GuardianUserID: guardianUserID, ChildUserID: childUserID, CreatedAtMs: 1,
	}); err != nil {
		t.Fatalf("seed guardian edge: %v", err)
	}
}

func userIDs(users []*User) map[string]bool {
	out := make(map[string]bool, len(users))
	for _, u := range users {
		out[u.ID] = true
	}
	return out
}

func TestListManagedChildren(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	guardian := seedConsentingAdult(t, repo, "guardian@example.com", "", adultFactors{})
	child1 := seedChildPendingConsent(repo, "child1@example.com")
	child2 := seedChildPendingConsent(repo, "child2@example.com")
	// An edge whose child account has been deleted is skipped, not an error.
	ghost := seedChildPendingConsent(repo, "ghost@example.com")
	stranger := seedConsentingAdult(t, repo, "stranger@example.com", "", adultFactors{})

	seedGuardianEdge(ctx, t, repo, guardian.ID, child1.ID)
	seedGuardianEdge(ctx, t, repo, guardian.ID, child2.ID)
	seedGuardianEdge(ctx, t, repo, guardian.ID, ghost.ID)
	if err := repo.DeleteUser(ctx, ghost.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	children, _, err := svc.ListManagedChildren(ctx, guardian.ID, 0, "")
	if err != nil {
		t.Fatalf("ListManagedChildren: %v", err)
	}
	got := userIDs(children)
	if len(children) != 2 || !got[child1.ID] || !got[child2.ID] {
		t.Fatalf("children = %#v, want {%s, %s} (deleted child skipped)", got, child1.ID, child2.ID)
	}

	children, _, err = svc.ListManagedChildren(ctx, stranger.ID, 0, "")
	if err != nil {
		t.Fatalf("ListManagedChildren (no edges): %v", err)
	}
	if len(children) != 0 {
		t.Fatalf("stranger must manage no children, got %d", len(children))
	}

	if _, _, err := svc.ListManagedChildren(ctx, "", 0, ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("empty guardian id: err = %v, want ErrUnauthenticated", err)
	}
}

func TestGetGuardians_Authorization(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	guardian := seedConsentingAdult(t, repo, "guardian@example.com", "", adultFactors{})
	other := seedConsentingAdult(t, repo, "other@example.com", "", adultFactors{})
	child := seedChildPendingConsent(repo, "child@example.com")
	seedGuardianEdge(ctx, t, repo, guardian.ID, child.ID)

	// A guardian of the child may list.
	guardians, _, err := svc.GetGuardians(ctx, guardian.ID, child.ID, false, 0, "")
	if err != nil {
		t.Fatalf("GetGuardians (guardian): %v", err)
	}
	if len(guardians) != 1 || guardians[0].ID != guardian.ID {
		t.Fatalf("guardians = %#v, want [%s]", guardians, guardian.ID)
	}

	// A project admin may list without holding an edge.
	guardians, _, err = svc.GetGuardians(ctx, other.ID, child.ID, true, 0, "")
	if err != nil {
		t.Fatalf("GetGuardians (admin): %v", err)
	}
	if len(guardians) != 1 || guardians[0].ID != guardian.ID {
		t.Fatalf("guardians = %#v, want [%s]", guardians, guardian.ID)
	}

	// A stranger is denied — with the SAME error whether the child exists or
	// not, so the surface discloses nothing about account existence.
	_, _, errExisting := svc.GetGuardians(ctx, other.ID, child.ID, false, 0, "")
	_, _, errMissing := svc.GetGuardians(ctx, other.ID, "no-such-child", false, 0, "")
	if !errors.Is(errExisting, ErrPermissionDenied) || !errors.Is(errMissing, ErrPermissionDenied) {
		t.Fatalf("stranger denials = %v / %v, want ErrPermissionDenied for both", errExisting, errMissing)
	}
	if errExisting.Error() != errMissing.Error() {
		t.Fatalf("denial must be account-agnostic: %q vs %q", errExisting, errMissing)
	}

	// Even an admin gets nothing disclosable for a nonexistent child: an
	// empty list, not an existence error.
	guardians, _, err = svc.GetGuardians(ctx, other.ID, "no-such-child", true, 0, "")
	if err != nil || len(guardians) != 0 {
		t.Fatalf("admin on nonexistent child: guardians=%#v err=%v, want empty nil", guardians, err)
	}

	if _, _, err := svc.GetGuardians(ctx, "", child.ID, true, 0, ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("empty caller: err = %v, want ErrUnauthenticated", err)
	}
	if _, _, err := svc.GetGuardians(ctx, guardian.ID, "  ", false, 0, ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank child id: err = %v, want ErrInvalidArgument", err)
	}
}

func TestGrantParentalConsent_CreatesGuardianEdge(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)

	adult := seedConsentingAdult(t, repo, "adult@example.com", hashPW(t, strongPW), adultFactors{phoneVerified: true})
	child := seedChildPendingConsent(repo, "child@example.com")

	if _, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "1.2.3.4", "agent/1.0"); err != nil {
		t.Fatalf("GrantParentalConsent: %v", err)
	}

	edge, err := repo.GetGuardianEdge(ctx, adult.ID, child.ID)
	if err != nil || edge == nil {
		t.Fatalf("grant must create the guardian edge: %#v err %v", edge, err)
	}
	if edge.CreatedAtMs == 0 {
		t.Fatalf("edge must carry a creation instant: %#v", edge)
	}
	if n := writer.countByEventTypeActorTarget(string(audit.EventGuardianEdgeCreated), adult.ID, child.ID); n != 1 {
		t.Fatalf("guardian_edge_created events with actor=adult target=child = %d, want 1", n)
	}
}

func TestRevokeParentalConsent_DeletesGuardianEdge(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)

	adult := seedConsentingAdult(t, repo, "adult@example.com", hashPW(t, strongPW), adultFactors{phoneVerified: true})
	child := seedChildPendingConsent(repo, "child@example.com")
	if _, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", ""); err != nil {
		t.Fatalf("grant: %v", err)
	}

	if _, _, err := svc.RevokeParentalConsent(ctx, adult.ID, child.ID, "changed my mind"); err != nil {
		t.Fatalf("RevokeParentalConsent: %v", err)
	}

	if edge, err := repo.GetGuardianEdge(ctx, adult.ID, child.ID); err != nil || edge != nil {
		t.Fatalf("revoke must remove the guardian edge: %#v err %v", edge, err)
	}
	if n := writer.countByEventTypeActorTarget(string(audit.EventGuardianEdgeRemoved), adult.ID, child.ID); n != 1 {
		t.Fatalf("guardian_edge_removed events with actor=adult target=child = %d, want 1", n)
	}
	// The child was re-gated: the last guardian revoked.
	got, err := repo.GetUser(ctx, child.ID)
	if err != nil || got == nil {
		t.Fatalf("fetch child: %#v %v", got, err)
	}
	if got.Status != StatusPendingParentalConsent {
		t.Fatalf("child status = %q, want %q", got.Status, StatusPendingParentalConsent)
	}
}

// TestRevokeParentalConsent_LastGuardianRule pins the multi-guardian
// behaviour the revoke flow is structured for: while another active consent
// remains for the child, revoking one consent removes only that guardian's
// edge and leaves the child ACTIVE; revoking the last one re-gates.
func TestRevokeParentalConsent_LastGuardianRule(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	g1 := seedConsentingAdult(t, repo, "g1@example.com", "", adultFactors{})
	g2 := seedConsentingAdult(t, repo, "g2@example.com", "", adultFactors{})
	child := seedUser(repo, "child@example.com", "", StatusActive)

	// Two active consents, seeded directly (the grant RPC admits only one at
	// a time today; this seeds the future multi-guardian state the rule
	// guards). g1's is the newer record so GetActive returns it for g1's
	// revoke.
	for _, rec := range []*ParentalConsentRecord{
		{ConsentID: "pc-g2", ChildUserID: child.ID, ConsentingUserID: g2.ID, GrantedAt: 100},
		{ConsentID: "pc-g1", ChildUserID: child.ID, ConsentingUserID: g1.ID, GrantedAt: 200},
	} {
		if err := repo.CreateParentalConsent(ctx, rec); err != nil {
			t.Fatalf("seed consent %s: %v", rec.ConsentID, err)
		}
		seedGuardianEdge(ctx, t, repo, rec.ConsentingUserID, child.ID)
	}

	if _, _, err := svc.RevokeParentalConsent(ctx, g1.ID, child.ID, ""); err != nil {
		t.Fatalf("revoke as g1: %v", err)
	}
	// g1's edge is gone, g2's remains, and the child is STILL ACTIVE.
	if edge, _ := repo.GetGuardianEdge(ctx, g1.ID, child.ID); edge != nil {
		t.Fatalf("g1 edge must be removed, got %#v", edge)
	}
	if edge, _ := repo.GetGuardianEdge(ctx, g2.ID, child.ID); edge == nil {
		t.Fatal("g2 edge must remain")
	}
	got, err := repo.GetUser(ctx, child.ID)
	if err != nil || got == nil {
		t.Fatalf("fetch child: %#v %v", got, err)
	}
	if got.Status != StatusActive {
		t.Fatalf("child status after non-last revoke = %q, want %q", got.Status, StatusActive)
	}

	if _, _, err := svc.RevokeParentalConsent(ctx, g2.ID, child.ID, ""); err != nil {
		t.Fatalf("revoke as g2: %v", err)
	}
	got, err = repo.GetUser(ctx, child.ID)
	if err != nil || got == nil {
		t.Fatalf("fetch child: %#v %v", got, err)
	}
	if got.Status != StatusPendingParentalConsent {
		t.Fatalf("child status after last-guardian revoke = %q, want %q", got.Status, StatusPendingParentalConsent)
	}
}

// TestRevokeParentalConsent_FailsClosed pins the ordering that matters most in
// this feature: consent withdrawal removes ACCESS first and marks the record
// revoked last, so a storage failure part-way leaves the child gated behind a
// still-active record — safe, and retryable, because the record the retry
// looks up is still there. The reverse order strands an ACTIVE child with
// live sessions and no consent on file, unreachable by any later call.
func TestRevokeParentalConsent_FailsClosed(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	adult := seedConsentingAdult(t, repo, "parent@example.com", hashPW(t, strongPW), adultFactors{phoneVerified: true})
	child := seedUser(repo, "child@example.com", "", StatusActive)
	rec := &ParentalConsentRecord{
		ConsentID: "pc-fc", ChildUserID: child.ID, ConsentingUserID: adult.ID, GrantedAt: 100,
	}
	if err := repo.CreateParentalConsent(ctx, rec); err != nil {
		t.Fatalf("seed consent: %v", err)
	}
	seedGuardianEdge(ctx, t, repo, adult.ID, child.ID)

	// The LAST write fails. Everything protective has already landed.
	repo.markConsentRevokedErr = errConsentInjected
	if _, _, err := svc.RevokeParentalConsent(ctx, adult.ID, child.ID, ""); !errors.Is(err, errConsentInjected) {
		t.Fatalf("err = %v, want the injected failure", err)
	}

	// Access is gone: the child is re-gated, its sessions cut, the edge dropped.
	got, _ := repo.GetUser(ctx, child.ID)
	if got.Status != StatusPendingParentalConsent {
		t.Fatalf("child status = %q, want the child gated despite the failure", got.Status)
	}
	if edge, _ := repo.GetGuardianEdge(ctx, adult.ID, child.ID); edge != nil {
		t.Fatal("the guardian edge must be gone before the record write is attempted")
	}
	// And the operation is RETRYABLE: the record is still the active one.
	if active, _ := repo.GetActiveParentalConsentForChild(ctx, child.ID); active == nil {
		t.Fatal("the consent record must remain active so a retry can finish the job")
	}

	repo.markConsentRevokedErr = nil
	revoked, status, err := svc.RevokeParentalConsent(ctx, adult.ID, child.ID, "")
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if revoked.RevokedAt == 0 || status != StatusPendingParentalConsent {
		t.Fatalf("retry left revoked_at=%d status=%q", revoked.RevokedAt, status)
	}
}

// TestGuardianListings_RepoFailuresAndGhostRows covers the two listing
// surfaces' storage-failure paths and the skip that keeps a stale edge from
// erroring a whole listing.
func TestGuardianListings_RepoFailuresAndGhostRows(t *testing.T) {
	ctx := context.Background()

	t.Run("list children fails", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		repo.listGuardianEdgesErr = errConsentInjected
		if _, _, err := svc.ListManagedChildren(ctx, "guardian-1", 0, ""); !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})

	t.Run("hydrating the page fails", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		guardian := seedConsentingAdult(t, repo, "g@example.com", "", adultFactors{})
		child := seedChildPendingConsent(repo, "c@example.com")
		seedGuardianEdge(ctx, t, repo, guardian.ID, child.ID)
		repo.getUsersByIDsErr = errConsentInjected
		if _, _, err := svc.ListManagedChildren(ctx, guardian.ID, 0, ""); !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})

	t.Run("guardian listing skips a deleted guardian and propagates failures", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		g1 := seedConsentingAdult(t, repo, "g1@example.com", "", adultFactors{})
		ghost := seedConsentingAdult(t, repo, "ghost@example.com", "", adultFactors{})
		child := seedChildPendingConsent(repo, "c@example.com")
		seedGuardianEdge(ctx, t, repo, g1.ID, child.ID)
		seedGuardianEdge(ctx, t, repo, ghost.ID, child.ID)
		// Drop the ghost's account but leave its edge behind (the FK cascade
		// does this for real; a stale row must not error the listing).
		repo.mu.Lock()
		delete(repo.users, ghost.ID)
		repo.mu.Unlock()

		guardians, _, err := svc.GetGuardians(ctx, g1.ID, child.ID, false, 0, "")
		if err != nil {
			t.Fatalf("GetGuardians: %v", err)
		}
		if len(guardians) != 1 || guardians[0].ID != g1.ID {
			t.Fatalf("guardians = %#v, want only the surviving guardian", guardians)
		}

		repo.listGuardianEdgesErr = errConsentInjected
		if _, _, err := svc.GetGuardians(ctx, g1.ID, child.ID, true, 0, ""); !errors.Is(err, errConsentInjected) {
			t.Fatalf("admin listing: err = %v, want the injected failure", err)
		}
	})

	t.Run("edge check fails", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		repo.getGuardianEdgeErr = errConsentInjected
		if _, _, err := svc.GetGuardians(ctx, "caller", "child", false, 0, ""); !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})

	t.Run("edge write fails", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		repo.upsertGuardianEdgeErr = errConsentInjected
		if err := svc.upsertGuardianEdge(ctx, "g", "c", "", ""); !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})
}

// TestListManagedChildren_PagesAndBatches pins the two properties the listing
// gained: it is bounded (no single call returns an unbounded set), and it
// hydrates a page in ONE query rather than one per edge.
func TestListManagedChildren_PagesAndBatches(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	guardian := seedConsentingAdult(t, repo, "g@example.com", "", adultFactors{})

	const total = 7
	for i := 0; i < total; i++ {
		child := seedChildPendingConsent(repo, fmt.Sprintf("kid%02d@example.com", i))
		seedGuardianEdge(ctx, t, repo, guardian.ID, child.ID)
	}

	// Walk every page with a small limit and assert we see each child once.
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page, next, err := svc.ListManagedChildren(ctx, guardian.ID, 3, cursor)
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		pages++
		if len(page) > 3 {
			t.Fatalf("page %d returned %d children, want at most the limit of 3", pages, len(page))
		}
		for _, c := range page {
			if seen[c.ID] {
				t.Fatalf("child %s appeared on two pages", c.ID)
			}
			seen[c.ID] = true
		}
		if next == "" {
			break
		}
		cursor = next
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != total {
		t.Fatalf("walked %d children across %d pages, want %d", len(seen), pages, total)
	}
	if pages != 3 {
		t.Fatalf("pages = %d, want 3 for %d children at a limit of 3", pages, total)
	}

	// An absent limit clamps to the default rather than returning everything
	// unbounded, and a junk cursor starts from the beginning.
	all, next, err := svc.ListManagedChildren(ctx, guardian.ID, 0, "not-a-cursor")
	if err != nil {
		t.Fatalf("default page: %v", err)
	}
	if len(all) != total || next != "" {
		t.Fatalf("default page = %d children next=%q, want %d and no next page", len(all), next, total)
	}

	// An over-large limit is clamped to the maximum, not honoured.
	if size, _ := guardianPage(10_000, ""); size != maxGuardianPageSize {
		t.Fatalf("limit 10000 clamped to %d, want %d", size, maxGuardianPageSize)
	}
}

// TestListManagedChildren_SummariesOnly pins that the listing carries identity
// and classification but not the contact details GetManagedChildProfile gates
// behind a step-up.
func TestListManagedChildren_SummariesOnly(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, false)

	guardian := seedConsentingAdult(t, repo, "g@example.com", "", adultFactors{})
	child := seedChildPendingConsent(repo, "kid@example.com")
	repo.mu.Lock()
	child.Username = "kid.one"
	child.DateOfBirthMs = dobAgeMs(8)
	child.PhoneNumber = "+14155550100"
	child.RecoveryEmail = "backup@example.com"
	repo.mu.Unlock()
	seedGuardianEdge(ctx, t, repo, guardian.ID, child.ID)

	page, _, err := svc.ListManagedChildren(ctx, guardian.ID, 0, "")
	if err != nil || len(page) != 1 {
		t.Fatalf("ListManagedChildren: %v %#v", err, page)
	}
	got := page[0]
	if got.ID != child.ID || got.Username != "kid.one" || got.AgeBand != "CHILD" {
		t.Fatalf("summary lost its identity/classification: %+v", got)
	}
	if got.Email != "" || got.PhoneNumber != "" || got.RecoveryEmail != "" || got.DateOfBirthMs != 0 {
		t.Fatalf("summary must not carry contact details or DOB: %+v", got)
	}
}

// TestListManagedChildren_OmitsAgedOut pins that an account past the adult
// threshold drops out of the listing — the edge survives as consent history
// but confers nothing, and the management RPCs already refuse it.
func TestListManagedChildren_OmitsAgedOut(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, false)

	guardian := seedConsentingAdult(t, repo, "g@example.com", "", adultFactors{})
	kid := seedChildPendingConsent(repo, "kid@example.com")
	grown := seedChildPendingConsent(repo, "grown@example.com")
	repo.mu.Lock()
	kid.DateOfBirthMs = dobAgeMs(8)
	grown.DateOfBirthMs = dobAgeMs(21)
	repo.mu.Unlock()
	seedGuardianEdge(ctx, t, repo, guardian.ID, kid.ID)
	seedGuardianEdge(ctx, t, repo, guardian.ID, grown.ID)

	page, _, err := svc.ListManagedChildren(ctx, guardian.ID, 0, "")
	if err != nil {
		t.Fatalf("ListManagedChildren: %v", err)
	}
	if len(page) != 1 || page[0].ID != kid.ID {
		t.Fatalf("listing = %#v, want only the still-managed child", userIDs(page))
	}

	// Guardians, by contrast, are adults and must NOT be filtered out.
	guardians, _, err := svc.GetGuardians(ctx, guardian.ID, kid.ID, false, 0, "")
	if err != nil || len(guardians) != 1 || guardians[0].ID != guardian.ID {
		t.Fatalf("GetGuardians = %#v %v, want the adult guardian listed", guardians, err)
	}
}
