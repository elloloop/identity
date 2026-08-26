package service

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/pkg/audit"
)

// seedGuardianEdge inserts a (guardian -> child) edge directly into the fake
// repository, bypassing the consent flow.
func seedGuardianEdge(t *testing.T, repo *fakeRepo, guardianUserID, childUserID string) {
	t.Helper()
	if err := repo.UpsertGuardianEdge(context.Background(), &GuardianEdge{
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

	seedGuardianEdge(t, repo, guardian.ID, child1.ID)
	seedGuardianEdge(t, repo, guardian.ID, child2.ID)
	seedGuardianEdge(t, repo, guardian.ID, ghost.ID)
	if err := repo.DeleteUser(ctx, ghost.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	children, err := svc.ListManagedChildren(ctx, guardian.ID)
	if err != nil {
		t.Fatalf("ListManagedChildren: %v", err)
	}
	got := userIDs(children)
	if len(children) != 2 || !got[child1.ID] || !got[child2.ID] {
		t.Fatalf("children = %#v, want {%s, %s} (deleted child skipped)", got, child1.ID, child2.ID)
	}

	children, err = svc.ListManagedChildren(ctx, stranger.ID)
	if err != nil {
		t.Fatalf("ListManagedChildren (no edges): %v", err)
	}
	if len(children) != 0 {
		t.Fatalf("stranger must manage no children, got %d", len(children))
	}

	if _, err := svc.ListManagedChildren(ctx, ""); !errors.Is(err, ErrUnauthenticated) {
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
	seedGuardianEdge(t, repo, guardian.ID, child.ID)

	// A guardian of the child may list.
	guardians, err := svc.GetGuardians(ctx, guardian.ID, child.ID, false)
	if err != nil {
		t.Fatalf("GetGuardians (guardian): %v", err)
	}
	if len(guardians) != 1 || guardians[0].ID != guardian.ID {
		t.Fatalf("guardians = %#v, want [%s]", guardians, guardian.ID)
	}

	// A project admin may list without holding an edge.
	guardians, err = svc.GetGuardians(ctx, other.ID, child.ID, true)
	if err != nil {
		t.Fatalf("GetGuardians (admin): %v", err)
	}
	if len(guardians) != 1 || guardians[0].ID != guardian.ID {
		t.Fatalf("guardians = %#v, want [%s]", guardians, guardian.ID)
	}

	// A stranger is denied — with the SAME error whether the child exists or
	// not, so the surface discloses nothing about account existence.
	_, errExisting := svc.GetGuardians(ctx, other.ID, child.ID, false)
	_, errMissing := svc.GetGuardians(ctx, other.ID, "no-such-child", false)
	if !errors.Is(errExisting, ErrPermissionDenied) || !errors.Is(errMissing, ErrPermissionDenied) {
		t.Fatalf("stranger denials = %v / %v, want ErrPermissionDenied for both", errExisting, errMissing)
	}
	if errExisting.Error() != errMissing.Error() {
		t.Fatalf("denial must be account-agnostic: %q vs %q", errExisting, errMissing)
	}

	// Even an admin gets nothing disclosable for a nonexistent child: an
	// empty list, not an existence error.
	guardians, err = svc.GetGuardians(ctx, other.ID, "no-such-child", true)
	if err != nil || len(guardians) != 0 {
		t.Fatalf("admin on nonexistent child: guardians=%#v err=%v, want empty nil", guardians, err)
	}

	if _, err := svc.GetGuardians(ctx, "", child.ID, true); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("empty caller: err = %v, want ErrUnauthenticated", err)
	}
	if _, err := svc.GetGuardians(ctx, guardian.ID, "  ", false); !errors.Is(err, ErrInvalidArgument) {
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

	if _, err := svc.RevokeParentalConsent(ctx, adult.ID, child.ID, "changed my mind"); err != nil {
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
		seedGuardianEdge(t, repo, rec.ConsentingUserID, child.ID)
	}

	if _, err := svc.RevokeParentalConsent(ctx, g1.ID, child.ID, ""); err != nil {
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

	if _, err := svc.RevokeParentalConsent(ctx, g2.ID, child.ID, ""); err != nil {
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
