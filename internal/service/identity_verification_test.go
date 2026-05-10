package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/idv"
)

// makeIDVService builds a service backed by an in-test fakeRepo with
// a single user pre-seeded; returns the user's id for caller use.
func makeIDVService(t *testing.T, provider idv.Provider) (*IdentityVerificationService, *fakeRepo, string) {
	t.Helper()
	repo := newFakeRepo()
	uid, err := repo.CreateUser(context.Background(), &User{Email: "u@example.com", Status: "active"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	svc := NewIdentityVerificationService(repo, provider, "tenant-1", nil)
	// Pin clock so timestamps in assertions are deterministic.
	svc.clock = func() time.Time { return time.UnixMilli(1_000) }
	return svc, repo, uid
}

func TestIDV_Begin_RequiresAuthenticatedUser(t *testing.T) {
	t.Parallel()

	svc, _, _ := makeIDVService(t, idv.NewStubProvider())
	_, err := svc.BeginIdentityVerification(context.Background(), "")
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("err = %v; want ErrUnauthenticated", err)
	}
}

func TestIDV_Begin_UnknownUser(t *testing.T) {
	t.Parallel()

	svc, _, _ := makeIDVService(t, idv.NewStubProvider())
	_, err := svc.BeginIdentityVerification(context.Background(), "no-such-user")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v; want ErrNotFound", err)
	}
}

func TestIDV_Begin_PersistsPendingRecord(t *testing.T) {
	t.Parallel()

	provider := idv.NewStubProvider()
	svc, repo, uid := makeIDVService(t, provider)

	res, err := svc.BeginIdentityVerification(context.Background(), uid)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if res.VerificationID == "" {
		t.Fatal("VerificationID empty")
	}
	if res.Provider != "stub" {
		t.Fatalf("Provider = %q; want stub", res.Provider)
	}
	if res.SessionToken == "" {
		t.Fatal("SessionToken empty")
	}
	if res.ExpiresAt.IsZero() {
		t.Fatal("ExpiresAt zero")
	}

	rec, _ := repo.GetIdentityVerification(context.Background(), res.VerificationID)
	if rec == nil {
		t.Fatal("record not persisted")
	}
	if rec.Status != IDVStatusPending {
		t.Fatalf("status = %q; want pending", rec.Status)
	}
	if rec.UserID != uid || rec.TenantID != "tenant-1" {
		t.Fatalf("record mismatch: %+v", rec)
	}
}

func TestIDV_GetStatus_LatestWhenIDOmitted(t *testing.T) {
	t.Parallel()

	provider := idv.NewStubProvider()
	svc, _, uid := makeIDVService(t, provider)

	if _, err := svc.BeginIdentityVerification(context.Background(), uid); err != nil {
		t.Fatalf("Begin 1: %v", err)
	}
	// Advance the clock so the second record's CreatedAt is strictly newer.
	svc.clock = func() time.Time { return time.UnixMilli(5_000) }
	second, err := svc.BeginIdentityVerification(context.Background(), uid)
	if err != nil {
		t.Fatalf("Begin 2: %v", err)
	}

	rec, err := svc.GetIdentityVerificationStatus(context.Background(), uid, "")
	if err != nil {
		t.Fatalf("Get latest: %v", err)
	}
	if rec.VerificationID != second.VerificationID {
		t.Fatalf("latest = %q; want %q", rec.VerificationID, second.VerificationID)
	}
}

func TestIDV_GetStatus_PollResolvesProviderVerdict(t *testing.T) {
	t.Parallel()

	provider := idv.NewStubProvider() // default Verdict = APPROVED
	svc, _, uid := makeIDVService(t, provider)

	begin, err := svc.BeginIdentityVerification(context.Background(), uid)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	rec, err := svc.GetIdentityVerificationStatus(context.Background(), uid, begin.VerificationID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Status != IDVStatusApproved {
		t.Fatalf("Status = %q; want approved", rec.Status)
	}
	if rec.CompletedAt == 0 {
		t.Fatal("CompletedAt unset on approved verdict")
	}
}

func TestIDV_GetStatus_RejectedPersistsReason(t *testing.T) {
	t.Parallel()

	provider := idv.NewStubProvider()
	provider.Verdict = idv.StatusRejected
	svc, _, uid := makeIDVService(t, provider)

	begin, err := svc.BeginIdentityVerification(context.Background(), uid)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	rec, err := svc.GetIdentityVerificationStatus(context.Background(), uid, begin.VerificationID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Status != IDVStatusRejected || rec.RejectionReason == "" {
		t.Fatalf("expected rejected with reason; got %+v", rec)
	}
}

func TestIDV_GetStatus_TerminalCachesLocally(t *testing.T) {
	t.Parallel()

	provider := idv.NewStubProvider()
	svc, _, uid := makeIDVService(t, provider)

	begin, _ := svc.BeginIdentityVerification(context.Background(), uid)

	// First poll resolves the verdict in the persisted record.
	if _, err := svc.GetIdentityVerificationStatus(context.Background(), uid, begin.VerificationID); err != nil {
		t.Fatalf("Get 1: %v", err)
	}

	// If the provider is replaced with one that would re-resolve to
	// rejected, the cached terminal status must NOT change.
	rejecting := idv.NewStubProvider()
	rejecting.Verdict = idv.StatusRejected
	svc.provider = rejecting

	rec, err := svc.GetIdentityVerificationStatus(context.Background(), uid, begin.VerificationID)
	if err != nil {
		t.Fatalf("Get 2: %v", err)
	}
	if rec.Status != IDVStatusApproved {
		t.Fatalf("Status flipped after terminal: got %q", rec.Status)
	}
}

func TestIDV_GetStatus_OtherUserDenied(t *testing.T) {
	t.Parallel()

	provider := idv.NewStubProvider()
	svc, repo, uid := makeIDVService(t, provider)

	begin, _ := svc.BeginIdentityVerification(context.Background(), uid)

	// Seed a different caller.
	otherUID, err := repo.CreateUser(context.Background(), &User{Email: "other@example.com", Status: "active"})
	if err != nil {
		t.Fatalf("seed other: %v", err)
	}

	_, err = svc.GetIdentityVerificationStatus(context.Background(), otherUID, begin.VerificationID)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("err = %v; want ErrPermissionDenied", err)
	}
}

func TestIDV_GetStatus_NotFound(t *testing.T) {
	t.Parallel()

	provider := idv.NewStubProvider()
	svc, _, uid := makeIDVService(t, provider)

	_, err := svc.GetIdentityVerificationStatus(context.Background(), uid, "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v; want ErrNotFound", err)
	}
}

func TestIDV_GetStatus_ProviderSessionLostMarksExpired(t *testing.T) {
	t.Parallel()

	// Begin a session, then build a fresh provider that doesn't know
	// about it — simulates a provider-side TTL expiry.
	provider := idv.NewStubProvider()
	svc, _, uid := makeIDVService(t, provider)
	begin, err := svc.BeginIdentityVerification(context.Background(), uid)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	svc.provider = idv.NewStubProvider() // empty session map

	rec, err := svc.GetIdentityVerificationStatus(context.Background(), uid, begin.VerificationID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Status != IDVStatusExpired {
		t.Fatalf("Status = %q; want expired", rec.Status)
	}
}
