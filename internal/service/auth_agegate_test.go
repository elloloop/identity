package service

import (
	"context"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/agegate"
)

var ageGateNow = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

// enableAgeGate flips an already-constructed test service into age-gating
// mode with the conventional under-13 / adult-18 boundaries and a fixed
// clock so age derivation is deterministic.
func enableAgeGate(t *testing.T, svc *AuthService, requireDOB bool) {
	t.Helper()
	svc.cfg.AgeGateEnabled = true
	svc.cfg.AgeGateChildMaxAge = 12
	svc.cfg.AgeGateAdultAge = 18
	svc.cfg.AgeGateRequireDOB = requireDOB
	d, err := agegate.NewThreshold(12, 18)
	if err != nil {
		t.Fatalf("NewThreshold: %v", err)
	}
	svc.ageGate = d
	svc.nowFunc = func() time.Time { return ageGateNow }
}

func dobAgeMs(years int) int64 {
	return ageGateNow.AddDate(-years, 0, 0).UnixMilli()
}

func TestPasswordSignup_AgeGateOff_DOBIgnored_AdultActive(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	// Age-gate disabled by default: even a child DOB signs up active with tokens.
	res, err := svc.PasswordSignup(context.Background(), "kid@example.com", strongPW, "Kid", "", dobAgeMs(8))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatal("expected tokens when age-gate off")
	}
	if res.User.Status != "active" {
		t.Fatalf("status = %q, want active", res.User.Status)
	}
	if res.User.IsMinor || res.User.AgeBand != "" {
		t.Fatalf("expected no minor derivation when gate off, got minor=%v band=%q", res.User.IsMinor, res.User.AgeBand)
	}
}

func TestPasswordSignup_AgeGateOn_Adult_ActiveWithTokens(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, false)

	res, err := svc.PasswordSignup(context.Background(), "adult@example.com", strongPW, "Adult", "", dobAgeMs(30))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatal("expected tokens for adult")
	}
	if res.User.Status != "active" {
		t.Fatalf("status = %q, want active", res.User.Status)
	}
	if res.User.IsMinor || res.User.AgeBand != "ADULT" {
		t.Fatalf("got minor=%v band=%q, want adult", res.User.IsMinor, res.User.AgeBand)
	}
}

func TestPasswordSignup_AgeGateOn_Child_PendingNoTokens(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, false)

	res, err := svc.PasswordSignup(context.Background(), "child@example.com", strongPW, "Child", "", dobAgeMs(8))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatal("child account must not be issued tokens")
	}
	if res.User.Status != StatusPendingParentalConsent {
		t.Fatalf("status = %q, want %q", res.User.Status, StatusPendingParentalConsent)
	}
	if !res.User.IsMinor || res.User.AgeBand != "CHILD" {
		t.Fatalf("got minor=%v band=%q, want child/minor", res.User.IsMinor, res.User.AgeBand)
	}
	// The account is persisted in PENDING state and carries the DOB.
	stored, err := repo.FindUserByEmail(context.Background(), "child@example.com")
	if err != nil || stored == nil {
		t.Fatalf("stored lookup: %v %#v", err, stored)
	}
	if stored.Status != StatusPendingParentalConsent || stored.DateOfBirthMs != dobAgeMs(8) {
		t.Fatalf("stored = %+v", stored)
	}
}

func TestPasswordSignup_AgeGateOn_Teen_ActiveWithTokens(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, false)

	res, err := svc.PasswordSignup(context.Background(), "teen@example.com", strongPW, "Teen", "", dobAgeMs(15))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("teen is a minor but above child band: tokens expected")
	}
	if res.User.Status != "active" || !res.User.IsMinor || res.User.AgeBand != "TEEN" {
		t.Fatalf("got status=%q minor=%v band=%q", res.User.Status, res.User.IsMinor, res.User.AgeBand)
	}
}

func TestPasswordSignup_AgeGateOn_RequireDOB_MissingRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)

	_, err := svc.PasswordSignup(context.Background(), "nodob@example.com", strongPW, "NoDOB", "", 0)
	if err == nil {
		t.Fatal("expected error when DOB required but omitted")
	}
}
