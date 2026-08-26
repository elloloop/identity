package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/agegate"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/idv"
)

// childMinimizer builds a data-minimizer that classifies anyone at or below
// age 12 as a CHILD, using the same fixed clock as the age-gate tests so DOB
// math is deterministic.
func childMinimizer(t *testing.T, enabled bool) MinorDataMinimizer {
	t.Helper()
	d, err := agegate.NewThreshold(12, 18)
	if err != nil {
		t.Fatalf("NewThreshold: %v", err)
	}
	return NewMinorDataMinimizer(enabled, d, func() time.Time { return ageGateNow })
}

// ── MinorDataMinimizer unit semantics ───────────────────────────────

func TestMinorDataMinimizer_Disabled_NeverBlocks(t *testing.T) {
	t.Parallel()
	m := childMinimizer(t, false)
	if m.Enabled() {
		t.Fatal("Enabled() = true; want false")
	}
	if m.BlocksChildFor(context.Background(), &User{DateOfBirthMs: dobAgeMs(8)}) {
		t.Fatal("BlocksChildFor(child) = true while disabled; want false")
	}
}

func TestMinorDataMinimizer_GateOff_DisablesEvenIfFlagOn(t *testing.T) {
	t.Parallel()
	// A nil/no-op determiner means the age gate is off; minimization must
	// stay a no-op even when the flag is set.
	m := NewMinorDataMinimizer(true, agegate.NewNoop(), func() time.Time { return ageGateNow })
	if m.Enabled() {
		t.Fatal("Enabled() = true with age gate off; want false")
	}
	if m.BlocksChildFor(context.Background(), &User{DateOfBirthMs: dobAgeMs(8)}) {
		t.Fatal("BlocksChildFor = true with age gate off; want false")
	}
}

func TestMinorDataMinimizer_Enabled_BlocksOnlyChild(t *testing.T) {
	t.Parallel()
	m := childMinimizer(t, true)
	if !m.Enabled() {
		t.Fatal("Enabled() = false; want true")
	}
	if !m.BlocksChildFor(context.Background(), &User{DateOfBirthMs: dobAgeMs(8)}) {
		t.Fatal("BlocksChildFor(child) = false; want true")
	}
	if m.BlocksChildFor(context.Background(), &User{DateOfBirthMs: dobAgeMs(15)}) {
		t.Fatal("BlocksChildFor(teen) = true; want false (only CHILD is minimized)")
	}
	if m.BlocksChildFor(context.Background(), &User{DateOfBirthMs: dobAgeMs(30)}) {
		t.Fatal("BlocksChildFor(adult) = true; want false")
	}
	if m.BlocksChildFor(context.Background(), &User{}) {
		t.Fatal("BlocksChildFor(unknown DOB) = true; want false")
	}
}

func TestNewMinorDataMinimizer_NilNowDefaults(t *testing.T) {
	t.Parallel()
	// A nil now must not panic; the minimizer defaults to time.Now.
	m := NewMinorDataMinimizer(false, nil, nil)
	if m.BlocksChildFor(context.Background(), &User{DateOfBirthMs: 123}) {
		t.Fatal("BlocksChildFor = true on disabled minimizer with nil deps")
	}
}

// ── Phone verification ──────────────────────────────────────────────

// enableMinorData flips an age-gated test service into data-minimization mode
// with a clock matching the age-gate tests.
func enableMinorData(t *testing.T, svc *AuthService) {
	t.Helper()
	enableAgeGate(t, svc, false)
	svc.cfg.MinorDataMinimization = true
	svc.minorData = childMinimizer(t, true)
}

func TestRequestPhoneVerification_Minor_Blocked(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableMinorData(t, svc)
	svc.cfg.SMSEnabled = true
	uid, err := repo.CreateUser(context.Background(), &User{Email: "kid@example.com", Status: "active", DateOfBirthMs: dobAgeMs(8)})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	err = svc.RequestPhoneVerification(context.Background(), uid, "+14155550123")
	if !errors.Is(err, ErrMinorDataMinimized) {
		t.Fatalf("err = %v; want ErrMinorDataMinimized", err)
	}
}

func TestRequestPhoneVerification_MinimizationOff_ChildAllowed(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, false) // age gate on, but minimization OFF
	svc.cfg.SMSEnabled = true
	uid, err := repo.CreateUser(context.Background(), &User{Email: "kid@example.com", Status: "active", DateOfBirthMs: dobAgeMs(8)})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	err = svc.RequestPhoneVerification(context.Background(), uid, "+14155550123")
	if errors.Is(err, ErrMinorDataMinimized) {
		t.Fatal("child blocked while minimization off; want allowed")
	}
}

func TestRequestPhoneVerification_Minor_AdultAllowed(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableMinorData(t, svc)
	svc.cfg.SMSEnabled = true
	uid, err := repo.CreateUser(context.Background(), &User{Email: "adult@example.com", Status: "active", DateOfBirthMs: dobAgeMs(30)})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	err = svc.RequestPhoneVerification(context.Background(), uid, "+14155550123")
	if errors.Is(err, ErrMinorDataMinimized) {
		t.Fatal("adult blocked; want allowed")
	}
}

// ── Identity verification ───────────────────────────────────────────

func TestBeginIdentityVerification_Minor_Blocked(t *testing.T) {
	repo := newFakeRepo()
	uid, err := repo.CreateUser(context.Background(), &User{Email: "kid@example.com", Status: "active", DateOfBirthMs: dobAgeMs(8)})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := NewIdentityVerificationService(repo, idv.NewStubProvider(), "tenant-1", zap.NewNop()).
		WithMinorDataMinimizer(childMinimizer(t, true))

	_, err = svc.BeginIdentityVerification(context.Background(), uid)
	if !errors.Is(err, ErrMinorDataMinimized) {
		t.Fatalf("err = %v; want ErrMinorDataMinimized", err)
	}
}

func TestBeginIdentityVerification_MinimizationOff_ChildAllowed(t *testing.T) {
	repo := newFakeRepo()
	uid, err := repo.CreateUser(context.Background(), &User{Email: "kid@example.com", Status: "active", DateOfBirthMs: dobAgeMs(8)})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	// No minimizer wired => zero-value no-op.
	svc := NewIdentityVerificationService(repo, idv.NewStubProvider(), "tenant-1", zap.NewNop())

	if _, err := svc.BeginIdentityVerification(context.Background(), uid); err != nil {
		t.Fatalf("Begin: %v", err)
	}
}

func TestBeginIdentityVerification_Minor_AdultAllowed(t *testing.T) {
	repo := newFakeRepo()
	uid, err := repo.CreateUser(context.Background(), &User{Email: "adult@example.com", Status: "active", DateOfBirthMs: dobAgeMs(30)})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := NewIdentityVerificationService(repo, idv.NewStubProvider(), "tenant-1", zap.NewNop()).
		WithMinorDataMinimizer(childMinimizer(t, true))

	if _, err := svc.BeginIdentityVerification(context.Background(), uid); err != nil {
		t.Fatalf("Begin (adult): %v", err)
	}
}

// ── Signup recovery_email suppression ───────────────────────────────

func TestPasswordSignup_Minor_RecoveryEmailDropped(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableMinorData(t, svc)

	res, err := svc.PasswordSignup(context.Background(), "kid@example.com", strongPW, "Kid", "guardian@example.com", dobAgeMs(8), "")
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	// A child is created pending parental consent with NO tokens (#268) ...
	if res.User.Status != StatusPendingParentalConsent {
		t.Fatalf("status = %q; want pending_parental_consent", res.User.Status)
	}
	// ... and the recovery_email must never be persisted.
	stored, _ := repo.GetUser(context.Background(), res.User.ID)
	if stored.RecoveryEmail != "" {
		t.Fatalf("recovery_email = %q; want dropped for minor", stored.RecoveryEmail)
	}
}

func TestPasswordSignup_MinimizationOff_ChildRecoveryEmailKept(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, false) // gate on, minimization off

	res, err := svc.PasswordSignup(context.Background(), "kid@example.com", strongPW, "Kid", "guardian@example.com", dobAgeMs(8), "")
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	stored, _ := repo.GetUser(context.Background(), res.User.ID)
	if stored.RecoveryEmail != "guardian@example.com" {
		t.Fatalf("recovery_email = %q; want kept when minimization off", stored.RecoveryEmail)
	}
}

func TestPasswordSignup_Minor_AdultRecoveryEmailKept(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableMinorData(t, svc)

	res, err := svc.PasswordSignup(context.Background(), "adult@example.com", strongPW, "Adult", "alt@example.com", dobAgeMs(30), "")
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	stored, _ := repo.GetUser(context.Background(), res.User.ID)
	if stored.RecoveryEmail != "alt@example.com" {
		t.Fatalf("recovery_email = %q; want kept for adult", stored.RecoveryEmail)
	}
}

// ── Profile avatar suppression ──────────────────────────────────────

func newMinorProfileService(t *testing.T, repo *fakeRepo, m MinorDataMinimizer) *ProfileService {
	t.Helper()
	auditLog := audit.NewLogger(nil, "test-tenant", zap.NewNop())
	return NewProfileService(repo, nil, "test-tenant", auditLog, zap.NewNop()).
		WithMinorDataMinimizer(m)
}

func TestUpdateProfile_Minor_AvatarDropped(t *testing.T) {
	repo := newFakeRepo()
	uid, err := repo.CreateUser(context.Background(), &User{Email: "kid@example.com", Name: "Kid", Status: "active", DateOfBirthMs: dobAgeMs(8)})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := newMinorProfileService(t, repo, childMinimizer(t, true))

	user, err := svc.UpdateProfile(context.Background(), uid, "Kid New", "https://cdn.example.com/a.jpg")
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if user.Name != "Kid New" {
		t.Fatalf("name = %q; want updated (name is essential)", user.Name)
	}
	if user.AvatarURL != "" {
		t.Fatalf("avatar = %q; want dropped for minor", user.AvatarURL)
	}
	stored, _ := repo.GetUser(context.Background(), uid)
	if stored.AvatarURL != "" {
		t.Fatalf("persisted avatar = %q; want dropped", stored.AvatarURL)
	}
}

func TestUpdateProfile_MinimizationOff_ChildAvatarKept(t *testing.T) {
	repo := newFakeRepo()
	uid, err := repo.CreateUser(context.Background(), &User{Email: "kid@example.com", Status: "active", DateOfBirthMs: dobAgeMs(8)})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := newMinorProfileService(t, repo, childMinimizer(t, false))

	user, err := svc.UpdateProfile(context.Background(), uid, "", "https://cdn.example.com/a.jpg")
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if user.AvatarURL != "https://cdn.example.com/a.jpg" {
		t.Fatalf("avatar = %q; want kept when minimization off", user.AvatarURL)
	}
}

func TestUpdateProfile_Minor_AdultAvatarKept(t *testing.T) {
	repo := newFakeRepo()
	uid, err := repo.CreateUser(context.Background(), &User{Email: "adult@example.com", Status: "active", DateOfBirthMs: dobAgeMs(30)})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := newMinorProfileService(t, repo, childMinimizer(t, true))

	user, err := svc.UpdateProfile(context.Background(), uid, "", "https://cdn.example.com/a.jpg")
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if user.AvatarURL != "https://cdn.example.com/a.jpg" {
		t.Fatalf("avatar = %q; want kept for adult", user.AvatarURL)
	}
}

// TestMinorDataMinimizer_UsesJurisdictionThresholds pins the rule that one
// definition of "child" governs both classification and minimization. With
// the deployment ceiling at 12 and a project configuring IN at 17, a
// 15-year-old Indian account IS a child — so its optional PII must be
// suppressed too, not collected because a second, looser threshold said teen.
func TestMinorDataMinimizer_UsesJurisdictionThresholds(t *testing.T) {
	t.Parallel()
	m := childMinimizer(t, true) // env ceiling: child_max 12, adult 18

	teenUnderEnv := &User{DateOfBirthMs: dobAgeMs(15), Market: "IN"}
	if m.BlocksChildFor(context.Background(), teenUnderEnv) {
		t.Fatal("with no project scope the env ceiling applies: 15 is a teen")
	}

	// The same account, under a project that classifies under-18s as children.
	ctx := jurisdictionScope(t, `{"access":{"mode":"open"},"jurisdictions":{"default":"IN","thresholds":{`+
		`"IN":{"child_max_age":17,"adult_age":18},`+
		`"US":{"child_max_age":12,"adult_age":18}}}}`)
	if !m.BlocksChildFor(ctx, teenUnderEnv) {
		t.Fatal("an account the project classifies CHILD must be data-minimized")
	}
	// And a US account of the same age is still a teen under that project.
	if m.BlocksChildFor(ctx, &User{DateOfBirthMs: dobAgeMs(15), Market: "US"}) {
		t.Fatal("US ceiling is 12: a 15-year-old is a teen, not minimized")
	}
}
