package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// ── Fixture ────────────────────────────────────────────────────────────

// guardianFixture is an age-gated service with a stepped-up-capable guardian
// and one managed child account the guardian holds an edge to.
type guardianFixture struct {
	svc      *AuthService
	repo     *fakeRepo
	writer   *recordingAuditWriter
	purger   *fakePurger
	guardian *User
	child    *User
}

// fakePurger stands in for the AdminService's erasure cascade so the service
// test can assert the guardian delete path DELEGATES rather than
// reimplementing it.
type fakePurger struct {
	calls []string // "actor->target" per call
	err   error
	repo  *fakeRepo
}

func (p *fakePurger) PurgeAccount(ctx context.Context, actorUserID string, u *User) error {
	p.calls = append(p.calls, actorUserID+"->"+u.ID)
	if p.err != nil {
		return p.err
	}
	return p.repo.DeleteUser(ctx, u.ID)
}

func newGuardianFixture(ctx context.Context, t *testing.T) *guardianFixture {
	t.Helper()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	enableAgeGate(t, svc, false)
	purger := &fakePurger{repo: repo}
	svc = svc.WithAccountPurger(purger)

	guardian := seedConsentingAdult(t, repo, "parent@example.com", hashPW(t, strongPW), adultFactors{phoneVerified: true})
	child := seedManagedChild(t, repo, "kid.one", dobAgeMs(8))
	seedGuardianEdge(ctx, t, repo, guardian.ID, child.ID)

	return &guardianFixture{svc: svc, repo: repo, writer: writer, purger: purger, guardian: guardian, child: child}
}

// seedManagedChild seeds an active, username-identified child account with no
// email — the shape CreateManagedChildAccount produces.
func seedManagedChild(t *testing.T, repo *fakeRepo, username string, dobMs int64) *User {
	t.Helper()
	u := seedUser(repo, "", hashPW(t, strongPW), StatusActive)
	repo.mu.Lock()
	u.Username = username
	u.DateOfBirthMs = dobMs
	u.Name = username
	repo.mu.Unlock()
	return u
}

// seedChildSession gives the child one live session and one refresh token so
// revocation is observable.
func seedChildSession(t *testing.T, repo *fakeRepo, userID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := repo.CreateSession(ctx, &SessionRecord{UserID: userID, SID: "sess-" + userID}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, err := repo.CreateRefreshToken(ctx, &RefreshTokenRecord{UserID: userID, TokenHash: "hash-" + userID}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
}

func (f *guardianFixture) childSessionsLive(t *testing.T) bool {
	t.Helper()
	f.repo.mu.Lock()
	defer f.repo.mu.Unlock()
	for _, s := range f.repo.sessions {
		if s.UserID == f.child.ID && s.RevokedAtMs == 0 {
			return true
		}
	}
	for _, rt := range f.repo.refreshTokens {
		if rt.UserID == f.child.ID {
			return true
		}
	}
	return false
}

// ── The guard: edge + step-up, on every operation ──────────────────────

// guardianOp invokes one management operation with the given caller,
// target and step-up password, so the guard can be table-tested across the
// whole surface rather than once per RPC.
type guardianOpCase struct {
	name string
	call func(f *guardianFixture, caller, child, stepUp string) error
}

func allGuardianOps() []guardianOpCase {
	ctx := context.Background()
	return []guardianOpCase{
		{"view_profile", func(f *guardianFixture, c, ch, su string) error {
			_, err := f.svc.GetManagedChildProfile(ctx, c, ch, su, "", "")
			return err
		}},
		{"set_password", func(f *guardianFixture, c, ch, su string) error {
			return f.svc.SetManagedChildPassword(ctx, c, ch, "An0ther!Str0ng", su, "", "")
		}},
		{"set_username", func(f *guardianFixture, c, ch, su string) error {
			_, err := f.svc.SetManagedChildUsername(ctx, c, ch, "kid.renamed", su, "", "")
			return err
		}},
		{"revoke_sessions", func(f *guardianFixture, c, ch, su string) error {
			return f.svc.RevokeManagedChildSessions(ctx, c, ch, su, "", "")
		}},
		{"deactivate", func(f *guardianFixture, c, ch, su string) error {
			return f.svc.DeactivateManagedChildAccount(ctx, c, ch, "lost tablet", su, "", "")
		}},
		{"reactivate", func(f *guardianFixture, c, ch, su string) error {
			return f.svc.ReactivateManagedChildAccount(ctx, c, ch, su, "", "")
		}},
		{"delete", func(f *guardianFixture, c, ch, su string) error {
			return f.svc.DeleteManagedChildAccount(ctx, c, ch, su, "", "")
		}},
	}
}

// TestGuardianManagement_RequiresEdgeAndStepUp is the core control: EVERY
// operation refuses without an edge and refuses without step-up. Holding a
// valid session is never enough.
func TestGuardianManagement_RequiresEdgeAndStepUp(t *testing.T) {
	ctx := context.Background()
	for _, op := range allGuardianOps() {
		t.Run(op.name, func(t *testing.T) {
			t.Run("no_edge", func(t *testing.T) {
				f := newGuardianFixture(ctx, t)
				stranger := seedConsentingAdult(t, f.repo, "stranger@example.com", hashPW(t, strongPW), adultFactors{phoneVerified: true})
				err := op.call(f, stranger.ID, f.child.ID, strongPW)
				if !errors.Is(err, ErrPermissionDenied) {
					t.Fatalf("err = %v, want ErrPermissionDenied", err)
				}
			})

			t.Run("wrong_step_up", func(t *testing.T) {
				f := newGuardianFixture(ctx, t)
				err := op.call(f, f.guardian.ID, f.child.ID, "not-the-password")
				if !errors.Is(err, ErrParentalConsentStepUpFailed) {
					t.Fatalf("err = %v, want ErrParentalConsentStepUpFailed", err)
				}
			})

			t.Run("missing_step_up", func(t *testing.T) {
				f := newGuardianFixture(ctx, t)
				err := op.call(f, f.guardian.ID, f.child.ID, "")
				if !errors.Is(err, ErrParentalConsentStepUpFailed) {
					t.Fatalf("err = %v, want ErrParentalConsentStepUpFailed", err)
				}
			})

			t.Run("unauthenticated", func(t *testing.T) {
				f := newGuardianFixture(ctx, t)
				if err := op.call(f, "", f.child.ID, strongPW); !errors.Is(err, ErrUnauthenticated) {
					t.Fatalf("err = %v, want ErrUnauthenticated", err)
				}
			})

			t.Run("missing_child_id", func(t *testing.T) {
				f := newGuardianFixture(ctx, t)
				if err := op.call(f, f.guardian.ID, "  ", strongPW); !errors.Is(err, ErrInvalidArgument) {
					t.Fatalf("err = %v, want ErrInvalidArgument", err)
				}
			})

			t.Run("aged_out", func(t *testing.T) {
				f := newGuardianFixture(ctx, t)
				// The managed account has reached the adult band: the edge
				// survives as consent history but confers nothing.
				if err := f.repo.UpdateUser(ctx, f.child.ID, map[string]any{
					"date_of_birth_ms": dobAgeMs(21),
				}); err != nil {
					t.Fatalf("age the child out: %v", err)
				}
				if err := op.call(f, f.guardian.ID, f.child.ID, strongPW); !errors.Is(err, ErrGuardianRightsExpired) {
					t.Fatalf("err = %v, want ErrGuardianRightsExpired", err)
				}
			})
		})
	}
}

// TestGuardianManagement_DenialIsAccountAgnostic pins that a non-guardian
// learns nothing about whether the child account exists.
func TestGuardianManagement_DenialIsAccountAgnostic(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)
	stranger := seedConsentingAdult(t, f.repo, "stranger@example.com", hashPW(t, strongPW), adultFactors{phoneVerified: true})

	_, errExisting := f.svc.GetManagedChildProfile(ctx, stranger.ID, f.child.ID, strongPW, "", "")
	_, errMissing := f.svc.GetManagedChildProfile(ctx, stranger.ID, "no-such-child", strongPW, "", "")
	if !errors.Is(errExisting, ErrPermissionDenied) || !errors.Is(errMissing, ErrPermissionDenied) {
		t.Fatalf("denials = %v / %v, want ErrPermissionDenied for both", errExisting, errMissing)
	}
	if errExisting.Error() != errMissing.Error() {
		t.Fatalf("denial must be account-agnostic: %q vs %q", errExisting, errMissing)
	}
}

// TestGuardianManagement_RevokedConsentEndsRightsImmediately pins that
// revoking parental consent (which deletes the edge) takes effect on the very
// next call — no cached authorization, no grace period.
func TestGuardianManagement_RevokedConsentEndsRightsImmediately(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)

	// Rights hold while the edge does.
	if _, err := f.svc.GetManagedChildProfile(ctx, f.guardian.ID, f.child.ID, strongPW, "", ""); err != nil {
		t.Fatalf("GetManagedChildProfile before revoke: %v", err)
	}

	if err := f.repo.DeleteGuardianEdge(ctx, f.guardian.ID, f.child.ID); err != nil {
		t.Fatalf("DeleteGuardianEdge: %v", err)
	}

	_, err := f.svc.GetManagedChildProfile(ctx, f.guardian.ID, f.child.ID, strongPW, "", "")
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("after edge removal: err = %v, want ErrPermissionDenied", err)
	}
}

// TestGuardianManagement_AgedOutLeavesChildSessionsAlone pins the ageing-out
// transition: the guardian's rights lapse, but the (now adult) account's own
// live sessions are untouched — ageing out is not a security event for the
// account holder.
func TestGuardianManagement_AgedOutLeavesChildSessionsAlone(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)
	seedChildSession(t, f.repo, f.child.ID)

	if err := f.repo.UpdateUser(ctx, f.child.ID, map[string]any{"date_of_birth_ms": dobAgeMs(21)}); err != nil {
		t.Fatalf("age the child out: %v", err)
	}
	if err := f.svc.RevokeManagedChildSessions(ctx, f.guardian.ID, f.child.ID, strongPW, "", ""); !errors.Is(err, ErrGuardianRightsExpired) {
		t.Fatalf("err = %v, want ErrGuardianRightsExpired", err)
	}
	if !f.childSessionsLive(t) {
		t.Fatal("ageing out must not disturb the account holder's own sessions")
	}
}

// TestGuardianManagement_GateOffEdgeIsTheAuthority pins that with the age
// gate off no band can be derived, so the edge alone authorizes — the
// pre-gate behaviour is unchanged.
func TestGuardianManagement_GateOffEdgeIsTheAuthority(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo) // age gate off
	guardian := seedConsentingAdult(t, repo, "parent@example.com", hashPW(t, strongPW), adultFactors{phoneVerified: true})
	child := seedManagedChild(t, repo, "kid.one", 0) // no DOB at all
	seedGuardianEdge(ctx, t, repo, guardian.ID, child.ID)

	if _, err := svc.GetManagedChildProfile(ctx, guardian.ID, child.ID, strongPW, "", ""); err != nil {
		t.Fatalf("gate off: %v", err)
	}
}

// ── Per-operation behaviour ────────────────────────────────────────────

func TestGetManagedChildProfile_ReturnsStoredAccount(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)

	child, err := f.svc.GetManagedChildProfile(ctx, f.guardian.ID, f.child.ID, strongPW, "1.2.3.4", "agent/1.0")
	if err != nil {
		t.Fatalf("GetManagedChildProfile: %v", err)
	}
	if child.ID != f.child.ID || child.Username != "kid.one" {
		t.Fatalf("child = %+v, want the managed account", child)
	}
	if child.AgeBand != "CHILD" || !child.IsMinor {
		t.Fatalf("band = %q minor = %v, want CHILD", child.AgeBand, child.IsMinor)
	}
	if n := f.writer.countByEventTypeActorTarget(string(audit.EventGuardianChildProfileViewed), f.guardian.ID, f.child.ID); n != 1 {
		t.Fatalf("audit events = %d, want 1", n)
	}
}

func TestSetManagedChildPassword_SetsAndCutsSessions(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)
	seedChildSession(t, f.repo, f.child.ID)
	const newPW = "An0ther!Str0ng"

	if err := f.svc.SetManagedChildPassword(ctx, f.guardian.ID, f.child.ID, newPW, strongPW, "", ""); err != nil {
		t.Fatalf("SetManagedChildPassword: %v", err)
	}

	stored, err := f.repo.GetUser(ctx, f.child.ID)
	if err != nil || stored == nil {
		t.Fatalf("stored child: %v %#v", err, stored)
	}
	if !passwords.Verify(newPW, stored.PasswordHash) {
		t.Fatal("the new password does not verify against the stored hash")
	}
	if f.childSessionsLive(t) {
		t.Fatal("setting the password must cut the child's sessions and refresh tokens")
	}
	if n := f.writer.countByEventTypeActorTarget(string(audit.EventGuardianChildPasswordSet), f.guardian.ID, f.child.ID); n != 1 {
		t.Fatalf("audit events = %d, want 1", n)
	}
}

// TestSetManagedChildPassword_EnforcesPasswordPolicy pins that the guardian
// path is held to the same password rules as the self-service paths.
func TestSetManagedChildPassword_EnforcesPasswordPolicy(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)

	err := f.svc.SetManagedChildPassword(ctx, f.guardian.ID, f.child.ID, "short", strongPW, "", "")
	if !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("err = %v, want ErrWeakPassword", err)
	}
	stored, _ := f.repo.GetUser(ctx, f.child.ID)
	if passwords.Verify("short", stored.PasswordHash) {
		t.Fatal("a rejected password must not be stored")
	}
}

func TestSetManagedChildUsername(t *testing.T) {
	ctx := context.Background()

	t.Run("changes the handle", func(t *testing.T) {
		f := newGuardianFixture(ctx, t)
		child, err := f.svc.SetManagedChildUsername(ctx, f.guardian.ID, f.child.ID, "  Kid.Two  ", strongPW, "", "")
		if err != nil {
			t.Fatalf("SetManagedChildUsername: %v", err)
		}
		if child.Username != "kid.two" {
			t.Fatalf("username = %q, want normalized kid.two", child.Username)
		}
		stored, _ := f.repo.GetUser(ctx, f.child.ID)
		if stored.Username != "kid.two" {
			t.Fatalf("stored username = %q, want kid.two", stored.Username)
		}
		if n := f.writer.countByEventTypeAndDetail(string(audit.EventGuardianChildUsernameChanged), "previous_username", "kid.one"); n != 1 {
			t.Fatalf("audit events with previous_username = %d, want 1", n)
		}
	})

	t.Run("rejects a taken handle", func(t *testing.T) {
		f := newGuardianFixture(ctx, t)
		seedManagedChild(t, f.repo, "kid.two", dobAgeMs(9))
		_, err := f.svc.SetManagedChildUsername(ctx, f.guardian.ID, f.child.ID, "kid.two", strongPW, "", "")
		if !errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("err = %v, want ErrAlreadyExists", err)
		}
	})

	t.Run("rejects a malformed handle", func(t *testing.T) {
		f := newGuardianFixture(ctx, t)
		for _, bad := range []string{"ab", "Kid Two", "kid@two", "kid!"} {
			if _, err := f.svc.SetManagedChildUsername(ctx, f.guardian.ID, f.child.ID, bad, strongPW, "", ""); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("username %q: err = %v, want ErrInvalidArgument", bad, err)
			}
		}
	})

	t.Run("is idempotent for the same handle", func(t *testing.T) {
		f := newGuardianFixture(ctx, t)
		child, err := f.svc.SetManagedChildUsername(ctx, f.guardian.ID, f.child.ID, "kid.one", strongPW, "", "")
		if err != nil || child.Username != "kid.one" {
			t.Fatalf("same handle: %v %+v", err, child)
		}
	})

	t.Run("maps a racing unique-index violation", func(t *testing.T) {
		f := newGuardianFixture(ctx, t)
		f.repo.updateUserErr = fmt.Errorf("unique index: %w", ErrAlreadyExists)
		_, err := f.svc.SetManagedChildUsername(ctx, f.guardian.ID, f.child.ID, "kid.three", strongPW, "", "")
		if !errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("err = %v, want ErrAlreadyExists", err)
		}
	})
}

func TestRevokeManagedChildSessions(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)
	seedChildSession(t, f.repo, f.child.ID)

	if err := f.svc.RevokeManagedChildSessions(ctx, f.guardian.ID, f.child.ID, strongPW, "", ""); err != nil {
		t.Fatalf("RevokeManagedChildSessions: %v", err)
	}
	if f.childSessionsLive(t) {
		t.Fatal("a revoked session must not survive, and its refresh token must be gone")
	}
	if n := f.writer.countByEventTypeActorTarget(string(audit.EventGuardianChildSessionsRevoked), f.guardian.ID, f.child.ID); n != 1 {
		t.Fatalf("audit events = %d, want 1", n)
	}
}

func TestDeactivateAndReactivateManagedChildAccount(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)
	seedChildSession(t, f.repo, f.child.ID)

	if err := f.svc.DeactivateManagedChildAccount(ctx, f.guardian.ID, f.child.ID, "lost tablet", strongPW, "", ""); err != nil {
		t.Fatalf("DeactivateManagedChildAccount: %v", err)
	}
	stored, _ := f.repo.GetUser(ctx, f.child.ID)
	if stored.Status != StatusDeactivated {
		t.Fatalf("status = %q, want %q", stored.Status, StatusDeactivated)
	}
	if f.childSessionsLive(t) {
		t.Fatal("deactivation must cut the child's access immediately")
	}
	// Idempotent.
	if err := f.svc.DeactivateManagedChildAccount(ctx, f.guardian.ID, f.child.ID, "", strongPW, "", ""); err != nil {
		t.Fatalf("second deactivate: %v", err)
	}

	// Reversible by the same guardian.
	if err := f.svc.ReactivateManagedChildAccount(ctx, f.guardian.ID, f.child.ID, strongPW, "", ""); err != nil {
		t.Fatalf("ReactivateManagedChildAccount: %v", err)
	}
	stored, _ = f.repo.GetUser(ctx, f.child.ID)
	if stored.Status != StatusActive {
		t.Fatalf("status = %q, want %q", stored.Status, StatusActive)
	}
	if n := f.writer.countByEventTypeActorTarget(string(audit.EventGuardianChildReactivated), f.guardian.ID, f.child.ID); n != 1 {
		t.Fatalf("reactivate audit events = %d, want 1", n)
	}
}

// TestReactivateManagedChildAccount_CannotBypassConsentGate pins that
// reactivation is not a back door out of pending_parental_consent.
func TestReactivateManagedChildAccount_CannotBypassConsentGate(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)
	if err := f.repo.UpdateUser(ctx, f.child.ID, map[string]any{"status": StatusPendingParentalConsent}); err != nil {
		t.Fatalf("gate the child: %v", err)
	}

	err := f.svc.ReactivateManagedChildAccount(ctx, f.guardian.ID, f.child.ID, strongPW, "", "")
	if !errors.Is(err, ErrParentalConsentRequired) {
		t.Fatalf("err = %v, want ErrParentalConsentRequired", err)
	}
	stored, _ := f.repo.GetUser(ctx, f.child.ID)
	if stored.Status != StatusPendingParentalConsent {
		t.Fatalf("status = %q, want the account left gated", stored.Status)
	}
}

// TestDeactivateManagedChildAccount_RefusesOtherStates pins that the
// guardian path does not overwrite another state machine's state.
func TestDeactivateManagedChildAccount_RefusesOtherStates(t *testing.T) {
	ctx := context.Background()
	for _, status := range []string{StatusPendingParentalConsent, StatusPendingDeletion} {
		f := newGuardianFixture(ctx, t)
		if err := f.repo.UpdateUser(ctx, f.child.ID, map[string]any{"status": status}); err != nil {
			t.Fatalf("seed status: %v", err)
		}
		err := f.svc.DeactivateManagedChildAccount(ctx, f.guardian.ID, f.child.ID, "", strongPW, "", "")
		if !errors.Is(err, ErrAccountNotActive) {
			t.Fatalf("status %q: err = %v, want ErrAccountNotActive", status, err)
		}
	}
}

// TestDeleteManagedChildAccount_RunsTheSharedCascade pins that erasure
// DELEGATES to the injected AccountPurger (the AdminService cascade) rather
// than reimplementing it, and that the consent record survives.
func TestDeleteManagedChildAccount_RunsTheSharedCascade(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)
	consent := &ParentalConsentRecord{
		ConsentID:        "pconsent_test",
		ChildUserID:      f.child.ID,
		ConsentingUserID: f.guardian.ID,
		PolicyVersion:    consentPolicyVersion,
		SteppedUp:        true,
		GrantedAt:        1,
	}
	if err := f.repo.CreateParentalConsent(ctx, consent); err != nil {
		t.Fatalf("seed consent: %v", err)
	}

	if err := f.svc.DeleteManagedChildAccount(ctx, f.guardian.ID, f.child.ID, strongPW, "", ""); err != nil {
		t.Fatalf("DeleteManagedChildAccount: %v", err)
	}
	if want := f.guardian.ID + "->" + f.child.ID; len(f.purger.calls) != 1 || f.purger.calls[0] != want {
		t.Fatalf("purger calls = %v, want [%s]", f.purger.calls, want)
	}
	if u, _ := f.repo.GetUser(ctx, f.child.ID); u != nil {
		t.Fatal("the child account must be erased")
	}
	// The compliance artifact survives the erasure, per #448's retention posture.
	if rec, err := f.repo.GetActiveParentalConsentForChild(ctx, f.child.ID); err != nil || rec == nil {
		t.Fatalf("consent record must survive deletion: %v %#v", err, rec)
	}
	if n := f.writer.countByEventTypeActorTarget(string(audit.EventGuardianChildDeleted), f.guardian.ID, f.child.ID); n != 1 {
		t.Fatalf("audit events = %d, want 1", n)
	}
}

// TestDeleteManagedChildAccount_UnwiredPurger pins the fail-closed shape when
// the erasure cascade is not wired.
func TestDeleteManagedChildAccount_UnwiredPurger(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)
	f.svc.purger = nil

	if err := f.svc.DeleteManagedChildAccount(ctx, f.guardian.ID, f.child.ID, strongPW, "", ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("err = %v, want ErrServiceUnavailable", err)
	}
	if u, _ := f.repo.GetUser(ctx, f.child.ID); u == nil {
		t.Fatal("a refused erasure must not delete the account")
	}
}

// TestGuardianManagement_RefusalsAreAudited pins that a refused attempt is as
// visible in the trail as a successful one, with the failing step named.
func TestGuardianManagement_RefusalsAreAudited(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)
	stranger := seedConsentingAdult(t, f.repo, "stranger@example.com", hashPW(t, strongPW), adultFactors{phoneVerified: true})

	if _, err := f.svc.GetManagedChildProfile(ctx, stranger.ID, f.child.ID, strongPW, "", ""); err == nil {
		t.Fatal("expected a refusal")
	}
	if n := f.writer.countByEventTypeAndDetail(string(audit.EventGuardianChildProfileViewed), "step", "not_guardian"); n != 1 {
		t.Fatalf("not_guardian refusals = %d, want 1", n)
	}

	if err := f.svc.RevokeManagedChildSessions(ctx, f.guardian.ID, f.child.ID, "wrong", "", ""); err == nil {
		t.Fatal("expected a step-up refusal")
	}
	if n := f.writer.countByEventTypeAndDetail(string(audit.EventGuardianChildSessionsRevoked), "step", "step_up"); n != 1 {
		t.Fatalf("step_up refusals = %d, want 1", n)
	}
}

// TestGuardianManagement_InactiveGuardianRefused pins that a suspended
// guardian cannot act on a child, even holding the edge and the password.
func TestGuardianManagement_InactiveGuardianRefused(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)
	if err := f.repo.UpdateUser(ctx, f.guardian.ID, map[string]any{"status": StatusDeactivated}); err != nil {
		t.Fatalf("deactivate guardian: %v", err)
	}

	_, err := f.svc.GetManagedChildProfile(ctx, f.guardian.ID, f.child.ID, strongPW, "", "")
	if !errors.Is(err, ErrAccountNotActive) {
		t.Fatalf("err = %v, want ErrAccountNotActive", err)
	}
}

// ── Repository failures propagate, and nothing half-applies ────────────

// TestGuardianManagement_RepoFailuresPropagate walks each storage read the
// guard depends on and asserts the injected failure reaches the caller
// unchanged rather than being swallowed into a denial — a storage outage must
// not look like "you are not a guardian", which would send a parent chasing a
// permissions problem that does not exist.
func TestGuardianManagement_RepoFailuresPropagate(t *testing.T) {
	ctx := context.Background()

	t.Run("edge lookup fails", func(t *testing.T) {
		f := newGuardianFixture(ctx, t)
		f.repo.getGuardianEdgeErr = errConsentInjected
		_, err := f.svc.GetManagedChildProfile(ctx, f.guardian.ID, f.child.ID, strongPW, "", "")
		if !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
		if errors.Is(err, ErrPermissionDenied) {
			t.Fatal("a storage failure must not be reported as a permission denial")
		}
	})

	t.Run("guardian lookup fails", func(t *testing.T) {
		f := newGuardianFixture(ctx, t)
		f.repo.getUserErrByID = map[string]error{f.guardian.ID: errConsentInjected}
		_, err := f.svc.GetManagedChildProfile(ctx, f.guardian.ID, f.child.ID, strongPW, "", "")
		if !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})

	t.Run("child lookup fails", func(t *testing.T) {
		f := newGuardianFixture(ctx, t)
		f.repo.getUserErrByID = map[string]error{f.child.ID: errConsentInjected}
		_, err := f.svc.GetManagedChildProfile(ctx, f.guardian.ID, f.child.ID, strongPW, "", "")
		if !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})

	t.Run("write fails", func(t *testing.T) {
		f := newGuardianFixture(ctx, t)
		f.repo.updateUserErr = errConsentInjected
		if err := f.svc.SetManagedChildPassword(ctx, f.guardian.ID, f.child.ID, "An0ther!Str0ng", strongPW, "", ""); !errors.Is(err, errConsentInjected) {
			t.Fatalf("set password: err = %v, want the injected failure", err)
		}
		if err := f.svc.DeactivateManagedChildAccount(ctx, f.guardian.ID, f.child.ID, "", strongPW, "", ""); !errors.Is(err, errConsentInjected) {
			t.Fatalf("deactivate: err = %v, want the injected failure", err)
		}
	})

	t.Run("session revocation fails", func(t *testing.T) {
		f := newGuardianFixture(ctx, t)
		f.repo.deleteRefreshTokensErr = errConsentInjected
		if err := f.svc.RevokeManagedChildSessions(ctx, f.guardian.ID, f.child.ID, strongPW, "", ""); !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})

	t.Run("username lookup fails", func(t *testing.T) {
		f := newGuardianFixture(ctx, t)
		f.repo.findUserByEmailErr = nil
		f.repo.getUserErr = nil
		f.repo.updateUserErr = errConsentInjected
		if _, err := f.svc.SetManagedChildUsername(ctx, f.guardian.ID, f.child.ID, "kid.renamed", strongPW, "", ""); !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})

	t.Run("erasure fails", func(t *testing.T) {
		f := newGuardianFixture(ctx, t)
		f.purger.err = errConsentInjected
		if err := f.svc.DeleteManagedChildAccount(ctx, f.guardian.ID, f.child.ID, strongPW, "", ""); !errors.Is(err, errConsentInjected) {
			t.Fatalf("err = %v, want the injected failure", err)
		}
	})
}

// TestGuardianManagement_ReactivateIdempotentAndRefusals covers the states an
// already-active or otherwise-ineligible account lands in.
func TestGuardianManagement_ReactivateIdempotentAndRefusals(t *testing.T) {
	ctx := context.Background()

	// Already active: a no-op success, not an error.
	f := newGuardianFixture(ctx, t)
	if err := f.svc.ReactivateManagedChildAccount(ctx, f.guardian.ID, f.child.ID, strongPW, "", ""); err != nil {
		t.Fatalf("reactivating an active account must be a no-op: %v", err)
	}

	// Pending deletion is another state machine's; refuse rather than
	// overwrite it.
	f2 := newGuardianFixture(ctx, t)
	if err := f2.repo.UpdateUser(ctx, f2.child.ID, map[string]any{"status": StatusPendingDeletion}); err != nil {
		t.Fatalf("seed status: %v", err)
	}
	if err := f2.svc.ReactivateManagedChildAccount(ctx, f2.guardian.ID, f2.child.ID, strongPW, "", ""); !errors.Is(err, ErrAccountNotActive) {
		t.Fatalf("err = %v, want ErrAccountNotActive", err)
	}
}

// TestSetManagedChildPassword_ClearsLockout pins that the guardian path is a
// real recovery route: a child locked out by failed attempts can sign in with
// the new password immediately, without waiting out the lockout window. It is
// the ONLY recovery path an email-less child has.
func TestSetManagedChildPassword_ClearsLockout(t *testing.T) {
	ctx := context.Background()
	f := newGuardianFixture(ctx, t)
	if err := f.repo.UpdateUser(ctx, f.child.ID, map[string]any{
		"failed_login_count": 5,
		"locked_until":       f.svc.nowMs() + 900_000,
	}); err != nil {
		t.Fatalf("seed lockout: %v", err)
	}

	const newPW = "An0ther!Str0ng"
	if err := f.svc.SetManagedChildPassword(ctx, f.guardian.ID, f.child.ID, newPW, strongPW, "", ""); err != nil {
		t.Fatalf("SetManagedChildPassword: %v", err)
	}
	stored, _ := f.repo.GetUser(ctx, f.child.ID)
	if stored.LockedUntil != 0 || stored.FailedLoginCount != 0 {
		t.Fatalf("lockout survived the reset: locked_until=%d failed=%d",
			stored.LockedUntil, stored.FailedLoginCount)
	}
}
