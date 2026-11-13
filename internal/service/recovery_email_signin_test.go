package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/agegate"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/jwt"
)

// newRecoverySignInFixture is a project that keeps recovery emails and lets
// them sign in, with the given access policy.
func newRecoverySignInFixture(t *testing.T, access ProjectAccessConfig) *recoveryEmailFixture {
	t.Helper()
	f := newRecoveryEmailFixture(t, ProjectRecoveryEmailsConfig{Enabled: true, SignIn: true})
	scope := *ProjectScopeFromContext(f.ctx)
	scope.Access = access
	f.ctx = WithProjectScope(context.Background(), &scope)
	return f
}

// signInWith runs the emailed-code sign-in for addr.
func (f *recoveryEmailFixture) signInWith(ctx context.Context, t *testing.T, addr string) (*LoginResult, error) {
	t.Helper()
	if err := f.svc.RequestEmailLoginCode(ctx, addr); err != nil {
		t.Fatalf("RequestEmailLoginCode(%s): %v", addr, err)
	}
	return f.svc.VerifyEmailLoginCode(ctx, addr, f.codeMailedTo(t, strings.ToLower(addr)), "203.0.113.7", "test-agent")
}

func (f *recoveryEmailFixture) userCount() int {
	f.repo.mu.Lock()
	defer f.repo.mu.Unlock()
	return len(f.repo.users)
}

func TestRecoveryEmailSignIn_LandsInTheHoldingAccountAndTellsItsOtherAddresses(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	user.EmailVerified = true
	f.add(t, user, "spare@example.net")
	f.add(t, user, "second@example.net")
	users, sent := f.userCount(), f.mailer.count()

	result, err := f.signInWith(f.ctx, t, "Spare@example.net")
	if err != nil {
		t.Fatalf("sign-in by a recovery email: %v", err)
	}
	if result.User.ID != user.ID || result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatalf("signed in to %q with tokens %t/%t, want the holding account %q",
			result.User.ID, result.AccessToken != "", result.RefreshToken != "", user.ID)
	}
	if f.userCount() != users {
		t.Fatalf("the sign-in made a new account: %d users, want %d", f.userCount(), users)
	}
	const subject = "Your account was signed in to with a recovery email"
	for _, addr := range []string{"owner@example.com", "second@example.net"} {
		got := f.mailedTo(addr)
		if len(got) == 0 || got[len(got)-1].Subject != subject {
			t.Fatalf("%s was not told of the sign-in: %#v", addr, got)
		}
		// The notice says what the session cannot do, how to end it, and
		// what to check afterwards: what the session may grant once the hold
		// is over outlasts the address.
		for _, says := range []string{
			"spare@example.net", "cannot add or remove", "hand out access that would outlast it",
			"remove the address, which ends the session", "connected agents and their delegations",
			"agent machines and teammate keys", "owners and roles of your tenants",
		} {
			if !strings.Contains(got[len(got)-1].Text, says) {
				t.Fatalf("the notice to %s does not say %q:\n%s", addr, says, got[len(got)-1].Text)
			}
		}
	}
	// The login code, then nothing: the address that signed in needs no notice.
	if f.mailer.count() != sent+3 {
		t.Fatalf("%d messages after the request, want the code and two notices", f.mailer.count()-sent)
	}
}

// sessionAMR is the amr claim of an access token the fixture's service minted.
func (f *recoveryEmailFixture) sessionAMR(t *testing.T, accessToken string) []string {
	t.Helper()
	claims, err := jwt.VerifyAccessToken(accessToken, f.svc.signer, "", "", false)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	return claims.AMR
}

// holdUntil is when the recovery hold on userID's account ends, 0 for none.
func (f *recoveryEmailFixture) holdUntil(t *testing.T, userID string) int64 {
	t.Helper()
	_, until, err := f.svc.ListRecoveryEmails(f.ctx, userID)
	if err != nil {
		t.Fatalf("ListRecoveryEmails: %v", err)
	}
	return until
}

// addSession stores a session of userID's under id, whose access tokens
// carry the sid sid ("" outside GATEWAY_REVOCATION_MODE=session).
func (f *recoveryEmailFixture) addSession(userID, id, sid string) {
	f.db.addRefreshToken(id, userID, f.now.Add(time.Hour).UnixMilli())
	f.db.mu.Lock()
	defer f.db.mu.Unlock()
	f.db.nodes[id].Payload[rfSID] = sid
}

// heldChanges are the changes a session a recovery hold binds may not make,
// each asked for by session: the account security changes, those that add a
// way in or a way to recover the account, take one away, replace one, end
// another session, or delete the account; and the grants of authority that
// would outlast the hold (heldGrants). It is the list the recovery-emails
// docs page (docs-site auth/recovery-emails) gives; keep the two the same.
// The project-admin calls the hold refuses are AdminService's, whose clock
// the fixture does not set (TestRecoveryHold_HoldsTheAdminSeatsGrants).
func (f *recoveryEmailFixture) heldChanges(userID string, session SessionSignIn) map[string]func() error {
	changes := f.heldGrants(userID, session)
	for name, change := range f.heldSecurityChanges(userID, session) {
		changes[name] = change
	}
	return changes
}

// heldAgentStore is the fixture's store as AgentOAuthService finds a machine
// registry in it. The hold refuses before the registry is read, so none is
// behind it.
type heldAgentStore struct {
	*fakeRepo
	AgentMachineRepository
}

func (r heldAgentStore) WithProject(string) Repository { return r }

// heldGrants are the calls that hand out authority outlasting the session,
// each asked for by session from userID's account: a delegation to an
// agent, an agent machine and the agents it acts as, a teammate's hire, an
// OAuth client, a guardian's control over a child, an agent's new owner, and
// who belongs to a tenant and with what role.
func (f *recoveryEmailFixture) heldGrants(userID string, session SessionSignIn) map[string]func() error {
	now := func() time.Time { return f.now }
	f.svc.cfg.AgentMachineEnabled = true
	agents := &AgentOAuthService{auth: f.svc, base: heldAgentStore{fakeRepo: f.repo}}
	human := AgentOAuthHuman{UserID: userID, SignIn: session}
	if human.SignIn.SessionID == "" {
		human.SignIn.SessionID = "sid-held"
	}
	keys := &TeammateKeyService{base: f.repo, logger: zap.NewNop(), audit: audit.NewLogger(nil, "project-a", zap.NewNop()), now: now}
	members := NewMembershipService(newFakeInvitationStore(), newFakeMembershipStore(), newFakeTenantStore(), newFakeUserDirectory(), f.mailer, true, &config.Config{}, nil).WithAccounts(f.repo)
	members.nowFunc = now
	domains := NewDomainService(newFakeDomainStore(), newFakeTenantStore(), newFakeMembershipStore(), nil, &config.Config{}, nil).WithAccounts(f.repo)
	domains.nowFunc = now
	return map[string]func() error{
		"GetAgentAuthorization": func() error {
			_, err := agents.GetConsent(f.ctx, human, "request-1", 0)
			return err
		},
		"DecideAgentAuthorization": func() error {
			_, err := agents.Decide(f.ctx, human, "request-1", 1, true, "agent-1")
			return err
		},
		"RegisterAgentMachine": func() error {
			_, err := agents.RegisterMachine(f.ctx, human, AgentMachineRegistration{ID: "machine-1", ClientID: "client-1"})
			return err
		},
		"SelectAgentMachineAgents": func() error {
			_, err := agents.SelectMachineAgents(f.ctx, human, "machine-1", 1, true, nil, nil)
			return err
		},
		"CreateHireGrant": func() error {
			_, err := keys.CreateHireGrant(f.ctx, userID, session, "agent-1", "placement-1", "company-1")
			return err
		},
		"CreateOAuthClient": func() error {
			_, err := f.svc.CreateOAuthClient(f.ctx, userID, session, &OAuthClientRegistration{})
			return err
		},
		"UpdateOAuthClient": func() error {
			_, err := f.svc.UpdateOAuthClient(f.ctx, userID, session, "client-1", 1, &OAuthClientRegistration{})
			return err
		},
		"GrantParentalConsent": func() error {
			_, err := f.svc.GrantParentalConsent(f.ctx, userID, session, "child-1", "v1", "Str0ng!Pass1", "", "")
			return err
		},
		"CreateManagedChildAccount": func() error {
			_, err := f.svc.CreateManagedChildAccount(f.ctx, userID, session, ManagedChildAccountRequest{Username: "kid"}, "", "")
			return err
		},
		"GetManagedChildProfile": func() error {
			_, err := f.svc.GetManagedChildProfile(f.ctx, userID, session, "child-1", "Str0ng!Pass1", "", "")
			return err
		},
		"SetManagedChildPassword": func() error {
			return f.svc.SetManagedChildPassword(f.ctx, userID, session, "child-1", "N3w!Str0ngPass", "Str0ng!Pass1", "", "")
		},
		"SetManagedChildUsername": func() error {
			_, err := f.svc.SetManagedChildUsername(f.ctx, userID, session, "child-1", "kid", "Str0ng!Pass1", "", "")
			return err
		},
		"RevokeManagedChildSessions": func() error {
			return f.svc.RevokeManagedChildSessions(f.ctx, userID, session, "child-1", "Str0ng!Pass1", "", "")
		},
		"DeactivateManagedChildAccount": func() error {
			return f.svc.DeactivateManagedChildAccount(f.ctx, userID, session, "child-1", "", "Str0ng!Pass1", "", "")
		},
		"ReactivateManagedChildAccount": func() error {
			return f.svc.ReactivateManagedChildAccount(f.ctx, userID, session, "child-1", "Str0ng!Pass1", "", "")
		},
		"DeleteManagedChildAccount": func() error {
			return f.svc.DeleteManagedChildAccount(f.ctx, userID, session, "child-1", "Str0ng!Pass1", "", "")
		},
		"TransferAgent": func() error {
			_, err := f.svc.TransferAgent(f.ctx, userID, session, "agent-1", "someone-else", "", "")
			return err
		},
		"CreateTenantInvitation": func() error {
			_, err := members.CreateTenantInvitation(f.ctx, userID, session, "tenant-1", "invitee@example.org", RoleAdmin)
			return err
		},
		"RemoveTenantMember": func() error {
			return members.RemoveTenantMember(f.ctx, userID, session, "tenant-1", "member-1", "", "")
		},
		"SuspendTenantMember": func() error {
			_, err := members.SuspendTenantMember(f.ctx, userID, session, "tenant-1", "member-1", "", "")
			return err
		},
		"RestoreTenantMember": func() error {
			_, err := members.RestoreTenantMember(f.ctx, userID, session, "tenant-1", "member-1", "", "")
			return err
		},
		"TransferTenantOwnership": func() error {
			_, err := members.TransferTenantOwnership(f.ctx, userID, session, "tenant-1", "member-1", "", "")
			return err
		},
		"CreateDomain": func() error {
			_, err := domains.CreateDomain(f.ctx, userID, session, "tenant-1", "example.org", DomainVerificationDNSTXT)
			return err
		},
		"VerifyDomain": func() error {
			_, err := domains.VerifyDomain(f.ctx, userID, session, "domain-1")
			return err
		},
		"SetDomainJoin": func() error {
			_, err := domains.SetDomainJoin(f.ctx, userID, session, "domain-1", true, "", "")
			return err
		},
	}
}

// heldSecurityChanges are the account security changes heldChanges lists.
func (f *recoveryEmailFixture) heldSecurityChanges(userID string, session SessionSignIn) map[string]func() error {
	return map[string]func() error{
		"RequestRecoveryEmail": func() error {
			return f.svc.RequestRecoveryEmail(f.ctx, userID, session, "added@example.net")
		},
		"VerifyRecoveryEmail": func() error {
			_, err := f.svc.VerifyRecoveryEmail(f.ctx, userID, session, "added@example.net", "123456")
			return err
		},
		"RemoveRecoveryEmail": func() error {
			_, err := f.svc.RemoveRecoveryEmail(f.ctx, userID, session, "spare@example.net")
			return err
		},
		"RequestPhoneVerification": func() error {
			return f.svc.RequestPhoneVerification(f.ctx, userID, session, "+14155550123")
		},
		"VerifyPhoneCode": func() error {
			_, err := f.svc.VerifyPhoneCode(f.ctx, userID, session, "+14155550123", "123456")
			return err
		},
		"RemovePhone": func() error {
			_, err := f.svc.RemovePhone(f.ctx, userID, session)
			return err
		},
		"BeginTotpSetup": func() error {
			_, _, _, err := f.svc.BeginTotpSetup(f.ctx, userID, session)
			return err
		},
		"VerifyTotpSetup": func() error {
			_, err := f.svc.VerifyTotpSetup(f.ctx, userID, session, "123456")
			return err
		},
		"BeginPasskeyRegistration": func() error {
			_, _, err := f.svc.BeginPasskeyRegistration(f.ctx, userID, session, "Key")
			return err
		},
		"CompletePasskeyRegistration": func() error {
			_, _, err := f.svc.CompletePasskeyRegistration(f.ctx, userID, session, "challenge", "{}", "Key", false, "", "")
			return err
		},
		"LinkIdentity": func() error {
			_, err := f.svc.LinkIdentity(f.ctx, userID, session, "code", "google", "https://app.test/cb", "", "", "")
			return err
		},
		"DisableTotp": func() error {
			return f.svc.DisableTotp(f.ctx, userID, session, "Str0ng!Pass1")
		},
		"RegenerateRecoveryCodes": func() error {
			_, err := f.svc.RegenerateRecoveryCodes(f.ctx, userID, session, "Str0ng!Pass1")
			return err
		},
		"RequestEmailChange": func() error {
			return f.svc.RequestEmailChange(f.ctx, userID, session, "moved@example.org", "Str0ng!Pass1")
		},
		"ChangePassword": func() error {
			return f.profile.ChangePassword(f.ctx, userID, session, "Str0ng!Pass1", "N3w!Str0ngPass")
		},
		"DeletePasskey": func() error {
			return f.profile.DeletePasskey(f.ctx, userID, session, "cred-held")
		},
		"UnlinkIdentity": func() error {
			return f.profile.UnlinkIdentity(f.ctx, userID, session, "google", "g-held")
		},
		"RevokeSession": func() error {
			f.addSession(userID, "held-other-session", "sid-other")
			return f.profile.RevokeSession(f.ctx, userID, session, "held-other-session")
		},
		"RevokeAllSessions": func() error {
			_, err := f.profile.RevokeAllSessions(f.ctx, userID, session, "Str0ng!Pass1")
			return err
		},
		"DeleteMyAccount": func() error {
			_, err := f.profile.DeleteMyAccount(f.ctx, userID, session, "")
			return err
		},
	}
}

func TestRecoveryEmailSignIn_MarksTheSessionAndHoldsOnlyIt(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	f.svc.cfg.SMSEnabled = true
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "spare@example.net")
	f.repo.mu.Lock()
	f.repo.users[user.ID].PhoneNumber, f.repo.users[user.ID].PhoneVerified = "+14155550199", true
	f.repo.mu.Unlock()

	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("hold before any recovery sign-in = %d, want 0", until)
	}
	result, err := f.signInWith(f.ctx, t, "spare@example.net")
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if amr := f.sessionAMR(t, result.AccessToken); !slices.Equal(amr, []string{AMRRecoveryEmail}) {
		t.Fatalf("the session's amr = %v, want [%s]", amr, AMRRecoveryEmail)
	}
	_, refreshed, _, err := f.svc.RefreshToken(f.ctx, result.RefreshToken, "", "", "")
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if amr := f.sessionAMR(t, refreshed); !slices.Equal(amr, []string{AMRRecoveryEmail}) {
		t.Fatalf("a refreshed session's amr = %v, want [%s]", amr, AMRRecoveryEmail)
	}
	wantUntil := f.now.Add(7 * 24 * time.Hour).UnixMilli()
	if until := f.holdUntil(t, user.ID); until != wantUntil {
		t.Fatalf("listed hold = %d, want %d", until, wantUntil)
	}

	// The session the recovery email opened, and one no host vouched for,
	// make no account security change.
	for name, change := range f.heldChanges(user.ID, f.recoverySignedInNow(t, user, "spare@example.net")) {
		var hold *RecoveryHoldError
		if err := change(); !errors.As(err, &hold) || !errors.Is(err, ErrRecoveryHold) || hold.UntilMs != wantUntil {
			t.Fatalf("%s by the recovery session during the hold = %v (%+v), want a RecoveryHoldError until %d", name, err, hold, wantUntil)
		}
	}
	// One no host vouched for cannot name the address behind it, so where
	// recovery emails sign in it is taken for a recovery session whose
	// address may be gone, hold or not; and so is one that says a recovery
	// email opened it but names none.
	for _, session := range []SessionSignIn{
		{AuthTimeSec: f.now.Unix(), AMR: []string{AMRUnvouched}},
		{AuthTimeSec: f.now.Unix(), AMR: []string{AMRRecoveryEmail}},
	} {
		for name, change := range f.heldChanges(user.ID, session) {
			if err := change(); !errors.Is(err, ErrRecoverySession) {
				t.Fatalf("%s by a %v session naming no recovery email = %v, want ErrRecoverySession", name, session.AMR, err)
			}
		}
	}
	// Nor can it hand a session to another device, which would not carry
	// its amr.
	qr, err := f.svc.InitiateQrLogin(f.ctx, "laptop", "agent", "203.0.113.9")
	if err != nil {
		t.Fatalf("InitiateQrLogin: %v", err)
	}
	if _, err := f.svc.ApproveQrLogin(f.ctx, qr.SessionID, true, user.ID, f.recoverySignedInNow(t, user, "spare@example.net"), "", ""); !errors.Is(err, ErrRecoverySession) {
		t.Fatalf("QR approval by a recovery session: want ErrRecoverySession, got %v", err)
	}

	// The owner, signed in with the primary email, is not held: they remove
	// the address that started the hold, and that ends it.
	if _, err := f.svc.RemoveRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net"); err != nil {
		t.Fatalf("the owner removes the compromised address during the hold: %v", err)
	}
	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("hold after the address that started it was removed = %d, want 0", until)
	}
}

// Removing the address ends the hold and, in the same write, the sessions
// the address opened. Their access tokens outlive that write: for the rest of
// their lifetime under GATEWAY_REVOCATION_MODE=ttl, and under session for as
// long as another replica's cache passes them. No hold binds them any more,
// so each is refused every account security change by the recovery email it
// names, which the account no longer holds. A recovery session whose address
// is still held is not, and neither is the session of an address removed and
// added again, which is a new address: the old session stays refused.
func TestRecoveryHold_ARemovedAddressEndsItsSessionsChangesInEitherMode(t *testing.T) {
	for _, mode := range []config.RevocationMode{config.RevocationModeTTL, config.RevocationModeSession} {
		t.Run(string(mode), func(t *testing.T) {
			f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
			f.svc.cfg.RevocationMode = mode
			f.svc.cfg.SMSEnabled = true
			f.svc.cfg.AccountMergeEnabled = true
			user := seedUser(f.repo, "owner@example.com", "", StatusActive)
			f.add(t, user, "spare@example.net")
			f.add(t, user, "kept@example.net")
			f.repo.mu.Lock()
			f.repo.users[user.ID].PhoneNumber, f.repo.users[user.ID].PhoneVerified = "+14155550199", true
			f.repo.mu.Unlock()
			result, err := f.signInWith(f.ctx, t, "spare@example.net")
			if err != nil {
				t.Fatalf("sign-in by the recovery email: %v", err)
			}
			claims, err := jwt.VerifyAccessToken(result.AccessToken, f.svc.signer, "", "", false)
			if err != nil || claims.RecoveryEmailID != f.recoveryEmailID(t, user.ID, "spare@example.net") || (claims.SID == "") != (mode == config.RevocationModeTTL) {
				t.Fatalf("the recovery session's token = %+v %v, want the address's id and a sid only in session mode", claims, err)
			}
			ended := SessionSignIn{AuthTimeSec: claims.AuthTime, AMR: claims.AMR, RecoveryEmailID: claims.RecoveryEmailID, SessionID: claims.SID}

			if _, err := f.svc.RemoveRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net"); err != nil {
				t.Fatalf("the owner removes the address: %v", err)
			}
			if until := f.holdUntil(t, user.ID); until != 0 {
				t.Fatalf("hold after the address was removed = %d, want 0", until)
			}
			f.add(t, user, "spare@example.net")
			for name, change := range f.heldChanges(user.ID, ended) {
				if err := change(); !errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrRecoveryHold) {
					t.Fatalf("%s by the removed address's session = %v, want ErrUnauthenticated", name, err)
				}
			}
			if _, err := f.svc.MergeAccounts(f.ctx, user.ID, ended, "other@example.com", "Str0ng!Pass1", "", "", false); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("MergeAccounts by the removed address's session = %v, want ErrUnauthenticated", err)
			}

			kept := f.recoverySignedInNow(t, user, "kept@example.net")
			if err := f.svc.refuseHeldSession(f.ctx, user.ID, kept); err != nil {
				t.Fatalf("a recovery session whose address is held, no hold in force = %v, want nil", err)
			}
		})
	}
}

// During a hold the recovery session cannot take the owner's ways in or
// sessions away, which would leave the owner with nothing but the address
// the hold is about; it can still end itself. The owner's session, opened by
// the primary email or a passkey, removes each of them as at any time.
func TestRecoveryHold_RemovalsAreHeldFromTheRecoverySessionOnly(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "spare@example.net")
	if _, err := f.signInWith(f.ctx, t, "spare@example.net"); err != nil {
		t.Fatalf("sign-in by the recovery email: %v", err)
	}
	f.db.addPasskey("pk-1", user.ID, "cred-1", "Laptop")
	for _, id := range []string{"g-1", "g-2"} {
		if err := f.repo.CreateOAuthIdentity(f.ctx, &OAuthIdentity{UserID: user.ID, Provider: "google", ProviderUserID: id}); err != nil {
			t.Fatalf("CreateOAuthIdentity: %v", err)
		}
	}
	f.addSession(user.ID, "owner-laptop", "sid-laptop")
	f.addSession(user.ID, "recovery-phone", "sid-recovery")
	recovery := f.recoverySignedInNow(t, user, "spare@example.net")
	recovery.SessionID = "sid-recovery"

	for name, remove := range map[string]func() error{
		"DeletePasskey":  func() error { return f.profile.DeletePasskey(f.ctx, user.ID, recovery, "cred-1") },
		"UnlinkIdentity": func() error { return f.profile.UnlinkIdentity(f.ctx, user.ID, recovery, "google", "g-1") },
		"RevokeSession":  func() error { return f.profile.RevokeSession(f.ctx, user.ID, recovery, "owner-laptop") },
		"DeleteMyAccount": func() error {
			_, err := f.profile.DeleteMyAccount(f.ctx, user.ID, recovery, "")
			return err
		},
	} {
		if err := remove(); !errors.Is(err, ErrRecoveryHold) {
			t.Fatalf("%s by the recovery session during the hold = %v, want ErrRecoveryHold", name, err)
		}
	}
	if err := f.profile.RevokeSession(f.ctx, user.ID, recovery, "recovery-phone"); err != nil {
		t.Fatalf("the recovery session ends itself during the hold: %v", err)
	}

	owner := f.signedInNow()
	if err := f.profile.DeletePasskey(f.ctx, user.ID, owner, "cred-1"); err != nil {
		t.Fatalf("the owner removes a passkey during the hold: %v", err)
	}
	if err := f.profile.UnlinkIdentity(f.ctx, user.ID, owner, "google", "g-1"); err != nil {
		t.Fatalf("the owner unlinks a provider during the hold: %v", err)
	}
	if err := f.profile.RevokeSession(f.ctx, user.ID, owner, "owner-laptop"); err != nil {
		t.Fatalf("the owner ends a session during the hold: %v", err)
	}
	if _, err := f.profile.DeleteMyAccount(f.ctx, user.ID, owner, ""); err != nil {
		t.Fatalf("the owner deletes the account during the hold: %v", err)
	}
	passkeys, err := f.profile.ListMyPasskeys(f.ctx, user.ID)
	if err != nil || len(passkeys) != 0 {
		t.Fatalf("passkeys after the owner removed theirs = %v %v, want none", passkeys, err)
	}
	links, err := f.profile.ListLinkedIdentities(f.ctx, user.ID)
	if err != nil || len(links) != 1 || links[0].ProviderUserID != "g-2" {
		t.Fatalf("links after the owner unlinked one = %+v %v, want g-2 alone", links, err)
	}
}

// A session no one vouched for how it was opened (the native-gRPC bridge
// without GRPCTrustAMR) may be one a recovery email opened. In a project
// whose recovery emails sign in it is taken for one, which cannot name its
// address: it approves no QR sign-in and makes no account security change,
// hold or not. Elsewhere it is refused both while a hold is in force, and
// otherwise approves and changes as before. A session a recovery email opened
// approves none, hold or not.
func TestRecoveryHold_AnUnvouchedSessionIsTakenForARecoverySessionWhereOneCouldBe(t *testing.T) {
	f := newRecoveryEmailFixture(t, ProjectRecoveryEmailsConfig{Enabled: true})
	signInOn := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "project-a", Access: ProjectAccessConfig{Mode: AccessModeOpen},
		RecoveryEmails: ProjectRecoveryEmailsConfig{Enabled: true, SignIn: true},
	})
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "spare@example.net")
	approve := func(ctx context.Context, session SessionSignIn) (string, error) {
		t.Helper()
		qr, err := f.svc.InitiateQrLogin(ctx, "laptop", "agent", "203.0.113.9")
		if err != nil {
			t.Fatalf("InitiateQrLogin: %v", err)
		}
		return f.svc.ApproveQrLogin(ctx, qr.SessionID, true, user.ID, session, "", "")
	}
	unvouched := SessionSignIn{AuthTimeSec: f.now.Unix(), AMR: []string{AMRUnvouched}}

	if status, err := approve(f.ctx, unvouched); err != nil || status != "approved" {
		t.Fatalf("approval by an unvouched session with no hold = %q %v, want approved", status, err)
	}
	if err := f.svc.refuseHeldSession(f.ctx, user.ID, unvouched); err != nil {
		t.Fatalf("an unvouched session with no hold, where recovery emails do not sign in = %v, want nil", err)
	}
	if _, err := approve(signInOn, unvouched); !errors.Is(err, ErrRecoverySession) {
		t.Fatalf("approval by an unvouched session where recovery emails sign in = %v, want ErrRecoverySession", err)
	}
	if err := f.svc.refuseHeldSession(signInOn, user.ID, unvouched); !errors.Is(err, ErrRecoverySession) {
		t.Fatalf("a change by an unvouched session where recovery emails sign in = %v, want ErrRecoverySession", err)
	}

	hold := 7 * 24 * time.Hour
	if err := f.repo.MarkRecoveryEmailSignIn(f.ctx, user.ID, f.recoveryEmailID(t, user.ID, "spare@example.net"), f.now.UnixMilli(), hold.Milliseconds()); err != nil {
		t.Fatalf("MarkRecoveryEmailSignIn: %v", err)
	}
	if _, err := approve(f.ctx, unvouched); !errors.Is(err, ErrRecoverySession) {
		t.Fatalf("approval by an unvouched session during the hold = %v, want ErrRecoverySession", err)
	}
	if err := f.svc.refuseHeldSession(f.ctx, user.ID, unvouched); !errors.Is(err, ErrRecoveryHold) {
		t.Fatalf("a change by an unvouched session during the hold = %v, want ErrRecoveryHold", err)
	}

	f.now = f.now.Add(hold + time.Hour)
	if status, err := approve(f.ctx, unvouched); err != nil || status != "approved" {
		t.Fatalf("approval by an unvouched session after the hold = %q %v, want approved", status, err)
	}
	if _, err := approve(f.ctx, f.recoverySignedInNow(t, user, "spare@example.net")); !errors.Is(err, ErrRecoverySession) {
		t.Fatalf("approval by a recovery session after the hold = %v, want ErrRecoverySession", err)
	}
}

// removedOnMarkRepo removes addr from its account right after a sign-in by
// it is marked, as the owner's RemoveRecoveryEmail landing between the two
// would.
type removedOnMarkRepo struct {
	*fakeRepo
	addr string
}

func (r removedOnMarkRepo) WithProject(string) Repository { return r }

func (r removedOnMarkRepo) MarkRecoveryEmailSignIn(ctx context.Context, userID, id string, atMs, holdMs int64) error {
	if err := r.fakeRepo.MarkRecoveryEmailSignIn(ctx, userID, id, atMs, holdMs); err != nil {
		return err
	}
	_, err := r.RemoveRecoveryEmail(ctx, userID, r.addr, atMs)
	return err
}

// An address the owner removes while its sign-in is being opened ends that
// sign-in: it is refused, holds nothing, and no notice goes out about a hold
// that is not in force.
func TestRecoveryEmailSignIn_AddressRemovedMidSignInSendsNoNotice(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "spare@example.net")
	f.svc.defaultRepo = removedOnMarkRepo{fakeRepo: f.repo, addr: "spare@example.net"}

	if err := f.svc.RequestEmailLoginCode(f.ctx, "spare@example.net"); err != nil {
		t.Fatalf("RequestEmailLoginCode: %v", err)
	}
	code, sent := f.codeMailedTo(t, "spare@example.net"), f.mailer.count()
	if _, err := f.svc.VerifyEmailLoginCode(f.ctx, "spare@example.net", code, "203.0.113.7", "test-agent"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("sign-in by an address removed as it was opened = %v, want ErrUnauthenticated", err)
	}
	if n := f.mailer.count() - sent; n != 0 {
		t.Fatalf("%d messages after the refused sign-in, want none: %#v", n, f.mailedTo("owner@example.com"))
	}
	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("hold after the refused sign-in = %d, want 0", until)
	}
}

// sessionRevokedAt is when the access session of accessToken was revoked, 0
// while it is live.
func (f *recoveryEmailFixture) sessionRevokedAt(t *testing.T, accessToken string) int64 {
	t.Helper()
	claims, err := jwt.VerifyAccessToken(accessToken, f.svc.signer, "", "", false)
	if err != nil || claims.SID == "" {
		t.Fatalf("VerifyAccessToken = %+v %v, want a token with a sid", claims, err)
	}
	session, err := f.repo.GetSessionBySid(f.ctx, claims.SID)
	if err != nil || session == nil {
		t.Fatalf("GetSessionBySid(%s) = %#v %v", claims.SID, session, err)
	}
	return session.RevokedAtMs
}

// The owner removing a compromised recovery email ends every session that
// address opened, the token it rotated away included, and no other: the
// account's other recovery email's session and the owner's own keep
// refreshing, so the refused tokens did not set off the replay alarm that
// signs an account out everywhere. The ended sessions' access tokens stop
// working at once, and their end is audited.
func TestRemoveRecoveryEmail_EndsTheSessionsTheAddressOpened(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	f.svc.cfg.RevocationMode = config.RevocationModeSession
	w := newRecordingAuditWriter()
	f.svc.audit = audit.NewLogger(w, "test-tenant", nil)
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "stolen@example.net")
	f.add(t, user, "kept@example.net")

	stolen, err := f.signInWith(f.ctx, t, "stolen@example.net")
	if err != nil {
		t.Fatalf("sign-in by the stolen address: %v", err)
	}
	_, rotatedAccess, rotatedRefresh, err := f.svc.RefreshToken(f.ctx, stolen.RefreshToken, "", "", "")
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	kept, err := f.signInWith(f.ctx, t, "kept@example.net")
	if err != nil {
		t.Fatalf("sign-in by the kept address: %v", err)
	}
	owner, err := f.signInWith(f.ctx, t, "owner@example.com")
	if err != nil {
		t.Fatalf("sign-in by the primary email: %v", err)
	}

	if _, err := f.svc.RemoveRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "Stolen@example.net"); err != nil {
		t.Fatalf("the owner removes the stolen address: %v", err)
	}
	for name, token := range map[string]string{"current": rotatedRefresh, "rotated away": stolen.RefreshToken} {
		if _, _, _, err := f.svc.RefreshToken(f.ctx, token, "", "", ""); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("refresh of the stolen session's %s token: want ErrUnauthenticated, got %v", name, err)
		}
	}
	for _, access := range []string{stolen.AccessToken, rotatedAccess} {
		if at := f.sessionRevokedAt(t, access); at != f.now.UnixMilli() {
			t.Fatalf("the stolen session's access session revoked at %d, want %d", at, f.now.UnixMilli())
		}
	}
	for name, survivor := range map[string]*LoginResult{"kept address": kept, "primary email": owner} {
		if at := f.sessionRevokedAt(t, survivor.AccessToken); at != 0 {
			t.Fatalf("the %s session was revoked at %d", name, at)
		}
		if _, _, _, err := f.svc.RefreshToken(f.ctx, survivor.RefreshToken, "", "", ""); err != nil {
			t.Fatalf("the %s session no longer refreshes: %v", name, err)
		}
	}
	revoked := w.detailsOf(string(audit.EventSessionRevoked))
	if len(revoked) != 1 || revoked[0]["scope"] != "recovery_email" || revoked[0]["revoked_count"] != float64(1) {
		t.Fatalf("session_revoked audit = %v, want one for the stolen address's one live session", revoked)
	}
}

// A step that continues a recovery sign-in carries its address: the
// date-of-birth step's session is the recovery session it interrupted, and
// once the owner has removed the address the step opens none.
func TestRecoveryEmailSignIn_DOBStepContinuesTheRecoverySessionWhileItsAddressIsHeld(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	f.svc.cfg.RevocationMode = config.RevocationModeSession
	f.svc.cfg.AgeGateEnabled, f.svc.cfg.AgeGateRequireDOB = true, true
	f.svc.cfg.AgeGateChildMaxAge, f.svc.cfg.AgeGateAdultAge = 12, 18
	gate, err := agegate.NewThreshold(12, 18)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.ageGate = gate
	adult := f.now.AddDate(-30, 0, 0).UnixMilli()

	ticketFor := func(owner, addr string) (*User, string) {
		t.Helper()
		user := seedUser(f.repo, owner, "", StatusActive)
		f.add(t, user, addr)
		var dob *DOBRequiredError
		if _, err := f.signInWith(f.ctx, t, addr); !errors.As(err, &dob) {
			t.Fatalf("recovery sign-in to a dob-less account: want a DOBRequiredError, got %v", err)
		}
		return user, dob.Ticket
	}

	held, ticket := ticketFor("held@example.com", "spare@example.net")
	done, err := f.svc.SubmitDateOfBirth(f.ctx, ticket, adult, "", "")
	if err != nil || done.AccessToken == "" {
		t.Fatalf("SubmitDateOfBirth = %+v %v, want the recovery session", done, err)
	}
	if amr := f.sessionAMR(t, done.AccessToken); !slices.Equal(amr, []string{AMRRecoveryEmail}) {
		t.Fatalf("the session the step completed has amr %v, want [%s]", amr, AMRRecoveryEmail)
	}
	if rec, _ := f.repo.FindRefreshTokenByHash(f.ctx, hashRefreshToken(done.RefreshToken)); rec == nil || rec.RecoveryEmailID != f.recoveryEmailID(t, held.ID, "spare@example.net") {
		t.Fatalf("the step's refresh token = %#v, want it tied to the recovery email", rec)
	}
	if _, err := f.svc.RemoveRecoveryEmail(f.ctx, held.ID, f.signedInNow(), "spare@example.net"); err != nil {
		t.Fatalf("RemoveRecoveryEmail: %v", err)
	}
	if _, _, _, err := f.svc.RefreshToken(f.ctx, done.RefreshToken, "", "", ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("refresh of the step's session after the removal: want ErrUnauthenticated, got %v", err)
	}

	removed, ticket := ticketFor("removed@example.com", "lost@example.net")
	if _, err := f.svc.RemoveRecoveryEmail(f.ctx, removed.ID, f.signedInNow(), "lost@example.net"); err != nil {
		t.Fatalf("RemoveRecoveryEmail: %v", err)
	}
	if done, err := f.svc.SubmitDateOfBirth(f.ctx, ticket, adult, "", ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("SubmitDateOfBirth after the address was removed = %+v %v, want ErrUnauthenticated", done, err)
	}
	f.repo.mu.Lock()
	defer f.repo.mu.Unlock()
	for _, rt := range f.repo.refreshTokens {
		if rt.UserID == removed.ID {
			t.Fatalf("the refused step stored a refresh token: %#v", rt)
		}
	}
	for _, session := range f.repo.sessions {
		if session.UserID == removed.ID && session.RevokedAtMs == 0 {
			t.Fatalf("the refused step left its access session live: %#v", session)
		}
	}
}

func TestRecoveryEmailSignIn_RepeatedSignInsCannotLockTheOwnerOut(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "spare@example.net")

	if _, err := f.signInWith(f.ctx, t, "spare@example.net"); err != nil {
		t.Fatalf("first sign-in: %v", err)
	}
	started := f.now.UnixMilli()
	wantUntil := f.now.Add(7 * 24 * time.Hour).UnixMilli()
	// Whoever holds the mailbox signs in again and again within the hold:
	// it does not move, and the list still says when each sign-in was.
	for day := 1; day <= 6; day++ {
		f.now = f.now.Add(24 * time.Hour)
		if _, err := f.signInWith(f.ctx, t, "spare@example.net"); err != nil {
			t.Fatalf("sign-in on day %d: %v", day, err)
		}
		if until := f.holdUntil(t, user.ID); until != wantUntil {
			t.Fatalf("hold after a sign-in on day %d = %d, want it still to end at %d", day, until, wantUntil)
		}
		listed, _, err := f.svc.ListRecoveryEmails(f.ctx, user.ID)
		if err != nil || len(listed) != 1 || listed[0].LastSignInAt != f.now.UnixMilli() || listed[0].HoldStartedAt != started {
			t.Fatalf("listed after a sign-in on day %d = %+v %v, want the sign-in last and the hold's start unmoved", day, listed, err)
		}
	}
	// And the owner, signed in another way, adds and removes as they please
	// throughout.
	f.add(t, user, "fresh@example.net")
	for _, addr := range []string{"fresh@example.net", "spare@example.net"} {
		if _, err := f.svc.RemoveRecoveryEmail(f.ctx, user.ID, f.signedInNow(), addr); err != nil {
			t.Fatalf("the owner removes %s during the hold: %v", addr, err)
		}
	}
	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("hold once every address is gone = %d, want 0", until)
	}
}

// recoverySecondFactorFixture is a recovery sign-in fixture in the project
// login governance governs, for an account on the governed domain.
func newRecoverySecondFactorFixture(t *testing.T, gov *LoginGovernance) (*recoveryEmailFixture, *User) {
	t.Helper()
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	scope := *ProjectScopeFromContext(f.ctx)
	scope.ProjectID = "proj-1"
	f.ctx = WithProjectScope(context.Background(), &scope)
	if gov != nil {
		f.svc.WithLoginGovernance(gov)
	}
	user := seedUser(f.repo, "owner@acme.com", "", StatusActive)
	f.add(t, user, "spare@example.net")
	return f, user
}

func TestRecoveryEmailSignIn_SecondFactorComesBeforeTheHold(t *testing.T) {
	f, user := newRecoverySecondFactorFixture(t, nil)
	seedVerifiedTotp(t, f.repo, user.ID)
	f.repo.mu.Lock()
	f.repo.users[user.ID].TotpRequired = true
	f.repo.mu.Unlock()
	const notice = "Your account was signed in to with a recovery email"

	// The code alone gets a challenge: no tokens, no hold, no notice.
	result, err := f.signInWith(f.ctx, t, "spare@example.net")
	if err != nil || !result.TotpRequired || result.LoginChallengeID == "" || result.AccessToken != "" {
		t.Fatalf("code sign-in to a two-step account = %+v %v, want a second-factor challenge", result, err)
	}
	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("a code alone started a hold until %d", until)
	}
	signInNotices := func() int {
		n := 0
		for _, m := range f.mailedTo("owner@acme.com") {
			if m.Subject == notice {
				n++
			}
		}
		return n
	}
	if signInNotices() != 0 {
		t.Fatal("a code alone sent the sign-in notice")
	}
	// A wrong second factor starts nothing either.
	if _, err := f.svc.VerifyTotp(f.ctx, result.LoginChallengeID, "000000", "", ""); err == nil {
		t.Fatal("VerifyTotp with a wrong code: want an error")
	}
	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("a sign-in that failed its second factor started a hold until %d", until)
	}

	f.now = f.now.Add(2 * time.Minute)
	result, err = f.signInWith(f.ctx, t, "spare@example.net")
	if err != nil || result.LoginChallengeID == "" {
		t.Fatalf("second sign-in = %+v %v", result, err)
	}
	code, err := totpGenerateCode("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	done, err := f.svc.VerifyTotp(f.ctx, result.LoginChallengeID, code, "", "")
	if err != nil || done.AccessToken == "" || done.User.ID != user.ID {
		t.Fatalf("VerifyTotp = %+v %v, want the holding account's session", done, err)
	}
	if amr := f.sessionAMR(t, done.AccessToken); !slices.Equal(amr, []string{AMRRecoveryEmail}) {
		t.Fatalf("the session the factor completed has amr %v, want [%s]", amr, AMRRecoveryEmail)
	}
	if until := f.holdUntil(t, user.ID); until != f.now.Add(7*24*time.Hour).UnixMilli() {
		t.Fatalf("hold once the factor passed = %d", until)
	}
	if n := signInNotices(); n != 1 {
		t.Fatalf("%d sign-in notices once the factor passed, want one", n)
	}
}

// An address the owner removes while its sign-in waits on the second factor
// opens nothing when the factor is proved: no session, no hold, no notice.
func TestRecoveryEmailSignIn_AddressRemovedWhileTheSecondFactorIsPending(t *testing.T) {
	f, user := newRecoverySecondFactorFixture(t, nil)
	seedVerifiedTotp(t, f.repo, user.ID)
	f.repo.mu.Lock()
	f.repo.users[user.ID].TotpRequired = true
	f.repo.mu.Unlock()
	result, err := f.signInWith(f.ctx, t, "spare@example.net")
	if err != nil || result.LoginChallengeID == "" {
		t.Fatalf("code sign-in to a two-step account = %+v %v, want a second-factor challenge", result, err)
	}
	if _, err := f.svc.RemoveRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net"); err != nil {
		t.Fatalf("the owner removes the address: %v", err)
	}
	sent := f.mailer.count()

	code, err := totpGenerateCode("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if done, err := f.svc.VerifyTotp(f.ctx, result.LoginChallengeID, code, "", ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("VerifyTotp after the address was removed = %+v %v, want ErrUnauthenticated", done, err)
	}
	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("hold after the refused sign-in = %d, want 0", until)
	}
	if n := f.mailer.count() - sent; n != 0 {
		t.Fatalf("%d messages after the refused sign-in, want none", n)
	}
	f.repo.mu.Lock()
	defer f.repo.mu.Unlock()
	for _, rt := range f.repo.refreshTokens {
		if rt.UserID == user.ID {
			t.Fatalf("the refused sign-in stored a refresh token: %#v", rt)
		}
	}
}

func TestRecoveryEmailSignIn_TenantRequire2FAAsksForTheFactor(t *testing.T) {
	f, user := newRecoverySecondFactorFixture(t, withRequire2FA())
	seedVerifiedTotp(t, f.repo, user.ID)

	result, err := f.signInWith(f.ctx, t, "spare@example.net")
	if err != nil || !result.TotpRequired || result.LoginChallengeID == "" || result.AccessToken != "" {
		t.Fatalf("recovery sign-in under a tenant's Require2FA = %+v %v, want a challenge", result, err)
	}
	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("a challenge started a hold until %d", until)
	}
}

func TestRecoveryEmailSignIn_PolicyThatRefusesEmailCodesRefusesIt(t *testing.T) {
	f, user := newRecoverySecondFactorFixture(t, withAllowedMethods(LoginMethodPassword))
	sent := f.mailer.count()

	if _, err := f.signInWith(f.ctx, t, "spare@example.net"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("recovery sign-in under a password-only policy: want ErrPermissionDenied, got %v", err)
	}
	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("a refused sign-in started a hold until %d", until)
	}
	if f.mailer.count() != sent+1 {
		t.Fatalf("%d messages, want only the code", f.mailer.count()-sent)
	}
}

func TestRecoveryEmailSignIn_MagicLinkSignsInToTheHoldingAccount(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	f.svc.returnAllow = mustReturnAllowlist(t, "https://app.test/")
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "spare@example.net")
	users := f.userCount()

	if err := f.svc.RequestMagicLink(f.ctx, "Spare@example.net", "https://app.test/finish"); err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	links := f.mailedTo("spare@example.net")
	result, err := f.svc.RedeemMagicLink(f.ctx, extractTokenFromLink(t, links[len(links)-1].Text), "203.0.113.7", "test-agent")
	if err != nil || result.User.ID != user.ID || result.AccessToken == "" {
		t.Fatalf("RedeemMagicLink = %+v %v, want the holding account", result, err)
	}
	if f.userCount() != users {
		t.Fatal("the link made a new account")
	}
	if amr := f.sessionAMR(t, result.AccessToken); !slices.Equal(amr, []string{AMRRecoveryEmail}) {
		t.Fatalf("the link's session has amr %v", amr)
	}
	if until := f.holdUntil(t, user.ID); until == 0 {
		t.Fatal("the link's sign-in started no hold")
	}
}

func TestRecoveryEmailSignIn_OffMeansTheAddressSignsInToNothing(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "spare@example.net")
	scope := *ProjectScopeFromContext(f.ctx)
	scope.RecoveryEmails.SignIn = false
	off := WithProjectScope(context.Background(), &scope)
	users := f.userCount()

	if _, err := f.signInWith(off, t, "spare@example.net"); !errors.Is(err, ErrEmailLoginCodeInvalid) {
		t.Fatalf("code sign-in with sign_in off: want ErrEmailLoginCodeInvalid, got %v", err)
	}
	if _, err := f.svc.completePasswordlessLogin(off, canonicalize("spare@example.net"), "magic_link", "", ""); !errors.Is(err, ErrMagicLinkInvalid) {
		t.Fatalf("link sign-in with sign_in off: want ErrMagicLinkInvalid, got %v", err)
	}
	if f.userCount() != users {
		t.Fatalf("a refused sign-in made an account: %d users, want %d", f.userCount(), users)
	}
	if _, until, _ := f.svc.ListRecoveryEmails(off, user.ID); until != 0 {
		t.Fatalf("a refused sign-in started a hold until %d", until)
	}
}

func TestRecoveryEmailSignIn_AccessGoesByTheAccountNotTheRecoveryAddress(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeAllowlist, AllowedEmails: []string{"owner@example.com"}})
	owner := seedUser(f.repo, "owner@example.com", "", StatusActive)
	outsider := seedUser(f.repo, "outsider@example.com", "", StatusActive)
	f.add(t, owner, "spare@example.net")
	f.add(t, outsider, "outsider-spare@example.net")

	// The recovery email is on no allowlist, and still receives the code and
	// signs in: the account's primary email is what the project admitted.
	result, err := f.signInWith(f.ctx, t, "spare@example.net")
	if err != nil || result.User.ID != owner.ID {
		t.Fatalf("sign-in for an admitted account = %v %v", result, err)
	}
	// An account the project no longer admits gets no way round that.
	if _, err := f.signInWith(f.ctx, t, "outsider-spare@example.net"); !errors.Is(err, ErrAccessNotAllowed) {
		t.Fatalf("sign-in for an account off the allowlist: want ErrAccessNotAllowed, got %v", err)
	}
	if _, until, _ := f.svc.ListRecoveryEmails(f.ctx, outsider.ID); until != 0 {
		t.Fatal("a refused sign-in started a hold")
	}

	// An address nobody holds is still not mailed by an allowlist project.
	sent := f.mailer.count()
	if err := f.svc.RequestEmailLoginCode(f.ctx, "stranger@example.net"); err != nil {
		t.Fatalf("RequestEmailLoginCode: %v", err)
	}
	if f.mailer.count() != sent {
		t.Fatal("a code was mailed to an address no account holds")
	}

	// A closed project mails no recovery email either.
	scope := *ProjectScopeFromContext(f.ctx)
	scope.Access = ProjectAccessConfig{Mode: AccessModeClosed}
	f.now = f.now.Add(2 * time.Minute)
	if err := f.svc.RequestEmailLoginCode(WithProjectScope(context.Background(), &scope), "spare@example.net"); err != nil {
		t.Fatalf("RequestEmailLoginCode (closed): %v", err)
	}
	if f.mailer.count() != sent {
		t.Fatal("a closed project mailed a sign-in code to a recovery email")
	}
}

func TestRecoveryEmailSignIn_RefusesAnAccountThatMayNotSignIn(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "spare@example.net")
	f.repo.mu.Lock()
	f.repo.users[user.ID].Status = StatusDeactivated
	f.repo.mu.Unlock()

	if _, err := f.signInWith(f.ctx, t, "spare@example.net"); !errors.Is(err, ErrAccountNotActive) {
		t.Fatalf("sign-in to a deactivated account: want ErrAccountNotActive, got %v", err)
	}
	if _, until, _ := f.svc.ListRecoveryEmails(f.ctx, user.ID); until != 0 {
		t.Fatal("a refused sign-in started a hold")
	}
}

func TestProjectRecoveryEmailsConfig_Hold(t *testing.T) {
	if got := (ProjectRecoveryEmailsConfig{}).hold(); got != 7*24*time.Hour {
		t.Fatalf("default hold = %s, want 168h", got)
	}
	if got := (ProjectRecoveryEmailsConfig{HoldSeconds: 3600}).hold(); got != time.Hour {
		t.Fatalf("configured hold = %s, want 1h", got)
	}
	for _, bad := range []int{-1, 30*24*60*60 + 1} {
		cfg := ProjectConfig{RecoveryEmails: ProjectRecoveryEmailsConfig{HoldSeconds: bad}}
		if err := cfg.Validate(); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("Validate(hold_seconds=%d): want ErrInvalidArgument, got %v", bad, err)
		}
	}
	// The hold follows the configured length, not the one in force when the
	// address signed in, and is measured from the latest hold's start, not
	// the latest sign-in.
	held := []*RecoveryEmail{{HoldStartedAt: 1_000, LastSignInAt: 9_000}, {HoldStartedAt: 5_000, LastSignInAt: 5_000}}
	if got := recoveryHoldUntil(held, 10*time.Second, 14_999); got != 15_000 {
		t.Fatalf("hold end = %d, want 15000", got)
	}
	if got := recoveryHoldUntil(held, 10*time.Second, 15_000); got != 0 {
		t.Fatalf("hold end at its own end = %d, want 0", got)
	}
}

// A project admin's recovery session adds no account, sets no role and sets
// no other account's password from the admin seat while the hold is in force,
// nor once its address is gone, and one that cannot name its address makes
// none where recovery emails sign in: each would outlast the hold. The admin
// signed in another way makes them as before.
func TestRecoveryHold_HoldsTheAdminSeatsGrants(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@example.test", "Admin", RoleAdmin, StatusActive)
	db.addUser("member-1", "member@example.test", "Member", "member", StatusActive)
	repo := newFakeRepo()
	repo.users["admin-1"] = &User{ID: "admin-1", Email: "admin@example.test", Role: RoleAdmin, Status: StatusActive}
	svc := newTestAdminServiceWithRepo(db, repo)
	ctx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "project-a", Access: ProjectAccessConfig{Mode: AccessModeOpen},
		RecoveryEmails: ProjectRecoveryEmailsConfig{Enabled: true, SignIn: true},
	})
	holdAccount(ctx, t, repo, "admin-1", "admin-spare@example.net", nowMs())
	held, err := repo.FindRecoveryEmailHolder(ctx, "admin-spare@example.net")
	if err != nil || held == nil {
		t.Fatalf("FindRecoveryEmailHolder = %+v %v", held, err)
	}
	grants := func(session SessionSignIn) map[string]func() error {
		return map[string]func() error{
			"InviteUser": func() error {
				_, err := svc.InviteUser(ctx, "admin-1", session, "new@example.test", "New", RoleAdmin, "", 0, true)
				return err
			},
			"CreateUsernameUser": func() error {
				_, err := svc.CreateUsernameUser(ctx, "admin-1", session, "newcomer", "New", RoleAdmin)
				return err
			},
			"UpdateUser": func() error {
				_, err := svc.UpdateUser(ctx, "admin-1", session, "member-1", "Member", RoleAdmin, "")
				return err
			},
			"ResetUserPassword": func() error {
				_, err := svc.ResetUserPassword(ctx, "admin-1", session, "member-1", true)
				return err
			},
		}
	}
	signedIn := time.Now().Unix()

	for name, grant := range grants(SessionSignIn{AuthTimeSec: signedIn, AMR: []string{AMRRecoveryEmail}, RecoveryEmailID: held.ID}) {
		if err := grant(); !errors.Is(err, ErrRecoveryHold) {
			t.Fatalf("%s by the admin's recovery session during the hold = %v, want ErrRecoveryHold", name, err)
		}
	}
	for name, grant := range grants(SessionSignIn{AuthTimeSec: signedIn, AMR: []string{AMRUnvouched}}) {
		if err := grant(); !errors.Is(err, ErrRecoverySession) {
			t.Fatalf("%s by a session that cannot name its address = %v, want ErrRecoverySession", name, err)
		}
	}
	if _, err := repo.RemoveRecoveryEmail(ctx, "admin-1", "admin-spare@example.net", nowMs()); err != nil {
		t.Fatalf("RemoveRecoveryEmail: %v", err)
	}
	for name, grant := range grants(SessionSignIn{AuthTimeSec: signedIn, AMR: []string{AMRRecoveryEmail}, RecoveryEmailID: held.ID}) {
		if err := grant(); !errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrRecoveryHold) {
			t.Fatalf("%s by the removed address's session = %v, want ErrUnauthenticated", name, err)
		}
	}
	if _, err := svc.ResetUserPassword(ctx, "admin-1", SessionSignIn{AuthTimeSec: signedIn}, "member-1", true); err != nil {
		t.Fatalf("the admin's own session resets another account's password: %v", err)
	}
}
