package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// liveSession gives userID a live session in repo and returns the sign-in
// that names it.
func liveSession(t *testing.T, repo *fakeRepo, userID string) SessionSignIn {
	t.Helper()
	sid := "sid-" + userID
	_, err := repo.CreateSession(context.Background(), &SessionRecord{SID: sid, UserID: userID, CreatedAtMs: time.Now().UnixMilli()})
	require.NoError(t, err)
	return SessionSignIn{SessionID: sid, AuthTimeSec: time.Now().Unix()}
}

func TestFenceManagedSession(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	managed := seedManaged(repo, "ann@acme.example.com", StatusActive)
	other := seedPerson(repo, "bo@example.com")
	live := liveSession(t, repo, managed.ID)
	others := liveSession(t, repo, other.ID)
	ended := liveSession(t, repo, "someone")
	ended.SessionID = "sid-ended"
	_, err := repo.CreateSession(ctx, &SessionRecord{SID: "sid-ended", UserID: managed.ID, RevokedAtMs: 1})
	require.NoError(t, err)

	fence := func(u *User, signIn SessionSignIn, r Repository) error {
		return fenceManagedSession(ctx, r, zap.NewNop(), u, signIn, "test")
	}
	require.NoError(t, fence(other, SessionSignIn{}, nil), "a personal account is never read for")
	require.NoError(t, fence(nil, SessionSignIn{}, nil))
	require.NoError(t, fence(managed, live, repo))

	require.ErrorIs(t, fence(managed, SessionSignIn{}, repo), ErrUnauthenticated, "no session behind the token")
	require.ErrorIs(t, fence(managed, ended, repo), ErrUnauthenticated, "a revoked session")
	require.ErrorIs(t, fence(managed, SessionSignIn{SessionID: "sid-missing"}, repo), ErrUnauthenticated, "an unknown session")
	require.ErrorIs(t, fence(managed, others, repo), ErrUnauthenticated, "another account's session")
	require.ErrorIs(t, fence(managed, live, nil), ErrServiceUnavailable, "no session store to read")
	invited := *managed
	invited.Status = StatusInvited
	require.ErrorIs(t, fence(&invited, live, repo), ErrAccountNotActive)
	require.Error(t, fence(managed, live, sessionReadFails{repo}))
}

// sessionReadFails is a repository whose session reads fail.
type sessionReadFails struct{ *fakeRepo }

func (sessionReadFails) GetSessionBySid(context.Context, string) (*SessionRecord, error) {
	return nil, errors.New("db down")
}

// Every credential a managed account could attach, and its own agent, is
// refused from a session that has ended, and works from a live one.
func TestManagedSessionFence_CredentialRPCs(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.AgentsEnabled = true
	phone := newTestPhoneService(t, repo, &fakeSMSSender{})
	managed := seedManaged(repo, "ann@acme.example.com", StatusActive)
	stale := SessionSignIn{SessionID: "sid-gone", AuthTimeSec: time.Now().Unix()}

	for name, call := range map[string]func(SessionSignIn) error{
		"BeginPasskeyRegistration": func(s SessionSignIn) error {
			_, _, err := svc.BeginPasskeyRegistration(ctx, managed.ID, s, "laptop", false)
			return err
		},
		"CompletePasskeyRegistration": func(s SessionSignIn) error {
			_, _, err := svc.CompletePasskeyRegistration(ctx, managed.ID, s, "challenge", "{}", "laptop", false, "", "")
			return err
		},
		"BeginTotpSetup": func(s SessionSignIn) error {
			_, _, _, err := svc.BeginTotpSetup(ctx, managed.ID, s)
			return err
		},
		"VerifyTotpSetup": func(s SessionSignIn) error {
			_, err := svc.VerifyTotpSetup(ctx, managed.ID, s, "123456")
			return err
		},
		"RequestPhoneVerification": func(s SessionSignIn) error {
			return phone.RequestPhoneVerification(ctx, managed.ID, s, "+14155550123")
		},
		"VerifyPhoneCode": func(s SessionSignIn) error {
			_, err := phone.VerifyPhoneCode(ctx, managed.ID, s, "+14155550123", "123456")
			return err
		},
		"LinkIdentity": func(s SessionSignIn) error {
			_, err := svc.LinkIdentity(ctx, managed.ID, s, "code", "google", "https://app.example.com/cb", "", "state", "")
			return err
		},
		"CreateAgent": func(s SessionSignIn) error {
			_, err := svc.CreateAgent(ctx, managed.ID, s, "Helper", "", "", "", "", "")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := call(stale)
			require.ErrorIs(t, err, ErrUnauthenticated, "an ended session attaches nothing")
		})
	}
}

// A managed account owns agents while it stands in its tenant: it creates
// one from a live session with an active membership, and neither it nor an
// admin creates one once the membership is not active; an agent whose owner
// fell out of standing holds no session.
func TestCreateAgent_ManagedOwnerNeedsItsStanding(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	managed := seedManaged(f.repo, "ann@acme.example.com", StatusActive)
	memberships := &managedMembershipsMock{get: membershipIn(MembershipStatusActive)}
	f.svc.WithManagedMemberships(memberships, tenantIn(TenantStatusClaimed))
	live := liveSession(t, f.repo, managed.ID)

	agent, err := f.svc.CreateAgent(ctx, managed.ID, live, "Helper", "", "", "", "", "managed-key")
	require.NoError(t, err)
	assert.Equal(t, managed.ID, agent.OwnerUserID)
	stored, err := f.repo.GetUser(ctx, agent.ID)
	require.NoError(t, err)
	require.NoError(t, f.svc.checkAgentStanding(ctx, stored))

	memberships.get = membershipIn(MembershipStatusSuspended)
	_, err = f.svc.CreateAgent(ctx, managed.ID, live, "Other", "", "", "", "", "managed-key-2")
	require.ErrorIs(t, err, ErrAccountNotActive)
	_, err = f.svc.CreateAgent(ctx, f.admin.ID, SessionSignIn{}, "Other", "", managed.ID, "", "", "admin-key")
	require.ErrorIs(t, err, errAgentOwnerNotEligible, "an admin gives no agent to a managed account out of standing")
	require.ErrorIs(t, f.svc.checkAgentStanding(ctx, stored), ErrAccountNotActive)

	f.svc.WithManagedMemberships(nil, nil)
	require.ErrorIs(t, f.svc.checkAgentStanding(ctx, stored), ErrAccountNotActive, "no reader refuses")
}

// ChangePassword by a managed account needs a live session of its own.
func TestManagedSessionFence_ChangePassword(t *testing.T) {
	ctx := context.Background()
	db := newErrorDB()
	db.addUserWithPassword("user-1", "ann@acme.example.com", "Ann", "member", StatusActive, hashPW(t, issuedPW))
	db.nodes["user-1"].Payload[ufManagedByTenantID] = mTestTenant
	repo := newFakeRepo()
	svc := NewProfileService(repo, db, "test-tenant", audit.NewLogger(nil, "test-tenant", zap.NewNop()), zap.NewNop())

	err := svc.ChangePassword(ctx, "user-1", SessionSignIn{SessionID: "sid-gone"}, issuedPW, strongPW)
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.NoError(t, svc.ChangePassword(ctx, "user-1", liveSession(t, repo, "user-1"), issuedPW, strongPW))
}

// A managed owner or admin administers its tenant only from a live session
// of its own while its account is active; a personal one is never read for.
func TestTenantAdminFence(t *testing.T) {
	f := newManagedFixture(t)
	_, err := f.members.UpsertMembership(context.Background(), &TenantMembership{
		ProjectID: ssProject, TenantID: ownTenant, UserID: managedMemberID,
		Source: MembershipSourceInvited, Role: RoleAdmin, Status: MembershipStatusActive,
	})
	require.NoError(t, err)
	sessions := newFakeRepo()
	ctx := managedProject(true, false)

	_, err = f.svc.ListTenantMembers(ctx, ssOwnerID, SessionSignIn{}, ownTenant)
	require.NoError(t, err, "a personal owner needs no session store")

	_, err = f.svc.ListTenantMembers(ctx, managedMemberID, SessionSignIn{SessionID: "sid-x"}, ownTenant)
	require.ErrorIs(t, err, ErrServiceUnavailable, "without a session store a managed admin is refused")

	f.svc.WithAccounts(sessions)
	live := liveSession(t, sessions, managedMemberID)
	_, err = f.svc.ListTenantMembers(ctx, managedMemberID, live, ownTenant)
	require.NoError(t, err)
	_, err = f.svc.ListTenantInvitations(ctx, managedMemberID, SessionSignIn{SessionID: "sid-gone"}, ownTenant)
	require.ErrorIs(t, err, ErrUnauthenticated)

	f.users.set(ssProject, &User{ID: managedMemberID, Email: managedAddress, Status: StatusInvited, ManagedByTenantID: ownTenant})
	_, err = f.svc.ListTenantMembers(ctx, managedMemberID, live, ownTenant)
	require.ErrorIs(t, err, ErrAccountNotActive, "a reset admin's live token administers nothing")
}

func TestDomainTenantAdminFence(t *testing.T) {
	ctx := withProject(testProject)
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.svc.WithAccounts(nil)
	_, err := f.svc.ListTenantDomains(ctx, testCaller, SessionSignIn{}, testTenant)
	require.ErrorIs(t, err, ErrServiceUnavailable, "with no account store nobody is read, so nobody administers")
}

// tokenLifetime is how long the access token accessToken was issued for:
// its exp less its iat, read without verifying it.
func tokenLifetime(t *testing.T, accessToken string) time.Duration {
	t.Helper()
	parts := strings.Split(accessToken, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		Exp int64 `json:"exp"`
		Iat int64 `json:"iat"`
	}
	require.NoError(t, json.Unmarshal(raw, &claims))
	return time.Duration(claims.Exp-claims.Iat) * time.Second
}

// An access token issued to a managed account lasts
// GATEWAY_MANAGED_ACCESS_TOKEN_EXPIRY_SECONDS, a minute by default, and a
// sign-in says so; a personal account's lasts GATEWAY_JWT_EXPIRY_SECONDS as
// before.
func TestAccessTokenExpiry_ManagedAccountsGetAMinute(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo).WithManagedMemberships(&managedMembershipsMock{get: membershipIn(MembershipStatusActive)}, tenantIn(TenantStatusClaimed))
	svc.cfg.JWTExpirySeconds = 900
	managed := seedManaged(repo, "ann@acme.example.com", StatusActive)
	personal := seedPerson(repo, "bo@example.com")
	ctx := context.Background()

	access, _, err := svc.issueTokensWithSessionStart(ctx, managed, "", "", sessionGateRefresh, 0, 0, 0, "", "", credentialEnrollment{})
	require.NoError(t, err)
	assert.Equal(t, time.Minute, tokenLifetime(t, access))
	assert.Equal(t, int32(60), svc.accessTokenExpiresIn(managed))

	access, _, err = svc.issueTokensWithSessionStart(ctx, personal, "", "", sessionGateRefresh, 0, 0, 0, "", "", credentialEnrollment{})
	require.NoError(t, err)
	assert.Equal(t, 15*time.Minute, tokenLifetime(t, access), "a personal account is unchanged")
	assert.Equal(t, int32(900), svc.accessTokenExpiresIn(personal))

	svc.cfg.ManagedAccessTokenExpirySeconds = 30
	access, _, err = svc.issueTokensWithSessionStart(ctx, managed, "", "", sessionGateRefresh, 0, 0, 0, "", "", credentialEnrollment{})
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, tokenLifetime(t, access))
}

// Every way an agent comes to a managed owner, or acts for one, holds the
// owner to its standing in its tenant: while its membership is suspended
// it creates no agent, is given none (by an admin, a transfer, an offer's
// acceptance or an orphan's reassignment), and its agents hold no session
// and pass no OAuth or machine admission; reinstated, each works again, and
// an agent its suspension deactivated works once the owner reactivates it.
func TestManagedAgentOwner_EveryPathFollowsItsStanding(t *testing.T) {
	ctx := context.Background()
	f := newAgentFixture(t)
	managed := seedManaged(f.repo, "ann@acme.example.com", StatusActive)
	memberships := &managedMembershipsMock{get: membershipIn(MembershipStatusActive)}
	f.svc.WithManagedMemberships(memberships, tenantIn(TenantStatusClaimed))
	live := liveSession(t, f.repo, managed.ID)
	oauth := &AgentOAuthService{auth: f.svc}
	suspend := func(suspended bool) {
		memberships.get = membershipIn(MembershipStatusActive)
		if suspended {
			memberships.get = membershipIn(MembershipStatusSuspended)
		}
	}

	owned, err := f.svc.CreateAgent(ctx, managed.ID, live, "Owned", "", "", "", "", "owned")
	require.NoError(t, err)
	offered := seedAgent(f.repo, f.owner.ID)
	_, err = f.svc.TransferAgent(ctx, f.owner.ID, SessionSignIn{}, offered.ID, managed.ID, "", "")
	require.NoError(t, err, "an offer to an owner in standing")
	orphan := seedAgent(f.repo, "owner-gone")
	given := seedAgent(f.repo, f.owner.ID)
	agentOf := func(id string) *User {
		u, err := f.repo.GetUser(ctx, id)
		require.NoError(t, err)
		return u
	}

	suspend(true)
	_, err = f.svc.CreateAgent(ctx, managed.ID, live, "Mine", "", "", "", "", "mine-1")
	require.ErrorIs(t, err, ErrAccountNotActive, "creating its own agent")
	_, err = f.svc.CreateAgent(ctx, f.admin.ID, SessionSignIn{}, "Given", "", managed.ID, "", "", "admin-1")
	require.ErrorIs(t, err, errAgentOwnerNotEligible, "an admin creating one for it")
	_, err = f.svc.TransferAgent(ctx, f.owner.ID, SessionSignIn{}, given.ID, managed.ID, "", "")
	require.ErrorIs(t, err, errAgentOwnerNotEligible, "a transfer to it")
	_, err = f.svc.AcceptAgentTransfer(ctx, managed.ID, offered.ID, "", "")
	require.ErrorIs(t, err, errAgentOwnerNotEligible, "its acceptance of an offer")
	_, err = f.svc.TransferAgent(ctx, f.admin.ID, SessionSignIn{}, orphan.ID, managed.ID, "", "")
	require.ErrorIs(t, err, errAgentOwnerNotEligible, "an orphan's reassignment to it")
	require.ErrorIs(t, f.svc.checkAgentStanding(ctx, agentOf(owned.ID)), ErrAccountNotActive, "its agent's session")
	require.ErrorIs(t, oauth.ownerStanding(ctx, managed), ErrAccountNotActive, "OAuth and machine admission")

	suspend(false)
	f.repo.mu.Lock()
	f.repo.users[owned.ID].Status = StatusDeactivated
	f.repo.mu.Unlock()
	require.ErrorIs(t, f.svc.checkAgentStanding(ctx, agentOf(owned.ID)), ErrAccountNotActive, "deactivated by the suspension")
	require.NoError(t, f.svc.ReactivateAgent(ctx, managed.ID, owned.ID, "", ""))
	require.NoError(t, f.svc.checkAgentStanding(ctx, agentOf(owned.ID)), "reactivated by its reinstated owner")
	_, err = f.svc.CreateAgent(ctx, managed.ID, live, "Mine", "", "", "", "", "mine-2")
	require.NoError(t, err)
	_, err = f.svc.CreateAgent(ctx, f.admin.ID, SessionSignIn{}, "Given", "", managed.ID, "", "", "admin-2")
	require.NoError(t, err)
	_, err = f.svc.TransferAgent(ctx, f.owner.ID, SessionSignIn{}, given.ID, managed.ID, "", "")
	require.NoError(t, err)
	_, err = f.svc.AcceptAgentTransfer(ctx, managed.ID, offered.ID, "", "")
	require.NoError(t, err)
	_, err = f.svc.TransferAgent(ctx, f.admin.ID, SessionSignIn{}, orphan.ID, managed.ID, "", "")
	require.NoError(t, err)
	require.NoError(t, oauth.ownerStanding(ctx, managed))
}

// Every token an agent of a managed owner gets lasts the managed lifetime
// too: its session tokens here, and its delegated and machine tokens
// through managedTokenCapMs. An agent of a personal owner keeps the usual
// lifetime, and one whose owner cannot be read gets the short one.
func TestAccessTokenExpiry_AgentsOfManagedOwnersGetAMinute(t *testing.T) {
	f := newAgentFixture(t)
	f.svc.cfg.JWTExpirySeconds = 900
	managed := seedManaged(f.repo, "ann@acme.example.com", StatusActive)
	f.svc.WithManagedMemberships(&managedMembershipsMock{get: membershipIn(MembershipStatusActive)}, tenantIn(TenantStatusClaimed))
	ctx := context.Background()

	managedAgent := seedAgent(f.repo, managed.ID)
	access, _, err := f.svc.issueTokensWithSessionStart(ctx, managedAgent, "", "", sessionGateRefresh, 0, 0, 0, "", "", credentialEnrollment{})
	require.NoError(t, err)
	assert.Equal(t, time.Minute, tokenLifetime(t, access))

	personalAgent := seedAgent(f.repo, f.owner.ID)
	access, _, err = f.svc.issueTokensWithSessionStart(ctx, personalAgent, "", "", sessionGateRefresh, 0, 0, 0, "", "", credentialEnrollment{})
	require.NoError(t, err)
	assert.Equal(t, 15*time.Minute, tokenLifetime(t, access))

	assert.Equal(t, time.Minute, f.svc.accessTokenExpiry(ctx, &User{ID: "x", Kind: UserKindAgent, OwnerUserID: "owner-gone"}), "an unread owner gets the short lifetime")

	now := time.Now().UnixMilli()
	far := now + (10 * time.Minute).Milliseconds()
	assert.Equal(t, now+time.Minute.Milliseconds(), managedTokenCapMs(f.svc.cfg, managed, now, far), "a delegated or machine token of a managed owner")
	assert.Equal(t, far, managedTokenCapMs(f.svc.cfg, f.owner, now, far), "a personal owner's")
	assert.Equal(t, far, managedTokenCapMs(f.svc.cfg, nil, now, far))
	soon := now + (10 * time.Second).Milliseconds()
	assert.Equal(t, soon, managedTokenCapMs(f.svc.cfg, managed, now, soon), "a shorter expiry stands")
}

// The credential calls hold a managed caller to its standing in its tenant
// as well as to a live session: a suspended tenant, or a membership that is
// not active, refuses them.
func TestManagedSessionFence_CredentialCallsNeedTheTenantsStanding(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	managed := seedManaged(repo, "ann@acme.example.com", StatusActive)
	live := liveSession(t, repo, managed.ID)
	tenants := tenantIn(TenantStatusClaimed)
	memberships := &managedMembershipsMock{get: membershipIn(MembershipStatusActive)}
	svc.WithManagedMemberships(memberships, tenants)

	_, _, _, err := svc.BeginTotpSetup(ctx, managed.ID, live)
	require.NoError(t, err)

	tenants.status = func(string, string) (string, error) { return TenantStatusSuspended, nil }
	_, _, _, err = svc.BeginTotpSetup(ctx, managed.ID, live)
	require.ErrorIs(t, err, ErrAccountNotActive, "a suspended tenant")

	tenants.status = func(string, string) (string, error) { return TenantStatusClaimed, nil }
	memberships.get = membershipIn(MembershipStatusSuspended)
	_, _, err = svc.BeginPasskeyRegistration(ctx, managed.ID, live, "laptop", false)
	require.ErrorIs(t, err, ErrAccountNotActive, "a suspended membership")
}
