package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// A managed standing that cannot be read fails closed and is retryable: it
// is ErrUnavailable as well as ErrAccountNotActive, on sign-in, on a
// teammate exchange and in agent OAuth admission, which keeps the grant.
func TestManagedStandingUnread_IsUnavailableEverywhere(t *testing.T) {
	require.ErrorIs(t, errManagedStandingUnread, ErrUnavailable)
	require.ErrorIs(t, errManagedStandingUnread, ErrAccountNotActive)
	require.False(t, isAgentOAuthAdmissionRefusal(errManagedStandingUnread), "an unread standing ends no grant or machine")

	failing := &managedMembershipsMock{get: func(string, string, string) (*TenantMembership, error) { return nil, errors.New("db down") }}
	svc, _, _ := managedSignedIn(t)
	svc.WithManagedMemberships(failing, tenantIn(TenantStatusClaimed))
	_, err := svc.PasswordLogin(managedScope(admitted()), maAddress, signupPassword, "", "")
	require.ErrorIs(t, err, ErrUnavailable, "sign-in")

	repo := newFakeRepo()
	grantor := seedPerson(repo, "admin@acme.example.com")
	repo.mu.Lock()
	grantor.Role, grantor.ManagedByTenantID, grantor.SetUpAtMs = RoleAdmin, mTestTenant, 1
	repo.mu.Unlock()
	lead := seedPerson(repo, "lead@example.com")
	teammate := seedAgent(repo, lead.ID)
	keys := (&TeammateKeyService{base: repo, logger: zap.NewNop()}).WithManagedStanding(failing, tenantIn(TenantStatusClaimed))
	_, err = keys.ownerStandsBehind(context.Background(), mTestProject, &TeammateKey{OwnerUserID: grantor.ID, TeammateID: teammate.ID})
	require.ErrorIs(t, err, ErrUnavailable, "teammate exchange")
}

// A grant or machine whose owner is refused admission for good is revoked at
// that exchange and stays revoked: once the owner is admitted again, they
// authorize the agent anew. A standing that could not be read revokes
// nothing.
func TestAgentMachine_RevokedOnAnOwnerRefusalStaysRevoked(t *testing.T) {
	oauth, base, raw := machineAdmissionFixture(t)
	repo := &revokingMachineRepo{machineAdmissionRepo: base}
	oauth.base = repo
	oauth.auth.cfg.IDVRequired = true

	_, _, _, err := oauth.machineAccess(t.Context(), AgentMachineChallengeRequest{MachineID: base.stale.ID, Operation: AgentMachineRoster}, raw)
	require.ErrorIs(t, err, ErrAgentOAuthGrant)
	require.Equal(t, 1, repo.revoked, "the machine is revoked at the refused exchange")

	base.authority.Owner.IDVVerified = true
	_, _, _, err = oauth.machineAccess(t.Context(), AgentMachineChallengeRequest{MachineID: base.stale.ID, Operation: AgentMachineRoster}, raw)
	require.ErrorIs(t, err, ErrAgentOAuthGrant, "the owner admitted again does not bring the machine back")
	require.Equal(t, 1, repo.revoked)
}

// revokingMachineRepo records a machine's revocation and keeps it revoked.
type revokingMachineRepo struct {
	*machineAdmissionRepo
	revoked int
}

func (r *revokingMachineRepo) WithProject(string) Repository { return r }

func (r *revokingMachineRepo) MutateAgentMachine(_ context.Context, _ string, m AgentMachineMutation) (*AgentMachine, error) {
	if m.Operation == AgentMachineRevoke {
		r.revoked++
		r.authority.Machine.RevokedAtMs = m.AtMs
		r.stale.RevokedAtMs = m.AtMs
	}
	return r.authority.Machine.Clone(), nil
}

// The refusal log names the calling surface, once per refusal.
func TestManagedStanding_RefusalLogNamesTheSurfaceOnce(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	j := managedStanding{memberships: &managedMembershipsMock{get: membershipIn(MembershipStatusSuspended)}, tenants: tenantIn(TenantStatusClaimed), logger: zap.New(core)}
	user := &User{ID: "m", Status: StatusActive, ManagedByTenantID: mTestTenant, SetUpAtMs: 1}
	for _, surface := range []string{"session", "refresh", "agent_owner", "teammate_exchange", "hire_grant"} {
		require.ErrorIs(t, j.refuse(context.Background(), mTestProject, user, surface), ErrAccountNotActive)
	}
	entries := logs.FilterMessage("managed_account_refused").All()
	require.Len(t, entries, 5, "one line per refusal")
	for i, surface := range []string{"session", "refresh", "agent_owner", "teammate_exchange", "hire_grant"} {
		require.Equal(t, surface, entries[i].ContextMap()["surface"])
	}
}

// An admin-granted teammate key needs the teammate's owner to be an active
// person, and, when a tenant manages the owner's account, in standing in it:
// an owner suspended, deactivated or deleted, or out of standing in its
// tenant, stands behind no token.
func TestTeammateOwnerStandsBehind_AdminGrantNeedsAnActivePersonalOwner(t *testing.T) {
	ctx := context.Background()
	for name, mutate := range map[string]func(repo *fakeRepo, owner *User, reader *managedMembershipsMock){
		"owner suspended":   func(_ *fakeRepo, o *User, _ *managedMembershipsMock) { o.Status = "suspended" },
		"owner deactivated": func(_ *fakeRepo, o *User, _ *managedMembershipsMock) { o.Status = StatusDeactivated },
		"owner deleted":     func(r *fakeRepo, o *User, _ *managedMembershipsMock) { delete(r.users, o.ID) },
		"managed owner out of standing": func(_ *fakeRepo, o *User, m *managedMembershipsMock) {
			o.ManagedByTenantID, o.SetUpAtMs = mTestTenant, 1
			m.get = membershipIn(MembershipStatusSuspended)
		},
	} {
		t.Run(name, func(t *testing.T) {
			repo := newFakeRepo()
			admin := seedPerson(repo, "admin@example.com")
			owner := seedPerson(repo, "owner@example.com")
			repo.mu.Lock()
			admin.Role = RoleAdmin
			repo.mu.Unlock()
			teammate := seedAgent(repo, owner.ID)
			reader := &managedMembershipsMock{get: membershipIn(MembershipStatusActive)}
			keys := (&TeammateKeyService{base: repo, logger: zap.NewNop()}).WithManagedStanding(reader, tenantIn(TenantStatusClaimed))
			key := &TeammateKey{OwnerUserID: admin.ID, TeammateID: teammate.ID}
			_, err := keys.ownerStandsBehind(ctx, mTestProject, key)
			require.NoError(t, err, "an active personal owner")
			repo.mu.Lock()
			mutate(repo, owner, reader)
			repo.mu.Unlock()
			_, err = keys.ownerStandsBehind(ctx, mTestProject, key)
			require.ErrorIs(t, err, ErrUnauthenticated)
		})
	}
}
