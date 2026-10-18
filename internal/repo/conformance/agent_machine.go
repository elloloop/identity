package conformance

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

type machineFixture struct {
	base    service.Repository
	repo    service.AgentMachineRepository
	oauth   service.AgentOAuthRepository
	machine *service.AgentMachine
	agent   string
}

func seedAgentMachine(ctx context.Context, t *testing.T, base service.Repository) machineFixture {
	t.Helper()
	owner, err := base.CreateUser(ctx, &service.User{Email: "machine-owner@example.test", Kind: service.UserKindPerson, Status: service.StatusActive})
	require.NoError(t, err)
	agent, err := base.CreateUser(ctx, &service.User{Kind: service.UserKindAgent, Status: service.StatusActive, OwnerUserID: owner})
	require.NoError(t, err)
	_, err = base.CreateSession(ctx, &service.SessionRecord{SID: "registration-sid", UserID: owner, CreatedAtMs: 100})
	require.NoError(t, err)
	client := oauthClientRecord("machine-client")
	client.Registration.GrantTypes = append(client.Registration.GrantTypes, service.OAuthGrantAgentMachine)
	client.Registration.Resources[0].Product = "records"
	require.NoError(t, base.CreateOAuthClient(ctx, client))
	oauth, ok := base.(service.AgentOAuthRepository)
	require.True(t, ok)
	repo, ok := base.(service.AgentMachineRepository)
	require.True(t, ok)
	m := &service.AgentMachine{ID: "machine", OwnerID: owner, ClientID: client.ID, ClientRevision: client.Revision, Resource: client.Registration.Resources[0].Resource, Product: "records", Scopes: []string{"read"}, DisplayName: "Acme workstation", CredentialHash: agentOAuthHash("machine-secret"), RegistrationSID: "registration-sid", AllAgents: true, CreatedAtMs: time.Now().UnixMilli(), Revision: 1}
	a, err := oauth.AgentOAuthAuthority(ctx, owner, "", m.RegistrationSID, client.ID)
	require.NoError(t, err)
	stored, err := repo.CreateAgentMachine(ctx, m, a.Fingerprint())
	require.NoError(t, err)
	require.Equal(t, m, stored)
	return machineFixture{base: base, repo: repo, oauth: oauth, machine: m, agent: agent}
}

func (f machineFixture) candidate(ctx context.Context, t *testing.T, id string) (*service.AgentAuthorization, string) {
	t.Helper()
	a, err := f.repo.AgentMachineAuthority(ctx, f.machine.ID, f.agent)
	require.NoError(t, err)
	now := time.Now().UnixMilli()
	return &service.AgentAuthorization{ID: id, MachineID: f.machine.ID, ClientID: f.machine.ClientID, ClientRevision: f.machine.ClientRevision, Resource: f.machine.Resource, Product: f.machine.Product, Scopes: []string{"read"}, OwnerID: f.machine.OwnerID, AgentID: f.agent, SessionID: "machine-session", Decision: service.AgentAuthorizationApproved, CreatedAtMs: now, ConsentAtMs: now, Revision: 1}, a.Fingerprint()
}

func (f machineFixture) ensure(ctx context.Context, t *testing.T, id string) *service.AgentAuthorization {
	t.Helper()
	candidate, fingerprint := f.candidate(ctx, t, id)
	grant, err := f.repo.EnsureAgentMachineDelegation(ctx, f.machine.ID, candidate, f.machine.CredentialHash, fingerprint)
	require.NoError(t, err)
	return grant
}

// RunAgentMachineConformance verifies durable machine and per-agent grant boundaries.
func RunAgentMachineConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/AgentMachine", func(t *testing.T) {
		ctx := context.Background()
		t.Run("RegistrationReceiptAndFreshSession", func(t *testing.T) {
			f := seedAgentMachine(ctx, t, driver.NewRepo(t))
			require.NoError(t, f.base.RevokeSession(ctx, f.machine.RegistrationSID, f.machine.CreatedAtMs+1))
			_, err := f.base.CreateSession(ctx, &service.SessionRecord{SID: "fresh-sid", UserID: f.machine.OwnerID, CreatedAtMs: f.machine.CreatedAtMs + 2})
			require.NoError(t, err)
			retry := f.machine.Clone()
			retry.RegistrationSID = "fresh-sid"
			retry.CreatedAtMs++
			a, err := f.oauth.AgentOAuthAuthority(ctx, retry.OwnerID, "", retry.RegistrationSID, retry.ClientID)
			require.NoError(t, err)
			got, err := f.repo.CreateAgentMachine(ctx, retry, a.Fingerprint())
			require.NoError(t, err)
			require.Equal(t, f.machine, got)
			retry.CredentialHash = agentOAuthHash("different")
			_, err = f.repo.CreateAgentMachine(ctx, retry, a.Fingerprint())
			require.ErrorIs(t, err, service.ErrAlreadyExists)
			retry = f.machine.Clone()
			retry.RegistrationSID = "fresh-sid"
			retry.AllAgents = false
			retry.AgentIDs = []string{f.agent}
			_, err = f.repo.CreateAgentMachine(ctx, retry, a.Fingerprint())
			require.ErrorIs(t, err, service.ErrAlreadyExists)
			_, err = f.repo.CreateAgentMachine(ctx, f.machine, "stale")
			require.ErrorIs(t, err, service.ErrAgentOAuthGrant)
			got.Scopes[0] = "write"
			got, err = f.repo.GetAgentMachine(ctx, f.machine.ID)
			require.NoError(t, err)
			require.Equal(t, []string{"read"}, got.Scopes)
			page, err := f.repo.ListAgentMachines(ctx, f.machine.OwnerID, "", 1)
			require.NoError(t, err)
			require.Len(t, page, 1)
			page, err = f.repo.ListAgentMachines(ctx, f.machine.OwnerID, f.machine.ID, 1)
			require.NoError(t, err)
			require.Empty(t, page)
			page, err = f.repo.ListAgentMachines(ctx, "other-owner", "", 1)
			require.NoError(t, err)
			require.Empty(t, page)
			revoked, err := f.repo.MutateAgentMachine(ctx, f.machine.ID, service.AgentMachineMutation{Operation: service.AgentMachineRevoke, OwnerID: f.machine.OwnerID, AtMs: f.machine.CreatedAtMs + 3})
			require.NoError(t, err)
			retry = f.machine.Clone()
			retry.RegistrationSID = "fresh-sid"
			got, err = f.repo.CreateAgentMachine(ctx, retry, a.Fingerprint())
			require.NoError(t, err)
			require.Equal(t, revoked, got)
		})
		t.Run("ConcurrentEnsureAndDurableRetention", func(t *testing.T) {
			f := seedAgentMachine(ctx, t, driver.NewRepo(t))
			candidate, fingerprint := f.candidate(ctx, t, "child")
			results := make(chan *service.AgentAuthorization, 8)
			failures := make(chan error, 8)
			var group sync.WaitGroup
			for i := range 8 {
				group.Go(func() {
					copy := candidate.Clone()
					copy.ID = fmt.Sprintf("child-%d", i)
					got, err := f.repo.EnsureAgentMachineDelegation(ctx, f.machine.ID, copy, f.machine.CredentialHash, fingerprint)
					if err != nil {
						failures <- err
					} else {
						results <- got
					}
				})
			}
			group.Wait()
			close(results)
			close(failures)
			for err := range failures {
				require.NoError(t, err)
			}
			var original *service.AgentAuthorization
			for result := range results {
				if original == nil {
					original = result
				}
				require.Equal(t, original, result)
			}
			require.NotNil(t, original)
			require.NoError(t, f.oauth.DeleteExpiredAgentAuthorizations(ctx, time.Now().Add(365*24*time.Hour).UnixMilli(), 100))
			retained, err := f.oauth.GetAgentAuthorization(ctx, original.ID)
			require.NoError(t, err)
			require.Equal(t, original, retained)
			a, err := f.repo.AgentMachineAuthority(ctx, f.machine.ID, f.agent)
			require.NoError(t, err)
			_, err = f.oauth.MutateAgentAuthorization(ctx, original.ID, service.AgentOAuthMutation{Operation: service.AgentOAuthValidate, AtMs: time.Now().UnixMilli(), AuthorityFingerprint: a.Fingerprint()})
			require.NoError(t, err)
			candidate, fingerprint = f.candidate(ctx, t, "wrong-proof")
			_, err = f.repo.EnsureAgentMachineDelegation(ctx, f.machine.ID, candidate, agentOAuthHash("wrong"), fingerprint)
			require.ErrorIs(t, err, service.ErrAgentOAuthGrant)
			_, err = f.repo.EnsureAgentMachineDelegation(ctx, f.machine.ID, candidate, f.machine.CredentialHash, "stale")
			require.ErrorIs(t, err, service.ErrAgentOAuthGrant)
		})
		t.Run("SelectionAndChildRevocationNeverRevive", func(t *testing.T) {
			f := seedAgentMachine(ctx, t, driver.NewRepo(t))
			child := f.ensure(ctx, t, "first-child")
			excluded, err := f.repo.MutateAgentMachine(ctx, f.machine.ID, service.AgentMachineMutation{Operation: service.AgentMachineSelect, OwnerID: f.machine.OwnerID, ExpectedRevision: 1, AllAgents: true, ExcludedAgentIDs: []string{f.agent}, AtMs: time.Now().UnixMilli()})
			require.NoError(t, err)
			revoked, err := f.oauth.GetAgentAuthorization(ctx, child.ID)
			require.NoError(t, err)
			require.NotZero(t, revoked.RevokedAtMs)
			_, err = f.repo.MutateAgentMachine(ctx, f.machine.ID, service.AgentMachineMutation{Operation: service.AgentMachineSelect, OwnerID: f.machine.OwnerID, ExpectedRevision: excluded.Revision, AllAgents: true, AtMs: time.Now().UnixMilli()})
			require.NoError(t, err)
			got := f.ensure(ctx, t, "replacement-child")
			require.Equal(t, revoked, got)
			_, err = f.repo.MutateAgentMachine(ctx, f.machine.ID, service.AgentMachineMutation{Operation: service.AgentMachineSelect, OwnerID: f.machine.OwnerID, ExpectedRevision: 1, AllAgents: true, AtMs: time.Now().UnixMilli()})
			require.ErrorIs(t, err, service.ErrAgentOAuthRevision)
		})
		t.Run("ParentRevokesAllChildren", func(t *testing.T) {
			f := seedAgentMachine(ctx, t, driver.NewRepo(t))
			child := f.ensure(ctx, t, "child")
			_, err := f.repo.MutateAgentMachine(ctx, f.machine.ID, service.AgentMachineMutation{Operation: service.AgentMachineRevoke, OwnerID: "other", AtMs: time.Now().UnixMilli()})
			require.ErrorIs(t, err, service.ErrPermissionDenied)
			_, err = f.repo.MutateAgentMachine(ctx, f.machine.ID, service.AgentMachineMutation{Operation: service.AgentMachineRevoke, OwnerID: f.machine.OwnerID, AtMs: time.Now().UnixMilli()})
			require.NoError(t, err)
			stored, err := f.oauth.GetAgentAuthorization(ctx, child.ID)
			require.NoError(t, err)
			require.NotZero(t, stored.RevokedAtMs)
			candidate, fingerprint := f.candidate(ctx, t, "replacement")
			_, err = f.repo.EnsureAgentMachineDelegation(ctx, f.machine.ID, candidate, f.machine.CredentialHash, fingerprint)
			require.ErrorIs(t, err, service.ErrAgentOAuthGrant)
		})
		t.Run("TransferBackNeverRevivesChild", func(t *testing.T) {
			f := seedAgentMachine(ctx, t, driver.NewRepo(t))
			child := f.ensure(ctx, t, "child")
			other, err := f.base.CreateUser(ctx, &service.User{Email: "other-owner@example.test", Kind: service.UserKindPerson, Status: service.StatusActive})
			require.NoError(t, err)
			changed, err := f.base.SetAgentOwnership(ctx, f.agent, f.machine.OwnerID, other, "", time.Now().UnixMilli())
			require.NoError(t, err)
			require.True(t, changed)
			candidate, fingerprint := f.candidate(ctx, t, "wrong-owner-child")
			_, err = f.repo.EnsureAgentMachineDelegation(ctx, f.machine.ID, candidate, f.machine.CredentialHash, fingerprint)
			require.ErrorIs(t, err, service.ErrAgentOAuthGrant)
			changed, err = f.base.SetAgentOwnership(ctx, f.agent, other, f.machine.OwnerID, "", time.Now().UnixMilli())
			require.NoError(t, err)
			require.True(t, changed)
			got := f.ensure(ctx, t, "returned-child")
			require.Equal(t, child.ID, got.ID)
			require.NotZero(t, got.RevokedAtMs)
		})
		t.Run("ProjectBoundaries", func(t *testing.T) {
			if driver.BindProject == nil {
				t.Skip("no project binding")
			}
			base := driver.NewRepo(t)
			one := driver.BindProject(t, base, "machine-one")
			two := driver.BindProject(t, base, "machine-two")
			f := seedAgentMachine(ctx, t, one)
			g := seedAgentMachine(ctx, t, two)
			own := f.ensure(ctx, t, "child")
			other := g.ensure(ctx, t, "child")
			_, err := g.repo.MutateAgentMachine(ctx, g.machine.ID, service.AgentMachineMutation{Operation: service.AgentMachineRevoke, OwnerID: g.machine.OwnerID, AtMs: time.Now().UnixMilli()})
			require.NoError(t, err)
			got, err := f.oauth.GetAgentAuthorization(ctx, own.ID)
			require.NoError(t, err)
			require.Zero(t, got.RevokedAtMs)
			got, err = g.oauth.GetAgentAuthorization(ctx, other.ID)
			require.NoError(t, err)
			require.NotZero(t, got.RevokedAtMs)
			if f.machine.OwnerID != g.machine.OwnerID {
				_, err = g.repo.MutateAgentMachine(ctx, g.machine.ID, service.AgentMachineMutation{Operation: service.AgentMachineRevoke, OwnerID: f.machine.OwnerID, AtMs: time.Now().UnixMilli()})
				require.ErrorIs(t, err, service.ErrPermissionDenied)
			}
		})
		for _, operation := range []string{"owner-status", "owner-email", "owner-password", "owner-delete", "agent-status", "client-revision", "guardian-delete", "sid-revoke", "sid-global", "refresh-delete", "refresh-global"} {
			t.Run(operation, func(t *testing.T) {
				f := seedAgentMachine(ctx, t, driver.NewRepo(t))
				child := f.ensure(ctx, t, "child")
				persistent := operation == "sid-revoke" || operation == "sid-global" || operation == "refresh-delete" || operation == "refresh-global"
				switch operation {
				case "owner-status":
					require.NoError(t, f.base.UpdateUser(ctx, f.machine.OwnerID, map[string]any{"status": service.StatusDeactivated}))
					require.NoError(t, f.base.UpdateUser(ctx, f.machine.OwnerID, map[string]any{"status": service.StatusActive}))
				case "owner-email":
					require.NoError(t, f.base.UpdateUserEmail(ctx, f.machine.OwnerID, "changed@example.test", time.Now().UnixMilli()))
				case "owner-password":
					require.NoError(t, f.base.UpdateUser(ctx, f.machine.OwnerID, map[string]any{"password_hash": "changed"}))
				case "owner-delete":
					require.NoError(t, f.base.DeleteUser(ctx, f.machine.OwnerID))
				case "agent-status":
					require.NoError(t, f.base.UpdateUser(ctx, f.agent, map[string]any{"status": service.StatusDeactivated}))
					require.NoError(t, f.base.UpdateUser(ctx, f.agent, map[string]any{"status": service.StatusActive}))
				case "client-revision":
					client, err := f.base.GetOAuthClient(ctx, f.machine.ClientID)
					require.NoError(t, err)
					_, err = f.base.UpdateOAuthClient(ctx, client.ID, client.Revision, &client.Registration, time.Now().UnixMilli())
					require.NoError(t, err)
				case "guardian-delete":
					guardian, err := f.base.CreateUser(ctx, &service.User{Email: "guardian@example.test", Status: service.StatusActive})
					require.NoError(t, err)
					require.NoError(t, f.base.UpsertGuardianEdge(ctx, &service.GuardianEdge{GuardianUserID: guardian, ChildUserID: f.machine.OwnerID}))
					require.NoError(t, f.base.DeleteGuardianEdge(ctx, guardian, f.machine.OwnerID))
				case "sid-revoke":
					require.NoError(t, f.base.RevokeSession(ctx, f.machine.RegistrationSID, time.Now().UnixMilli()))
				case "sid-global":
					require.NoError(t, f.base.RevokeSessionsForUser(ctx, f.machine.OwnerID, time.Now().UnixMilli()))
				case "refresh-delete", "refresh-global":
					id, err := f.base.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: agentOAuthHash("human-refresh"), UserID: f.machine.OwnerID, SID: f.machine.RegistrationSID, ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
					require.NoError(t, err)
					if operation == "refresh-delete" {
						require.NoError(t, f.base.DeleteRefreshToken(ctx, id))
					} else {
						require.NoError(t, f.base.DeleteRefreshTokensForUser(ctx, f.machine.OwnerID))
					}
				}
				machine, err := f.repo.GetAgentMachine(ctx, f.machine.ID)
				require.NoError(t, err)
				got, err := f.oauth.GetAgentAuthorization(ctx, child.ID)
				require.NoError(t, err)
				if persistent {
					require.Zero(t, machine.RevokedAtMs)
					require.Zero(t, got.RevokedAtMs)
					a, err := f.repo.AgentMachineAuthority(ctx, f.machine.ID, f.agent)
					require.NoError(t, err)
					_, err = f.oauth.MutateAgentAuthorization(ctx, child.ID, service.AgentOAuthMutation{Operation: service.AgentOAuthValidate, AtMs: time.Now().UnixMilli(), AuthorityFingerprint: a.Fingerprint()})
					require.NoError(t, err)
				} else {
					require.NotZero(t, got.RevokedAtMs)
					if operation != "agent-status" {
						require.NotZero(t, machine.RevokedAtMs)
					}
				}
			})
		}
		t.Run("ProjectPolicyRestorationNeverRevives", func(t *testing.T) {
			if driver.ChangeProjectPolicy == nil {
				t.Skip("driver has no project policy control plane")
			}
			f := seedAgentMachine(ctx, t, driver.NewRepo(t))
			child := f.ensure(ctx, t, "policy-child")
			driver.ChangeProjectPolicy(t, f.base)
			m, err := f.repo.GetAgentMachine(ctx, f.machine.ID)
			require.NoError(t, err)
			require.NotZero(t, m.RevokedAtMs)
			stored, err := f.oauth.GetAgentAuthorization(ctx, child.ID)
			require.NoError(t, err)
			require.NotZero(t, stored.RevokedAtMs)
			candidate, fingerprint := f.candidate(ctx, t, "restored-policy-child")
			_, err = f.repo.EnsureAgentMachineDelegation(ctx, f.machine.ID, candidate, f.machine.CredentialHash, fingerprint)
			require.ErrorIs(t, err, service.ErrAgentOAuthGrant)
		})
		t.Run("RestartPreservesGrantAndTombstone", func(t *testing.T) {
			if driver.Reopen == nil {
				t.Skip("driver has no durable restart")
			}
			f := seedAgentMachine(ctx, t, driver.NewRepo(t))
			original := f.ensure(ctx, t, "original-child")
			f.base = driver.Reopen(t, f.base)
			f.repo = f.base.(service.AgentMachineRepository)
			f.oauth = f.base.(service.AgentOAuthRepository)
			got := f.ensure(ctx, t, "post-restart-child")
			require.Equal(t, original, got)
			_, err := f.oauth.MutateAgentAuthorization(ctx, got.ID, service.AgentOAuthMutation{Operation: service.AgentOAuthRevoke, OwnerID: f.machine.OwnerID, AtMs: time.Now().UnixMilli()})
			require.NoError(t, err)
			f.base = driver.Reopen(t, f.base)
			f.repo = f.base.(service.AgentMachineRepository)
			f.oauth = f.base.(service.AgentOAuthRepository)
			got = f.ensure(ctx, t, "post-revoke-restart")
			require.Equal(t, original.ID, got.ID)
			require.NotZero(t, got.RevokedAtMs)
		})
	})
}
