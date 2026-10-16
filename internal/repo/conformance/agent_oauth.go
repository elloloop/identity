package conformance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func agentOAuthHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func seedAgentOAuth(t *testing.T, base service.Repository) (service.AgentOAuthRepository, *service.AgentAuthorization, service.AgentOAuthMutation) {
	t.Helper()
	ctx := context.Background()
	repo, ok := base.(service.AgentOAuthRepository)
	require.True(t, ok)
	owner, err := base.CreateUser(ctx, &service.User{Email: "owner@example.test", Kind: service.UserKindPerson, Status: service.StatusActive})
	require.NoError(t, err)
	agent, err := base.CreateUser(ctx, &service.User{Kind: service.UserKindAgent, Status: service.StatusActive, OwnerUserID: owner})
	require.NoError(t, err)
	_, err = base.CreateSession(ctx, &service.SessionRecord{SID: "human-sid", UserID: owner, CreatedAtMs: 100})
	require.NoError(t, err)
	client := oauthClientRecord("delegated-client")
	require.NoError(t, base.CreateOAuthClient(ctx, client))
	now := time.Now().UnixMilli()
	request := &service.AgentAuthorization{ID: "authorization", ClientID: client.ID, ClientRevision: client.Revision, RedirectURI: client.Registration.RedirectURIs[0], Resource: client.Registration.Resources[0].Resource, Scopes: []string{"read"}, Challenge: strings.Repeat("a", 43), CreatedAtMs: now, ExpiresAtMs: now + 60000, Decision: service.AgentAuthorizationPending, Revision: 1}
	require.NoError(t, repo.CreateAgentAuthorization(ctx, request))
	a, err := repo.AgentOAuthAuthority(ctx, owner, agent, "human-sid", client.ID)
	require.NoError(t, err)
	approval := service.AgentOAuthMutation{Operation: service.AgentOAuthApprove, AtMs: now, ExpectedRevision: 1, OwnerID: owner, AgentID: agent, HumanSID: "human-sid", GrantExpiresAtMs: now + 120000, CodeHash: agentOAuthHash("code"), CodeExpiresAtMs: now + 30000, AuthorityFingerprint: a.Fingerprint()}
	return repo, request, approval
}

// RunAgentOAuthConformance verifies the optional delegated OAuth capability.
// Each supported driver runs this in addition to the core Repository contract.
func RunAgentOAuthConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/AgentOAuth", func(t *testing.T) {
		t.Run("ConsentAndCodeSingleWinner", func(t *testing.T) {
			base := driver.NewRepo(t)
			repo, r, approve := seedAgentOAuth(t, base)
			ctx := context.Background()
			var winners atomic.Int32
			var group sync.WaitGroup
			errs := make(chan error, 8)
			for range 8 {
				group.Go(func() {
					_, err := repo.MutateAgentAuthorization(ctx, r.ID, approve)
					if err == nil {
						winners.Add(1)
					} else {
						errs <- err
					}
				})
			}
			group.Wait()
			close(errs)
			require.EqualValues(t, 1, winners.Load())
			for err := range errs {
				require.ErrorIs(t, err, service.ErrAgentOAuthRevision)
			}
			saved, err := repo.FindAgentAuthorizationByCode(ctx, approve.CodeHash)
			require.NoError(t, err)
			require.Equal(t, r.ID, saved.ID)
			saved.Scopes[0] = "bad"
			saved, err = repo.GetAgentAuthorization(ctx, r.ID)
			require.NoError(t, err)
			require.Equal(t, []string{"read"}, saved.Scopes)
			redeem := service.AgentOAuthMutation{Operation: service.AgentOAuthRedeem, AtMs: approve.AtMs + 1, AuthorityFingerprint: approve.AuthorityFingerprint, CodeHash: agentOAuthHash("wrong"), SessionID: "delegated-sid", NextRefreshHash: agentOAuthHash("refresh"), RefreshExpiresAtMs: approve.GrantExpiresAtMs}
			_, err = repo.MutateAgentAuthorization(ctx, r.ID, redeem)
			require.ErrorIs(t, err, service.ErrAgentOAuthGrant)
			redeem.CodeHash = approve.CodeHash
			winners.Store(0)
			for range 8 {
				group.Go(func() {
					_, err := repo.MutateAgentAuthorization(ctx, r.ID, redeem)
					if err == nil {
						winners.Add(1)
					}
				})
			}
			group.Wait()
			require.EqualValues(t, 1, winners.Load())
			refresh, err := repo.FindAgentAuthorizationByRefresh(ctx, redeem.NextRefreshHash)
			require.NoError(t, err)
			require.Equal(t, "delegated-sid", refresh.SessionID)
			rotate := service.AgentOAuthMutation{Operation: service.AgentOAuthRotate, AtMs: approve.AtMs + 2, AuthorityFingerprint: approve.AuthorityFingerprint, RefreshHash: redeem.NextRefreshHash, NextRefreshHash: agentOAuthHash("next"), RefreshExpiresAtMs: approve.GrantExpiresAtMs}
			_, err = repo.MutateAgentAuthorization(ctx, r.ID, rotate)
			require.NoError(t, err)
			replay, err := repo.MutateAgentAuthorization(ctx, r.ID, rotate)
			require.ErrorIs(t, err, service.ErrAgentOAuthGrant)
			require.NotZero(t, replay.RevokedAtMs)
			_, err = repo.MutateAgentAuthorization(ctx, r.ID, service.AgentOAuthMutation{Operation: service.AgentOAuthValidate, AtMs: approve.AtMs + 3, AuthorityFingerprint: approve.AuthorityFingerprint})
			require.ErrorIs(t, err, service.ErrAgentOAuthGrant)
		})
		t.Run("TransferBackNeverRevives", func(t *testing.T) {
			base := driver.NewRepo(t)
			repo, r, m := seedAgentOAuth(t, base)
			ctx := context.Background()
			_, err := repo.MutateAgentAuthorization(ctx, r.ID, m)
			require.NoError(t, err)
			other, err := base.CreateUser(ctx, &service.User{Email: "other@example.test", Kind: service.UserKindPerson, Status: service.StatusActive})
			require.NoError(t, err)
			changed, err := base.SetAgentOwnership(ctx, m.AgentID, m.OwnerID, other, "", m.AtMs+1)
			require.NoError(t, err)
			require.True(t, changed)
			changed, err = base.SetAgentOwnership(ctx, m.AgentID, other, m.OwnerID, "", m.AtMs+2)
			require.NoError(t, err)
			require.True(t, changed)
			grant, err := repo.GetAgentAuthorization(ctx, r.ID)
			require.NoError(t, err)
			require.NotZero(t, grant.RevokedAtMs)
		})
		t.Run("RetentionAndRefreshCascade", func(t *testing.T) {
			base := driver.NewRepo(t)
			repo, r, m := seedAgentOAuth(t, base)
			ctx := context.Background()
			_, err := repo.MutateAgentAuthorization(ctx, r.ID, m)
			require.NoError(t, err)
			_, err = repo.MutateAgentAuthorization(ctx, r.ID, service.AgentOAuthMutation{Operation: service.AgentOAuthRedeem, AtMs: m.AtMs + 1, AuthorityFingerprint: m.AuthorityFingerprint, CodeHash: m.CodeHash, SessionID: "delegated-sid", NextRefreshHash: agentOAuthHash("refresh"), RefreshExpiresAtMs: m.GrantExpiresAtMs})
			require.NoError(t, err)
			require.ErrorIs(t, repo.DeleteExpiredAgentAuthorizations(ctx, m.GrantExpiresAtMs+1, 0), service.ErrInvalidArgument)
			require.NoError(t, repo.DeleteExpiredAgentAuthorizations(ctx, m.GrantExpiresAtMs, 1))
			got, err := repo.GetAgentAuthorization(ctx, r.ID)
			require.NoError(t, err)
			require.NotNil(t, got)
			require.NoError(t, repo.DeleteExpiredAgentAuthorizations(ctx, m.GrantExpiresAtMs+1, 1))
			got, err = repo.FindAgentAuthorizationByCode(ctx, m.CodeHash)
			require.NoError(t, err)
			require.Nil(t, got)
			got, err = repo.FindAgentAuthorizationByRefresh(ctx, agentOAuthHash("refresh"))
			require.NoError(t, err)
			require.Nil(t, got)
		})
		t.Run("ProjectIsolation", func(t *testing.T) {
			if driver.BindProject == nil {
				t.Skip("driver has no project binding")
			}
			base := driver.NewRepo(t)
			one := driver.BindProject(t, base, "delegation-one")
			two := driver.BindProject(t, base, "delegation-two")
			repo, r, m := seedAgentOAuth(t, one)
			other, ok := two.(service.AgentOAuthRepository)
			require.True(t, ok)
			ctx := context.Background()
			got, err := other.GetAgentAuthorization(ctx, r.ID)
			require.NoError(t, err)
			require.Nil(t, got)
			_, err = other.MutateAgentAuthorization(ctx, r.ID, m)
			require.ErrorIs(t, err, service.ErrAgentOAuthGrant)
			require.NoError(t, other.DeleteExpiredAgentAuthorizations(ctx, m.GrantExpiresAtMs+1, 10))
			got, err = repo.GetAgentAuthorization(ctx, r.ID)
			require.NoError(t, err)
			require.NotNil(t, got)
		})

		for _, operation := range []string{"owner-status", "agent-status", "owner-email", "owner-dob", "owner-idv", "owner-market", "owner-delete", "sid-revoke", "sid-global", "client-revision", "owner-password", "owner-password-required", "refresh-delete", "refresh-global", "guardian-delete"} {
			t.Run(operation, func(t *testing.T) {
				base := driver.NewRepo(t)
				repo, r, m := seedAgentOAuth(t, base)
				ctx := context.Background()
				var refreshID string
				if operation == "refresh-delete" || operation == "refresh-global" {
					var err error
					refreshID, err = base.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: agentOAuthHash("human-refresh"), UserID: m.OwnerID, SID: m.HumanSID, ExpiresAt: m.GrantExpiresAtMs})
					require.NoError(t, err)
				}
				if operation == "guardian-delete" {
					guardian, err := base.CreateUser(ctx, &service.User{Email: "guardian@example.test", Kind: service.UserKindPerson, Status: service.StatusActive})
					require.NoError(t, err)
					require.NoError(t, base.UpsertGuardianEdge(ctx, &service.GuardianEdge{GuardianUserID: guardian, ChildUserID: m.OwnerID}))
					authority, err := repo.AgentOAuthAuthority(ctx, m.OwnerID, m.AgentID, m.HumanSID, r.ClientID)
					require.NoError(t, err)
					m.AuthorityFingerprint = authority.Fingerprint()
				}
				_, err := repo.MutateAgentAuthorization(ctx, r.ID, m)
				require.NoError(t, err)
				switch operation {
				case "owner-password":
					require.NoError(t, base.UpdateUser(ctx, m.OwnerID, map[string]any{"password_hash": "changed-test-hash"}))
				case "owner-password-required":
					require.NoError(t, base.UpdateUser(ctx, m.OwnerID, map[string]any{"password_change_required": true}))
				case "refresh-delete":
					require.NoError(t, base.DeleteRefreshToken(ctx, refreshID))
				case "refresh-global":
					require.NoError(t, base.DeleteRefreshTokensForUser(ctx, m.OwnerID))
				case "guardian-delete":
					guardians, err := base.ListGuardiansOfChild(ctx, m.OwnerID, 1, 0)
					require.NoError(t, err)
					require.Len(t, guardians, 1)
					require.NoError(t, base.DeleteGuardianEdge(ctx, guardians[0].GuardianUserID, m.OwnerID))
				case "owner-status":
					require.NoError(t, base.UpdateUser(ctx, m.OwnerID, map[string]any{"status": service.StatusDeactivated}))
					require.NoError(t, base.UpdateUser(ctx, m.OwnerID, map[string]any{"status": service.StatusActive}))
				case "agent-status":
					require.NoError(t, base.UpdateUser(ctx, m.AgentID, map[string]any{"status": service.StatusDeactivated}))
					require.NoError(t, base.UpdateUser(ctx, m.AgentID, map[string]any{"status": service.StatusActive}))
				case "owner-email":
					require.NoError(t, base.UpdateUserEmail(ctx, m.OwnerID, "new@example.test", m.AtMs+1))
				case "owner-dob":
					_, err = base.SetDateOfBirthOnce(ctx, m.OwnerID, 1, "", m.AtMs+1)
					require.NoError(t, err)
				case "owner-idv":
					require.NoError(t, base.SetUserIDVVerified(ctx, m.OwnerID, m.AtMs+1))
				case "owner-market":
					require.NoError(t, base.UpdateUser(ctx, m.OwnerID, map[string]any{"market": "IN"}))
				case "owner-delete":
					require.NoError(t, base.DeleteUser(ctx, m.OwnerID))
				case "sid-revoke":
					require.NoError(t, base.RevokeSession(ctx, m.HumanSID, m.AtMs+1))
				case "sid-global":
					require.NoError(t, base.RevokeSessionsForUser(ctx, m.OwnerID, m.AtMs+1))
				case "client-revision":
					client, err := base.GetOAuthClient(ctx, r.ClientID)
					require.NoError(t, err)
					client.Registration.Disabled = true
					_, err = base.UpdateOAuthClient(ctx, r.ClientID, 1, &client.Registration, m.AtMs+1)
					require.NoError(t, err)
				}
				got, err := repo.GetAgentAuthorization(ctx, r.ID)
				require.NoError(t, err)
				require.NotZero(t, got.RevokedAtMs)
			})
		}
	})
}
