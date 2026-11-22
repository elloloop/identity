package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGuardianDeletionReceiptResolvesLostAcknowledgements(t *testing.T) {
	f := newReauthenticationFixture(t)
	ctx := context.Background()
	child := seedManagedChild(t, f.repo, "child.example", f.service.nowFunc().AddDate(-8, 0, 0).UnixMilli())
	seedGuardianEdge(ctx, t, f.repo, f.user.ID, child.ID)
	purger := &fakePurger{repo: f.repo}
	f.service.WithAccountPurger(purger)
	first := f.proof(t, "guardian.delete_child", child.ID, true)
	remove := func(proof *PasskeyReauthentication) error {
		return f.service.DeleteManagedChildAccount(context.Background(), f.user.ID, SessionSignIn{}, child.ID, "", proof, "", "")
	}
	require.NoError(t, remove(first))
	require.Error(t, remove(first))
	for _, loss := range []string{"RPC response", "application completion update"} {
		t.Run(loss, func(t *testing.T) {
			proof := f.proof(t, "guardian.delete_child", child.ID, true)
			require.NoError(t, remove(proof))
			require.Error(t, remove(proof))
		})
	}
	require.Len(t, purger.calls, 1)
	remaining, err := f.repo.GetUser(ctx, child.ID)
	require.NoError(t, err)
	require.Nil(t, remaining)
	edge, err := f.repo.GetGuardianEdge(ctx, f.user.ID, child.ID)
	require.NoError(t, err)
	require.Nil(t, edge)

	wrongAction := f.proof(t, "guardian.view_child", child.ID, true)
	require.Error(t, remove(wrongAction))
	proof := f.proof(t, "guardian.delete_child", child.ID, true)
	f.user.Status = StatusDeactivated
	require.Error(t, remove(proof))
}

func TestGuardianDeletionReceiptDoesNotReplaceMissingAuthority(t *testing.T) {
	f := newReauthenticationFixture(t)
	ctx := context.Background()
	child := seedManagedChild(t, f.repo, "child.example", f.service.nowFunc().AddDate(-8, 0, 0).UnixMilli())
	seedGuardianEdge(ctx, t, f.repo, f.user.ID, child.ID)
	f.service.WithAccountPurger(&fakePurger{repo: f.repo})
	proof := f.proof(t, "guardian.delete_child", child.ID, true)
	require.NoError(t, f.repo.DeleteUser(ctx, child.ID))
	require.ErrorIs(t, f.service.DeleteManagedChildAccount(ctx, f.user.ID, SessionSignIn{}, child.ID, "", proof, "", ""), ErrPermissionDenied)
	completed, err := f.repo.HasGuardianDeletionReceipt(ctx, f.user.ID, child.ID)
	require.NoError(t, err)
	require.False(t, completed)
}

func TestGuardianDeletionRechecksAuthorityAtFinalErasure(t *testing.T) {
	for _, change := range []string{"withdraw consent", "remove guardian", "disable guardian"} {
		t.Run(change, func(t *testing.T) {
			f := newReauthenticationFixture(t)
			ctx := context.Background()
			child := seedManagedChild(t, f.repo, "child.example", f.service.nowFunc().AddDate(-8, 0, 0).UnixMilli())
			seedGuardianEdge(ctx, t, f.repo, f.user.ID, child.ID)
			f.service.WithAccountPurger(&fakePurger{repo: f.repo, beforeManagedPurge: func() {
				switch change {
				case "withdraw consent":
					child.Status = StatusPendingParentalConsent
				case "remove guardian":
					require.NoError(t, f.repo.DeleteGuardianEdge(ctx, f.user.ID, child.ID))
				case "disable guardian":
					f.user.Status = StatusDeactivated
				}
			}})
			proof := f.proof(t, "guardian.delete_child", child.ID, true)
			require.ErrorIs(t, f.service.DeleteManagedChildAccount(ctx, f.user.ID, SessionSignIn{}, child.ID, "", proof, "", ""), ErrPermissionDenied)
			remaining, err := f.repo.GetUser(ctx, child.ID)
			require.NoError(t, err)
			require.NotNil(t, remaining)
			completed, err := f.repo.HasGuardianDeletionReceipt(ctx, f.user.ID, child.ID)
			require.NoError(t, err)
			require.False(t, completed)
		})
	}
}

type unavailableGuardianReceipts struct{ Repository }

func (r unavailableGuardianReceipts) WithProject(projectID string) Repository {
	return unavailableGuardianReceipts{r.Repository.WithProject(projectID)}
}

func (unavailableGuardianReceipts) HasGuardianDeletionReceipt(context.Context, string, string) (bool, error) {
	return false, ErrServiceUnavailable
}

func TestGuardianDeletionReceiptOutageFailsClosed(t *testing.T) {
	f := newReauthenticationFixture(t)
	proof := f.proof(t, "guardian.delete_child", "child", true)
	f.service.defaultRepo = unavailableGuardianReceipts{f.repo}
	require.ErrorIs(t, f.service.DeleteManagedChildAccount(context.Background(), f.user.ID, SessionSignIn{}, "child", "", proof, "", ""), ErrServiceUnavailable)
}

func TestGuardianDeletionParticipantPolicy(t *testing.T) {
	for _, status := range []string{"", StatusActive, StatusDeactivated, StatusPendingDeletion} {
		require.True(t, GuardianDeletionParticipantsAllowed(&User{Status: StatusActive}, &User{Status: status}))
	}
	for _, invalid := range []*User{
		nil,
		{Status: StatusPendingParentalConsent},
		{Status: StatusInvited},
		{Status: " active "},
		{Kind: UserKindAgent},
		{IsAnonymous: true},
		{MergedIntoUserID: "other"},
	} {
		require.False(t, GuardianDeletionParticipantsAllowed(&User{Status: StatusActive}, invalid))
		require.False(t, GuardianDeletionParticipantsAllowed(invalid, &User{Status: StatusActive}))
	}
	require.False(t, GuardianDeletionParticipantsAllowed(&User{Status: StatusDeactivated}, &User{Status: StatusActive}))
}

func TestGuardianDeletionChecksStatusBeforeDestructiveCleanup(t *testing.T) {
	for _, status := range []string{StatusPendingDeletion, StatusPendingParentalConsent} {
		t.Run(status, func(t *testing.T) {
			f := newReauthenticationFixture(t)
			child := seedManagedChild(t, f.repo, "child.example", f.service.nowFunc().AddDate(-8, 0, 0).UnixMilli())
			child.Status = status
			ctx := context.Background()
			seedGuardianEdge(ctx, t, f.repo, f.user.ID, child.ID)
			seedChildSession(t, f.repo, child.ID)
			purger := &fakePurger{repo: f.repo}
			f.service.WithAccountPurger(purger)
			proof := f.proof(t, "guardian.delete_child", child.ID, true)
			err := f.service.DeleteManagedChildAccount(ctx, f.user.ID, SessionSignIn{}, child.ID, "", proof, "", "")
			if status == StatusPendingDeletion {
				require.NoError(t, err)
				require.Len(t, purger.calls, 1)
			} else {
				require.ErrorIs(t, err, ErrPermissionDenied)
				require.Empty(t, purger.calls)
				session, err := f.repo.GetSessionBySid(ctx, "sess-"+child.ID)
				require.NoError(t, err)
				require.NotNil(t, session)
				require.Zero(t, session.RevokedAtMs)
			}
		})
	}
}
