package service

import (
	"context"
	"strings"
	"testing"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/events"
	"github.com/stretchr/testify/require"
)

func (r *fakeRepo) CreateAgent(_ context.Context, request AgentCreation) (*User, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return request.ApplyToUsers(r.users, r.agentCreations, nextNodeID)
}

func TestCreateAgentRetryNormalizesAndEmitsOnce(t *testing.T) {
	f := newAgentFixture(t)
	f.svc.cfg.AgentsMaxPerOwner = 1
	ctx := context.Background()
	first, err := f.svc.CreateAgent(ctx, f.owner.ID, " Helper ", " https://example.com/avatar.png ", "", "", "", "stable-create")
	require.NoError(t, err)
	replay, err := f.svc.CreateAgent(ctx, f.owner.ID, "Helper", "https://example.com/avatar.png", f.owner.ID, "", "", "stable-create")
	require.NoError(t, err)
	require.Equal(t, first.ID, replay.ID)
	count := 0
	for _, event := range f.pub.events {
		if event.Type == events.EventUserCreated {
			count++
		}
	}
	require.Equal(t, 1, count)
	_, err = f.svc.CreateAgent(ctx, f.owner.ID, "Different", "https://example.com/avatar.png", "", "", "", "stable-create")
	require.ErrorIs(t, err, ErrAlreadyExists)
	f.setStatus(f.owner.ID, StatusDeactivated)
	_, err = f.svc.CreateAgent(ctx, f.owner.ID, "Helper", "https://example.com/avatar.png", "", "", "", "stable-create")
	require.ErrorIs(t, err, ErrAccountNotActive)
}

func TestAgentCreationKeyAndFingerprint(t *testing.T) {
	for _, key := range []string{strings.Repeat("x", 129), "a\nb", string([]byte{0xff})} {
		require.ErrorIs(t, validateAgentCreationKey(key), ErrInvalidArgument)
	}
	require.NoError(t, validateAgentCreationKey("opaque : request"))
	require.NotEqual(t, agentCreationFingerprint("ab", "c"), agentCreationFingerprint("a", "bc"))
}

func TestAgentCreationAuthorityLoss(t *testing.T) {
	original := &User{Kind: UserKindAgent, OwnerUserID: "owner", Status: StatusActive, Role: RoleMember}
	for _, change := range []func(*User){func(u *User) { u.OwnerUserID = "other" }, func(u *User) { u.Status = StatusDeactivated }, func(u *User) { u.IsAnonymous = true }, func(u *User) { u.MergedIntoUserID = "other" }} {
		copy := *original
		change(&copy)
		require.True(t, AgentCreationAuthorityLost(original, &copy))
	}
	copy := *original
	copy.Name = "new"
	copy.PendingOwnerUserID = "recipient"
	require.False(t, AgentCreationAuthorityLost(original, &copy))
	require.True(t, AgentCreationAuthorityLost(original, nil))
}

func TestAgentCreationSharedMemoryOperation(t *testing.T) {
	owner := &User{ID: "owner", Kind: UserKindPerson, Role: RoleMember, Status: StatusActive}
	users := map[string]*User{owner.ID: owner}
	receipts := make(map[[2]string]AgentCreationReceipt)
	request := AgentCreation{CallerID: owner.ID, RequestID: "retry", Fingerprint: strings.Repeat("a", 64), OwnerLimit: 1, Agent: &User{Kind: UserKindAgent, OwnerUserID: owner.ID, Name: "Helper", Role: RoleMember, Status: StatusActive}}
	allocated := 0
	allocate := func() string { allocated++; return "agent" }
	first, created, err := request.ApplyToUsers(users, receipts, allocate)
	require.NoError(t, err)
	require.True(t, created)
	first.Name = "caller mutation"
	replay, created, err := request.ApplyToUsers(users, receipts, allocate)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, "Helper", replay.Name)
	require.Equal(t, 1, allocated)
	require.Empty(t, request.Agent.ID)
	InvalidateAgentCreationReceipts(receipts, owner.ID)
	_, _, err = request.ApplyToUsers(users, receipts, allocate)
	require.ErrorIs(t, err, ErrPermissionDenied)
	require.Equal(t, 1, allocated)
}

func TestCreateAgentAuditsStoreRefusals(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	_, err := f.svc.CreateAgent(ctx, f.owner.ID, "Helper", "", "", "", "", "same-key")
	require.NoError(t, err)
	_, err = f.svc.CreateAgent(ctx, f.owner.ID, "Other", "", "", "", "", "same-key")
	require.ErrorIs(t, err, ErrAlreadyExists)
	require.Equal(t, 1, f.writer.countByEventTypeAndDetail(string(audit.EventAgentCreated), "step", "request_id_conflict"))
	f.repo.afterGetUserHook = func(stored *User) { f.repo.afterGetUserHook = nil; stored.Status = StatusDeactivated }
	_, err = f.svc.CreateAgent(ctx, f.owner.ID, "Helper", "", "", "", "", "same-key")
	require.ErrorIs(t, err, ErrPermissionDenied)
	require.Equal(t, 1, f.writer.countByEventTypeAndDetail(string(audit.EventAgentCreated), "step", "authority_revoked"))
}
