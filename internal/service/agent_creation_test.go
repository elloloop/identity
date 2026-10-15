package service

import (
	"context"
	"strings"
	"testing"

	"github.com/elloloop/identity/pkg/events"
	"github.com/stretchr/testify/require"
)

func (r *fakeRepo) CreateAgent(_ context.Context, request AgentCreation) (*User, bool, error) {
	if err := ValidateAgentCreation(request); err != nil {
		return nil, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := CheckAgentCreationAuthority(r.users[request.CallerID], r.users[request.Agent.OwnerUserID]); err != nil {
		return nil, false, err
	}
	key := [2]string{request.CallerID, request.RequestID}
	if receipt, ok := r.agentCreations[key]; request.RequestID != "" && ok {
		agent := r.users[receipt.AgentID]
		if err := CheckAgentCreationReplay(receipt, request, agent); err != nil {
			return nil, false, err
		}
		copy := *agent
		return &copy, false, nil
	}
	count := 0
	for _, user := range r.users {
		if user.IsAgent() && user.OwnerUserID == request.Agent.OwnerUserID {
			count++
		}
	}
	if count >= request.OwnerLimit {
		return nil, false, ErrAgentLimitReached
	}
	copy := *request.Agent
	copy.ID = nextNodeID()
	r.users[copy.ID] = &copy
	if request.RequestID != "" {
		r.agentCreations[key] = AgentCreationReceipt{CallerID: request.CallerID, RequestID: request.RequestID, Fingerprint: request.Fingerprint, AgentID: copy.ID, OwnerID: copy.OwnerUserID}
	}
	result := copy
	return &result, true, nil
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
