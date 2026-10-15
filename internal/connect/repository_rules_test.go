package connect

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

func TestFakeRepositoryMergeMovesAgentOwnershipAndOffers(t *testing.T) {
	r := newFakeRepo()
	r.users["survivor"] = &service.User{ID: "survivor", Status: service.StatusActive}
	r.users["retired"] = &service.User{ID: "retired", Status: service.StatusActive}
	for _, u := range []*service.User{
		{ID: "owned", Kind: service.UserKindAgent, OwnerUserID: "retired"},
		{ID: "self-offer", Kind: service.UserKindAgent, OwnerUserID: "retired", PendingOwnerUserID: "survivor"},
		{ID: "incoming", Kind: service.UserKindAgent, OwnerUserID: "third", PendingOwnerUserID: "retired"},
		{ID: "survivor-offer", Kind: service.UserKindAgent, OwnerUserID: "survivor", PendingOwnerUserID: "retired"},
	} {
		r.users[u.ID] = u
	}
	require.NoError(t, r.ApplyAccountMerge(context.Background(), service.AccountMerge{SurvivorID: "survivor", OtherID: "retired", AtMs: 1234}))
	for _, tc := range []struct{ id, owner, pending string }{
		{"owned", "survivor", ""},
		{"self-offer", "survivor", ""},
		{"incoming", "third", "survivor"},
		{"survivor-offer", "survivor", ""},
	} {
		u, err := r.GetUser(context.Background(), tc.id)
		require.NoError(t, err)
		require.Equal(t, tc.owner, u.OwnerUserID, tc.id)
		require.Equal(t, tc.pending, u.PendingOwnerUserID, tc.id)
	}
}
