package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUserListFilterMatches(t *testing.T) {
	person := &User{Email: "Person@example.test", ExternalID: "directory-person"}
	agent := &User{Kind: UserKindAgent, OwnerUserID: "owner", PendingOwnerUserID: "recipient"}
	for _, tc := range []struct {
		name   string
		filter UserListFilter
		user   *User
		want   bool
	}{
		{"missing", UserListFilter{}, nil, false},
		{"person default", UserListFilter{}, person, true},
		{"anonymous default", UserListFilter{}, &User{IsAnonymous: true}, false},
		{"anonymous included", UserListFilter{IncludeAnonymous: true}, &User{IsAnonymous: true}, true},
		{"agent default", UserListFilter{}, agent, false},
		{"agent included", UserListFilter{IncludeAgents: true}, agent, true},
		{"email folded", UserListFilter{Email: "PERSON@EXAMPLE.TEST"}, person, true},
		{"email mismatch", UserListFilter{Email: "other@example.test"}, person, false},
		{"external exact", UserListFilter{ExternalID: "directory-person"}, person, true},
		{"external case sensitive", UserListFilter{ExternalID: "DIRECTORY-PERSON"}, person, false},
		{"owner still excludes agent", UserListFilter{OwnerUserID: "owner"}, agent, false},
		{"owner", UserListFilter{IncludeAgents: true, OwnerUserID: "owner"}, agent, true},
		{"different owner", UserListFilter{IncludeAgents: true, OwnerUserID: "other"}, agent, false},
		{"pending", UserListFilter{IncludeAgents: true, PendingOwnerUserID: "recipient"}, agent, true},
		{"different pending", UserListFilter{IncludeAgents: true, PendingOwnerUserID: "other"}, agent, false},
		{"combined predicates", UserListFilter{IncludeAgents: true, OwnerUserID: "owner", PendingOwnerUserID: "other"}, agent, false},
		{"pagination ignored", UserListFilter{Offset: 99, Limit: 1}, person, true},
	} {
		t.Run(tc.name, func(t *testing.T) { require.Equal(t, tc.want, tc.filter.Matches(tc.user)) })
	}
}

func TestUserAgentOwnershipRules(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		user                 *User
		owner, next, pending string
		want                 bool
	}{
		{"missing", nil, "owner", "next", "", false},
		{"person", &User{OwnerUserID: "owner"}, "owner", "next", "", false},
		{"stale owner", &User{Kind: UserKindAgent, OwnerUserID: "owner"}, "stale", "next", "", false},
		{"empty expected", &User{Kind: UserKindAgent, OwnerUserID: "owner"}, "", "next", "", false},
		{"empty next", &User{Kind: UserKindAgent, OwnerUserID: "owner"}, "owner", "", "", false},
		{"offer", &User{Kind: UserKindAgent, OwnerUserID: "owner"}, "owner", "owner", "recipient", true},
		{"reassign", &User{Kind: UserKindAgent, OwnerUserID: "owner", PendingOwnerUserID: "recipient"}, "owner", "next", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var before User
			if tc.user != nil {
				before = *tc.user
			}
			require.Equal(t, tc.want, tc.user.SetAgentOwnership(tc.owner, tc.next, tc.pending, 1234))
			if tc.want {
				require.Equal(t, tc.next, tc.user.OwnerUserID)
				require.Equal(t, tc.pending, tc.user.PendingOwnerUserID)
				require.Equal(t, time.UnixMilli(1234), tc.user.UpdatedAt)
			} else if tc.user != nil {
				require.Equal(t, before, *tc.user)
			}
		})
	}
}

func TestUserAgentTransferRules(t *testing.T) {
	for _, tc := range []struct {
		name         string
		user         *User
		pending      string
		accept, want bool
	}{
		{"missing", nil, "recipient", true, false},
		{"person", &User{PendingOwnerUserID: "recipient"}, "recipient", true, false},
		{"no offer", &User{Kind: UserKindAgent, OwnerUserID: "owner"}, "", true, false},
		{"stale offer", &User{Kind: UserKindAgent, OwnerUserID: "owner", PendingOwnerUserID: "recipient"}, "stale", true, false},
		{"accept", &User{Kind: UserKindAgent, OwnerUserID: "owner", PendingOwnerUserID: "recipient"}, "recipient", true, true},
		{"decline", &User{Kind: UserKindAgent, OwnerUserID: "owner", PendingOwnerUserID: "recipient"}, "recipient", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var before User
			if tc.user != nil {
				before = *tc.user
			}
			require.Equal(t, tc.want, tc.user.SettleAgentTransfer(tc.pending, tc.accept, 1234))
			if tc.want {
				owner := "owner"
				if tc.accept {
					owner = "recipient"
				}
				require.Equal(t, owner, tc.user.OwnerUserID)
				require.Empty(t, tc.user.PendingOwnerUserID)
				require.Equal(t, time.UnixMilli(1234), tc.user.UpdatedAt)
				require.False(t, tc.user.SettleAgentTransfer(tc.pending, tc.accept, 5678))
				require.Equal(t, time.UnixMilli(1234), tc.user.UpdatedAt)
			} else if tc.user != nil {
				require.Equal(t, before, *tc.user)
			}
		})
	}
}

func TestAccountMergeApplyToAgent(t *testing.T) {
	m := AccountMerge{SurvivorID: "survivor", OtherID: "retired"}
	m.ApplyToAgent(nil)
	for _, tc := range []struct{ owner, pending, wantOwner, wantPending string }{
		{"retired", "", "survivor", ""},
		{"retired", "survivor", "survivor", ""},
		{"retired", "retired", "survivor", ""},
		{"third", "retired", "third", "survivor"},
		{"survivor", "retired", "survivor", ""},
		{"third", "survivor", "third", "survivor"},
		{"retired", "fourth", "survivor", "fourth"},
		{"third", "fourth", "third", "fourth"},
	} {
		u := &User{Kind: UserKindAgent, OwnerUserID: tc.owner, PendingOwnerUserID: tc.pending}
		m.ApplyToAgent(u)
		require.Equal(t, tc.wantOwner, u.OwnerUserID)
		require.Equal(t, tc.wantPending, u.PendingOwnerUserID)
	}
}
