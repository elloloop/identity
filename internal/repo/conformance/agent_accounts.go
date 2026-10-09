package conformance

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runAgentAccountsConformance pins the storage semantics agent accounts
// depend on, which every driver must share:
//
//   - kind and owner_user_id round-trip, and a user created without a kind
//     reads back as a person;
//   - ListUsers and CountUsers leave agents out unless IncludeAgents is set,
//     and OwnerUserID narrows to one owner's agents (so the per-owner cap
//     and the owner's access cut-off see the same rows);
//   - owner_user_id is writable through UpdateUser (a transfer);
//   - ApplyAccountMerge refuses an agent on either side and re-points the
//     retired account's agents to the survivor.
func runAgentAccountsConformance(t *testing.T, driver Driver) {
	t.Helper()

	newPerson := func(t *testing.T, ctx context.Context, r service.Repository, email string) string {
		t.Helper()
		id, err := r.CreateUser(ctx, &service.User{Status: "active", Role: "member", Email: email})
		if err != nil {
			t.Fatalf("CreateUser(person): %v", err)
		}
		return id
	}
	newAgent := func(t *testing.T, ctx context.Context, r service.Repository, ownerID, name string) string {
		t.Helper()
		id, err := r.CreateUser(ctx, &service.User{
			Status: "active", Role: "member", Name: name,
			Kind: service.UserKindAgent, OwnerUserID: ownerID,
		})
		if err != nil {
			t.Fatalf("CreateUser(agent): %v", err)
		}
		return id
	}
	ids := func(us []*service.User) []string {
		out := make([]string, 0, len(us))
		for _, u := range us {
			out = append(out, u.ID)
		}
		sort.Strings(out)
		return out
	}
	sorted := func(s ...string) []string {
		sort.Strings(s)
		return s
	}
	equal := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	t.Run(driver.Name+"/AgentAccounts", func(t *testing.T) {
		t.Run("KindAndOwnerRoundTrip", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			owner := newPerson(t, ctx, r, "agent-owner@example.com")
			agent := newAgent(t, ctx, r, owner, "Helper")

			p, err := r.GetUser(ctx, owner)
			if err != nil || p == nil {
				t.Fatalf("GetUser(person) = (%#v, %v)", p, err)
			}
			if p.Kind != service.UserKindPerson || p.OwnerUserID != "" || p.IsAgent() {
				t.Fatalf("person reads back kind=%q owner=%q, want person and no owner", p.Kind, p.OwnerUserID)
			}
			a, err := r.GetUser(ctx, agent)
			if err != nil || a == nil {
				t.Fatalf("GetUser(agent) = (%#v, %v)", a, err)
			}
			if !a.IsAgent() || a.OwnerUserID != owner || a.Name != "Helper" {
				t.Fatalf("agent reads back kind=%q owner=%q name=%q", a.Kind, a.OwnerUserID, a.Name)
			}
		})

		t.Run("ListAndCountExcludeAgentsByDefault", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			alice := newPerson(t, ctx, r, "alice-agents@example.com")
			bob := newPerson(t, ctx, r, "bob-agents@example.com")
			a1 := newAgent(t, ctx, r, alice, "A1")
			a2 := newAgent(t, ctx, r, alice, "A2")
			b1 := newAgent(t, ctx, r, bob, "B1")

			cases := []struct {
				name   string
				filter service.UserListFilter
				want   []string
			}{
				{"default", service.UserListFilter{}, sorted(alice, bob)},
				{"include_agents", service.UserListFilter{IncludeAgents: true}, sorted(alice, bob, a1, a2, b1)},
				{"owner_alice", service.UserListFilter{IncludeAgents: true, OwnerUserID: alice}, sorted(a1, a2)},
				{"owner_bob", service.UserListFilter{IncludeAgents: true, OwnerUserID: bob}, sorted(b1)},
				{"owner_without_include", service.UserListFilter{OwnerUserID: alice}, nil},
				{"owner_unknown", service.UserListFilter{IncludeAgents: true, OwnerUserID: "no-such-owner"}, nil},
			}
			for _, c := range cases {
				got, err := r.ListUsers(ctx, c.filter)
				if err != nil {
					t.Fatalf("%s: ListUsers: %v", c.name, err)
				}
				if !equal(ids(got), c.want) {
					t.Errorf("%s: ListUsers = %v, want %v", c.name, ids(got), c.want)
				}
				n, err := r.CountUsers(ctx, c.filter)
				if err != nil {
					t.Fatalf("%s: CountUsers: %v", c.name, err)
				}
				if n != len(c.want) {
					t.Errorf("%s: CountUsers = %d, want %d", c.name, n, len(c.want))
				}
			}
		})

		t.Run("OwnerIsWritable", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			alice := newPerson(t, ctx, r, "alice-transfer@example.com")
			bob := newPerson(t, ctx, r, "bob-transfer@example.com")
			agent := newAgent(t, ctx, r, alice, "Mover")

			if err := r.UpdateUser(ctx, agent, map[string]any{"owner_user_id": bob}); err != nil {
				t.Fatalf("UpdateUser(owner_user_id): %v", err)
			}
			got, err := r.GetUser(ctx, agent)
			if err != nil || got == nil || got.OwnerUserID != bob || !got.IsAgent() {
				t.Fatalf("after transfer = (%#v, %v), want an agent owned by %q", got, err, bob)
			}
			if n, _ := r.CountUsers(ctx, service.UserListFilter{IncludeAgents: true, OwnerUserID: alice}); n != 0 {
				t.Errorf("previous owner still counts %d agents", n)
			}
		})

		t.Run("MergeRefusesAgentsAndMovesThemToSurvivor", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			survivor := newPerson(t, ctx, r, "merge-survivor@example.com")
			other, err := r.CreateUser(ctx, &service.User{Status: "active", Role: "member", Username: "merge-other"})
			if err != nil {
				t.Fatal(err)
			}
			agent := newAgent(t, ctx, r, other, "Follows")
			bystander := newAgent(t, ctx, r, survivor, "Stays")

			for _, m := range []service.AccountMerge{
				{SurvivorID: survivor, OtherID: agent, AtMs: 1000},
				{SurvivorID: agent, OtherID: other, AtMs: 1000},
			} {
				if err := r.ApplyAccountMerge(ctx, m); !errors.Is(err, service.ErrMergeConflict) {
					t.Fatalf("ApplyAccountMerge(%+v) err = %v, want ErrMergeConflict", m, err)
				}
			}
			if got, _ := r.GetUser(ctx, agent); got == nil || got.MergedIntoUserID != "" || got.OwnerUserID != other {
				t.Fatalf("a refused merge changed the agent: %#v", got)
			}

			if err := r.ApplyAccountMerge(ctx, service.AccountMerge{SurvivorID: survivor, OtherID: other, MoveUsername: true, AtMs: 2000}); err != nil {
				t.Fatalf("ApplyAccountMerge: %v", err)
			}
			got, err := r.ListUsers(ctx, service.UserListFilter{IncludeAgents: true, OwnerUserID: survivor})
			if err != nil {
				t.Fatalf("ListUsers: %v", err)
			}
			if want := sorted(agent, bystander); !equal(ids(got), want) {
				t.Fatalf("survivor owns %v after merge, want %v", ids(got), want)
			}
		})
	})
}
