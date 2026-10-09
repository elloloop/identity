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
//   - owner_user_id and pending_owner_user_id are writable through
//     UpdateUser (an orphan's reassignment, a transfer offer), and
//     PendingOwnerUserID narrows to the agents offered to one person;
//   - SettleAgentTransfer applies an answer only to the offer it names:
//     accepting moves the owner, declining keeps it, and both clear the
//     offer; a stale or absent offer, or a person, changes nothing, and
//     naming no agent or no pending owner is an error;
//   - ApplyAccountMerge refuses an agent on either side, re-points the
//     retired account's agents to the survivor, and re-points offers made to
//     the retired account (clearing one the survivor would make to itself).
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

		t.Run("PendingOwnerRoundTripAndFilter", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			alice := newPerson(t, ctx, r, "alice-pending@example.com")
			bob := newPerson(t, ctx, r, "bob-pending@example.com")
			offered := newAgent(t, ctx, r, alice, "Offered")
			newAgent(t, ctx, r, alice, "Kept")

			if err := r.UpdateUser(ctx, offered, map[string]any{"pending_owner_user_id": bob}); err != nil {
				t.Fatalf("UpdateUser(pending_owner_user_id): %v", err)
			}
			got, err := r.GetUser(ctx, offered)
			if err != nil || got == nil || got.PendingOwnerUserID != bob || got.OwnerUserID != alice {
				t.Fatalf("after offer = (%#v, %v), want owner %q pending %q", got, err, alice, bob)
			}
			if p, _ := r.GetUser(ctx, bob); p == nil || p.PendingOwnerUserID != "" {
				t.Fatalf("person reads back a pending owner: %#v", p)
			}
			for _, c := range []struct {
				name   string
				filter service.UserListFilter
				want   []string
			}{
				{"pending_bob", service.UserListFilter{IncludeAgents: true, PendingOwnerUserID: bob}, sorted(offered)},
				{"pending_alice", service.UserListFilter{IncludeAgents: true, PendingOwnerUserID: alice}, nil},
			} {
				list, err := r.ListUsers(ctx, c.filter)
				if err != nil {
					t.Fatalf("%s: ListUsers: %v", c.name, err)
				}
				if !equal(ids(list), c.want) {
					t.Errorf("%s: ListUsers = %v, want %v", c.name, ids(list), c.want)
				}
				if n, err := r.CountUsers(ctx, c.filter); err != nil || n != len(c.want) {
					t.Errorf("%s: CountUsers = %d, %v, want %d", c.name, n, err, len(c.want))
				}
			}
		})

		t.Run("SettleAgentTransfer", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			alice := newPerson(t, ctx, r, "alice-settle@example.com")
			bob := newPerson(t, ctx, r, "bob-settle@example.com")
			carol := newPerson(t, ctx, r, "carol-settle@example.com")
			offer := func(t *testing.T, agent, to string) {
				t.Helper()
				if err := r.UpdateUser(ctx, agent, map[string]any{"pending_owner_user_id": to}); err != nil {
					t.Fatal(err)
				}
			}
			expect := func(t *testing.T, agent, owner, pending string) {
				t.Helper()
				got, err := r.GetUser(ctx, agent)
				if err != nil || got == nil || got.OwnerUserID != owner || got.PendingOwnerUserID != pending {
					t.Fatalf("agent = (%#v, %v), want owner %q pending %q", got, err, owner, pending)
				}
			}
			settle := func(t *testing.T, agent, pending string, accept, want bool) {
				t.Helper()
				ok, err := r.SettleAgentTransfer(ctx, agent, pending, accept, 5000)
				if err != nil || ok != want {
					t.Fatalf("SettleAgentTransfer(%s, %s, %v) = (%v, %v), want %v", agent, pending, accept, ok, err, want)
				}
			}

			accepted := newAgent(t, ctx, r, alice, "Accepted")
			offer(t, accepted, bob)
			settle(t, accepted, carol, true, false) // names a stale offer
			expect(t, accepted, alice, bob)
			settle(t, accepted, bob, true, true)
			expect(t, accepted, bob, "")
			if got, _ := r.GetUser(ctx, accepted); got.UpdatedAt.UnixMilli() != 5000 {
				t.Errorf("updated_at = %d, want 5000", got.UpdatedAt.UnixMilli())
			}
			settle(t, accepted, bob, true, false) // already answered

			declined := newAgent(t, ctx, r, alice, "Declined")
			offer(t, declined, bob)
			settle(t, declined, bob, false, true)
			expect(t, declined, alice, "")

			never := newAgent(t, ctx, r, alice, "Never offered")
			if _, err := r.SettleAgentTransfer(ctx, never, "", true, 5000); err == nil {
				t.Fatal("SettleAgentTransfer with no pending owner named: want an error")
			}
			settle(t, never, bob, true, false)
			expect(t, never, alice, "")

			settle(t, bob, alice, true, false) // a person is never settled
			settle(t, "no-such-agent", bob, true, false)
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
			third := newPerson(t, ctx, r, "merge-third@example.com")
			offeredToOther := newAgent(t, ctx, r, third, "Offered to the retired account")
			for _, a := range []string{offeredToOther, bystander} {
				if err := r.UpdateUser(ctx, a, map[string]any{"pending_owner_user_id": other}); err != nil {
					t.Fatal(err)
				}
			}

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
			if a, _ := r.GetUser(ctx, offeredToOther); a == nil || a.PendingOwnerUserID != survivor || a.OwnerUserID != third {
				t.Fatalf("an offer to the retired account = %#v, want it re-pointed at the survivor", a)
			}
			if a, _ := r.GetUser(ctx, bystander); a == nil || a.PendingOwnerUserID != "" {
				t.Fatalf("an offer the survivor would make to itself = %#v, want it cleared", a)
			}
		})
	})
}
