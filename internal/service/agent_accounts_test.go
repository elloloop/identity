package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/events"
	"github.com/elloloop/identity/pkg/idv"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/secretcrypto"
	"github.com/elloloop/identity/pkg/totp"
)

// ── Fixture ────────────────────────────────────────────────────────────

// agentFixture is a service with two people (an owner and a stranger), a
// project admin, and the purger and publisher wired, so every agent
// operation can be driven and observed.
type agentFixture struct {
	svc      *AuthService
	repo     *fakeRepo
	writer   *recordingAuditWriter
	purger   *fakePurger
	pub      *capturePublisher
	owner    *User
	stranger *User
	admin    *User
}

func newAgentFixture(t *testing.T) *agentFixture {
	t.Helper()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	purger := &fakePurger{repo: repo}
	pub := &capturePublisher{}
	svc := newTestAuthServiceWithAudit(t, repo, writer).WithAccountPurger(purger).WithEventPublisher(pub)
	svc.cfg.AgentsEnabled = true
	f := &agentFixture{
		svc: svc, repo: repo, writer: writer, purger: purger, pub: pub,
		owner:    seedPerson(repo, "owner@example.com"),
		stranger: seedPerson(repo, "stranger@example.com"),
		admin:    seedPerson(repo, "admin@example.com"),
	}
	repo.mu.Lock()
	f.admin.Role = "admin"
	repo.mu.Unlock()
	return f
}

// seedPerson seeds an active person account.
func seedPerson(repo *fakeRepo, email string) *User {
	u := seedUser(repo, email, "", StatusActive)
	repo.mu.Lock()
	u.Kind = UserKindPerson
	repo.mu.Unlock()
	return u
}

// seedAgent seeds an active agent account owned by ownerID.
func seedAgent(repo *fakeRepo, ownerID string) *User {
	u := seedUser(repo, "", "", StatusActive)
	repo.mu.Lock()
	u.Kind, u.OwnerUserID, u.Name = UserKindAgent, ownerID, "Helper"
	repo.mu.Unlock()
	return u
}

// forceAgent turns a seeded account into an agent owned by ownerID while
// keeping whatever credential it holds: the corrupt row the sign-in
// refusal exists for, since no API path attaches a credential to an agent.
func forceAgent(repo *fakeRepo, u *User, ownerID string) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	stored := repo.users[u.ID]
	stored.Kind, stored.OwnerUserID = UserKindAgent, ownerID
}

func (f *agentFixture) setStatus(id, status string) {
	f.repo.mu.Lock()
	defer f.repo.mu.Unlock()
	f.repo.users[id].Status = status
}

// liveSessions reports whether userID holds a live session or a refresh
// token.
func liveSessions(repo *fakeRepo, userID string) bool {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	for _, s := range repo.sessions {
		if s.UserID == userID && s.RevokedAtMs == 0 {
			return true
		}
	}
	for _, rt := range repo.refreshTokens {
		if rt.UserID == userID {
			return true
		}
	}
	return false
}

// ── Kind and claim ─────────────────────────────────────────────────────

func TestUser_IsAgent(t *testing.T) {
	var nilUser *User
	assert.False(t, nilUser.IsAgent())
	assert.False(t, (&User{}).IsAgent())
	assert.False(t, (&User{Kind: UserKindPerson}).IsAgent())
	assert.True(t, (&User{Kind: UserKindAgent}).IsAgent())
}

// ── CreateAgent ────────────────────────────────────────────────────────

func TestCreateAgent_OwnedByCaller(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()

	agent, err := f.svc.CreateAgent(ctx, f.owner.ID, "  Research helper ", "https://cdn.example.com/a.png", "", "203.0.113.1", "ua")
	require.NoError(t, err)
	assert.True(t, agent.IsAgent())
	assert.Equal(t, f.owner.ID, agent.OwnerUserID)
	assert.Equal(t, "Research helper", agent.Name)
	assert.Equal(t, "https://cdn.example.com/a.png", agent.AvatarURL)
	assert.Equal(t, "member", agent.Role)
	assert.Equal(t, StatusActive, agent.Status)

	stored, err := f.repo.GetUser(ctx, agent.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.True(t, stored.IsAgent())
	assert.Empty(t, stored.Email, "an agent holds no address")
	assert.Empty(t, stored.Username, "an agent holds no username")
	assert.Empty(t, stored.PasswordHash, "an agent holds no password")

	assert.Equal(t, 1, f.writer.countByEventTypeActorTarget(string(audit.EventAgentCreated), f.owner.ID, agent.ID))
	evs := f.pub.all()
	require.Len(t, evs, 1)
	assert.Equal(t, events.EventUserCreated, evs[0].Type)
	assert.Equal(t, UserKindAgent, evs[0].User.Kind)
	assert.Equal(t, f.owner.ID, evs[0].User.OwnerUserID)
}

func TestCreateAgent_Validation(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	for _, tc := range []struct{ name, agentName, avatar string }{
		{"empty_name", "  ", ""},
		{"long_name", strings.Repeat("é", agentNameMaxRunes+1), ""},
		{"relative_avatar", "A", "/a.png"},
		{"http_avatar", "A", "http://example.com/a.png"},
		{"script_avatar", "A", "javascript:alert(1)"},
		{"long_avatar", "A", "https://example.com/" + strings.Repeat("a", agentAvatarURLMaxBytes)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.svc.CreateAgent(ctx, f.owner.ID, tc.agentName, tc.avatar, "", "", "")
			require.ErrorIs(t, err, ErrInvalidArgument)
		})
	}
	n, err := f.repo.CountUsers(ctx, UserListFilter{IncludeAgents: true, OwnerUserID: f.owner.ID})
	require.NoError(t, err)
	assert.Zero(t, n, "a refused create writes nothing")
}

func TestCreateAgent_ForAnotherOwner(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()

	_, err := f.svc.CreateAgent(ctx, f.stranger.ID, "A", "", f.owner.ID, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied, "only an admin names another owner")

	agent, err := f.svc.CreateAgent(ctx, f.admin.ID, "A", "", f.owner.ID, "", "")
	require.NoError(t, err)
	assert.Equal(t, f.owner.ID, agent.OwnerUserID)

	// The named owner must be an active person.
	f.setStatus(f.stranger.ID, StatusDeactivated)
	for _, owner := range []string{agent.ID, f.stranger.ID, "no-such-user"} {
		_, err := f.svc.CreateAgent(ctx, f.admin.ID, "A", "", owner, "", "")
		require.ErrorIs(t, err, ErrInvalidArgument, owner)
	}
}

func TestCreateAgent_RefusedCallers(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)
	anon := seedUser(f.repo, "", "", StatusActive)
	anon.IsAnonymous = true

	_, err := f.svc.CreateAgent(ctx, "", "A", "", "", "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
	for _, caller := range []string{agent.ID, anon.ID, "no-such-user"} {
		_, err := f.svc.CreateAgent(ctx, caller, "A", "", "", "", "")
		require.ErrorIs(t, err, ErrPermissionDenied, caller)
	}
	f.setStatus(f.stranger.ID, StatusDeactivated)
	_, err = f.svc.CreateAgent(ctx, f.stranger.ID, "A", "", "", "", "")
	require.ErrorIs(t, err, ErrAccountNotActive)
}

func TestCreateAgent_PerOwnerCap(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	f.svc.cfg.AgentsMaxPerOwner = 2

	for range 2 {
		_, err := f.svc.CreateAgent(ctx, f.owner.ID, "A", "", "", "", "")
		require.NoError(t, err)
	}
	_, err := f.svc.CreateAgent(ctx, f.owner.ID, "A", "", "", "", "")
	require.ErrorIs(t, err, ErrAgentLimitReached)
	assert.Equal(t, 1, f.writer.countByEventTypeAndDetail(string(audit.EventAgentCreated), "step", "limit_reached"))

	// Another owner's capacity is their own.
	_, err = f.svc.CreateAgent(ctx, f.stranger.ID, "A", "", "", "", "")
	require.NoError(t, err)
}

// With the switch off (the default), every agent operation answers
// ErrAgentsDisabled before reading anything, whoever calls.
func TestAgentOps_DisabledByDefault(t *testing.T) {
	f := newAgentFixture(t)
	f.svc.cfg.AgentsEnabled = false
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)

	_, err := f.svc.CreateAgent(ctx, f.owner.ID, "A", "", "", "", "")
	require.ErrorIs(t, err, ErrAgentsDisabled)
	_, err = f.svc.ListAgents(ctx, f.admin.ID, f.owner.ID)
	require.ErrorIs(t, err, ErrAgentsDisabled)
	for _, op := range allAgentOps() {
		for _, caller := range []string{f.owner.ID, f.admin.ID, ""} {
			require.ErrorIs(t, op.call(f, caller, agent.ID), ErrAgentsDisabled, op.name)
		}
	}
	stored, _ := f.repo.GetUser(ctx, agent.ID)
	require.NotNil(t, stored)
	assert.Equal(t, StatusActive, stored.Status)
	assert.Empty(t, f.purger.calls)
}

// ── The guard: owner or admin, uniform refusal ─────────────────────────

type agentOpCase struct {
	name string
	call func(f *agentFixture, caller, agentID string) error
}

func allAgentOps() []agentOpCase {
	ctx := context.Background()
	return []agentOpCase{
		{"update", func(f *agentFixture, c, a string) error {
			_, err := f.svc.UpdateAgent(ctx, c, a, "Renamed", "", "", "")
			return err
		}},
		{"transfer", func(f *agentFixture, c, a string) error {
			_, err := f.svc.TransferAgent(ctx, c, a, f.admin.ID, "", "")
			return err
		}},
		{"cancel_transfer", func(f *agentFixture, c, a string) error {
			_, err := f.svc.CancelAgentTransfer(ctx, c, a, "", "")
			return err
		}},
		{"deactivate", func(f *agentFixture, c, a string) error {
			return f.svc.DeactivateAgent(ctx, c, a, "", "", "")
		}},
		{"reactivate", func(f *agentFixture, c, a string) error {
			return f.svc.ReactivateAgent(ctx, c, a, "", "")
		}},
		{"delete", func(f *agentFixture, c, a string) error {
			return f.svc.DeleteAgent(ctx, c, a, "", "")
		}},
	}
}

// A caller who is neither the owner nor an admin gets the identical refusal
// whether the id names that agent, a person, or nothing, and the refusal
// changes nothing.
func TestAgentOps_StrangerRefusedUniformly(t *testing.T) {
	for _, op := range allAgentOps() {
		t.Run(op.name, func(t *testing.T) {
			f := newAgentFixture(t)
			agent := seedAgent(f.repo, f.owner.ID)
			var msgs []string
			for _, target := range []string{agent.ID, f.owner.ID, "no-such-user"} {
				err := op.call(f, f.stranger.ID, target)
				require.ErrorIs(t, err, ErrPermissionDenied, target)
				msgs = append(msgs, err.Error())
			}
			assert.Equal(t, msgs[0], msgs[1])
			assert.Equal(t, msgs[0], msgs[2])

			stored, _ := f.repo.GetUser(context.Background(), agent.ID)
			require.NotNil(t, stored)
			assert.Equal(t, "Helper", stored.Name)
			assert.Equal(t, f.owner.ID, stored.OwnerUserID)
			assert.Equal(t, StatusActive, stored.Status)
			assert.Empty(t, f.purger.calls)
		})
	}
}

func TestAgentOps_OwnerAndAdminAdmitted(t *testing.T) {
	for _, op := range allAgentOps() {
		for _, who := range []string{"owner", "admin"} {
			t.Run(op.name+"/"+who, func(t *testing.T) {
				f := newAgentFixture(t)
				agent := seedAgent(f.repo, f.owner.ID)
				caller := f.owner.ID
				if who == "admin" {
					caller = f.admin.ID
				}
				require.NoError(t, op.call(f, caller, agent.ID))
			})
		}
	}
}

// An agent may not manage agents, its own sibling included.
func TestAgentOps_AgentCallerRefused(t *testing.T) {
	for _, op := range allAgentOps() {
		t.Run(op.name, func(t *testing.T) {
			f := newAgentFixture(t)
			agent := seedAgent(f.repo, f.owner.ID)
			sibling := seedAgent(f.repo, f.owner.ID)
			require.ErrorIs(t, op.call(f, sibling.ID, agent.ID), ErrPermissionDenied)
		})
	}
}

func TestAgentOps_InputErrors(t *testing.T) {
	for _, op := range allAgentOps() {
		t.Run(op.name, func(t *testing.T) {
			f := newAgentFixture(t)
			require.ErrorIs(t, op.call(f, "", "x"), ErrUnauthenticated)
			require.ErrorIs(t, op.call(f, f.owner.ID, "  "), ErrInvalidArgument)
		})
	}
}

// ── ListAgents ─────────────────────────────────────────────────────────

func TestListAgents(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	a1 := seedAgent(f.repo, f.owner.ID)
	a2 := seedAgent(f.repo, f.owner.ID)
	seedAgent(f.repo, f.stranger.ID)

	got, err := f.svc.ListAgents(ctx, f.owner.ID, "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{a1.ID, a2.ID}, idsOf(got))

	_, err = f.svc.ListAgents(ctx, f.stranger.ID, f.owner.ID)
	require.ErrorIs(t, err, ErrPermissionDenied)

	got, err = f.svc.ListAgents(ctx, f.admin.ID, f.owner.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{a1.ID, a2.ID}, idsOf(got))

	// An admin finds the agents a deleted owner left behind.
	require.NoError(t, f.repo.DeleteUser(ctx, f.owner.ID))
	got, err = f.svc.ListAgents(ctx, f.admin.ID, f.owner.ID)
	require.NoError(t, err)
	assert.Len(t, got, 2)

	_, err = f.svc.ListAgents(ctx, "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
	_, err = f.svc.ListAgents(ctx, a1.ID, "")
	require.ErrorIs(t, err, ErrPermissionDenied)
}

// Listing another owner's agents is recorded, and so is a refusal; listing
// one's own is not.
func TestListAgents_Audited(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	seedAgent(f.repo, f.owner.ID)

	_, err := f.svc.ListAgents(ctx, f.owner.ID, "")
	require.NoError(t, err)
	assert.Zero(t, f.writer.countByEventType(string(audit.EventAgentsListed)))

	_, err = f.svc.ListAgents(ctx, f.admin.ID, f.owner.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, f.writer.countByEventTypeActorTarget(string(audit.EventAgentsListed), f.admin.ID, f.owner.ID))

	_, err = f.svc.ListAgents(ctx, f.stranger.ID, f.owner.ID)
	require.ErrorIs(t, err, ErrPermissionDenied)
	assert.Equal(t, 1, f.writer.countByEventTypeAndDetail(string(audit.EventAgentsListed), "step", "not_permitted"))
}

// An owner can hold more agents than one page (a merge can carry them past
// the cap); listing and revoking reach every one.
func TestListAgents_PagesThroughEveryAgent(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	n := MaxUserListLimit + 1
	for range n {
		seedAgent(f.repo, f.owner.ID)
	}
	got, err := f.svc.ListAgents(ctx, f.owner.ID, "")
	require.NoError(t, err)
	assert.Len(t, got, n)

	last := got[len(got)-1]
	seedChildSession(t, f.repo, last.ID)
	require.NoError(t, RevokeUserAccess(ctx, f.repo, f.owner.ID, time.Now().UnixMilli()))
	assert.False(t, liveSessions(f.repo, last.ID), "the agent past the first page is cut off too")
}

func idsOf(us []*User) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.ID)
	}
	return out
}

// ── UpdateAgent ────────────────────────────────────────────────────────

func TestUpdateAgent_ReplacesNameAndAvatar(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)
	f.repo.mu.Lock()
	f.repo.users[agent.ID].AvatarURL = "https://cdn.example.com/old.png"
	f.repo.mu.Unlock()

	got, err := f.svc.UpdateAgent(ctx, f.owner.ID, agent.ID, "Renamed", "", "", "")
	require.NoError(t, err)
	assert.Equal(t, "Renamed", got.Name)
	assert.Empty(t, got.AvatarURL, "both fields are replaced, so an empty avatar clears it")
	stored, _ := f.repo.GetUser(ctx, agent.ID)
	assert.Equal(t, "Renamed", stored.Name)
	assert.Empty(t, stored.AvatarURL)

	_, err = f.svc.UpdateAgent(ctx, f.owner.ID, agent.ID, "", "", "", "")
	require.ErrorIs(t, err, ErrInvalidArgument)
	assert.Equal(t, 1, f.writer.countByEventTypeActorTarget(string(audit.EventAgentUpdated), f.owner.ID, agent.ID))
}

// ── TransferAgent ──────────────────────────────────────────────────────

// A transfer is an offer: the agent stays with its owner, usable under
// their standing, until the recipient accepts.
func TestTransferAgent_IsAnOffer(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)
	seedChildSession(t, f.repo, agent.ID)

	got, err := f.svc.TransferAgent(ctx, f.owner.ID, agent.ID, f.stranger.ID, "", "")
	require.NoError(t, err)
	assert.Equal(t, f.owner.ID, got.OwnerUserID)
	assert.Equal(t, f.stranger.ID, got.PendingOwnerUserID)
	stored, _ := f.repo.GetUser(ctx, agent.ID)
	assert.Equal(t, f.owner.ID, stored.OwnerUserID, "ownership waits for the recipient")
	assert.Equal(t, f.stranger.ID, stored.PendingOwnerUserID)
	assert.True(t, liveSessions(f.repo, agent.ID), "an offer leaves the agent's sessions alone")
	assert.Equal(t, 1, f.writer.countByEventTypeActorTarget(string(audit.EventAgentTransferRequested), f.owner.ID, agent.ID))
	assert.Zero(t, f.writer.countByEventTypeActorTarget(string(audit.EventAgentTransferred), f.owner.ID, agent.ID))

	// The owner still manages it; the recipient does not yet.
	_, err = f.svc.UpdateAgent(ctx, f.owner.ID, agent.ID, "Still mine", "", "", "")
	require.NoError(t, err)
	_, err = f.svc.UpdateAgent(ctx, f.stranger.ID, agent.ID, "Mine", "", "", "")
	require.ErrorIs(t, err, ErrPermissionDenied)

	// To the current owner: a no-op that leaves the offer standing.
	_, err = f.svc.TransferAgent(ctx, f.owner.ID, agent.ID, f.owner.ID, "", "")
	require.NoError(t, err)
	stored, _ = f.repo.GetUser(ctx, agent.ID)
	assert.Equal(t, f.stranger.ID, stored.PendingOwnerUserID)
}

func TestAcceptAgentTransfer(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)
	seedChildSession(t, f.repo, agent.ID)
	_, err := f.svc.TransferAgent(ctx, f.owner.ID, agent.ID, f.stranger.ID, "", "")
	require.NoError(t, err)

	incoming, err := f.svc.ListIncomingAgentTransfers(ctx, f.stranger.ID)
	require.NoError(t, err)
	require.Len(t, incoming, 1)
	assert.Equal(t, agent.ID, incoming[0].ID)

	got, err := f.svc.AcceptAgentTransfer(ctx, f.stranger.ID, agent.ID, "", "")
	require.NoError(t, err)
	assert.Equal(t, f.stranger.ID, got.OwnerUserID)
	assert.Empty(t, got.PendingOwnerUserID)
	stored, _ := f.repo.GetUser(ctx, agent.ID)
	assert.Equal(t, f.stranger.ID, stored.OwnerUserID)
	assert.Empty(t, stored.PendingOwnerUserID)
	assert.False(t, liveSessions(f.repo, agent.ID), "an accepted transfer ends the agent's sessions")
	assert.Equal(t, 1, f.writer.countByEventTypeActorTarget(string(audit.EventAgentTransferred), f.stranger.ID, agent.ID))

	incoming, err = f.svc.ListIncomingAgentTransfers(ctx, f.stranger.ID)
	require.NoError(t, err)
	assert.Empty(t, incoming)

	// The previous owner has lost it; accepting again is refused.
	_, err = f.svc.UpdateAgent(ctx, f.owner.ID, agent.ID, "Mine", "", "", "")
	require.ErrorIs(t, err, ErrPermissionDenied)
	_, err = f.svc.AcceptAgentTransfer(ctx, f.stranger.ID, agent.ID, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied)
}

// Only the recipient may answer an offer; everyone else, a project admin
// and the owner included, gets the uniform refusal, and nothing changes.
func TestAgentTransferAnswer_OnlyTheRecipient(t *testing.T) {
	answers := map[string]func(f *agentFixture, caller, agentID string) error{
		"accept": func(f *agentFixture, c, a string) error {
			_, err := f.svc.AcceptAgentTransfer(context.Background(), c, a, "", "")
			return err
		},
		"decline": func(f *agentFixture, c, a string) error {
			_, err := f.svc.DeclineAgentTransfer(context.Background(), c, a, "", "")
			return err
		},
	}
	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			f := newAgentFixture(t)
			ctx := context.Background()
			agent := seedAgent(f.repo, f.owner.ID)
			unoffered := seedAgent(f.repo, f.owner.ID)
			sibling := seedAgent(f.repo, f.owner.ID)
			_, err := f.svc.TransferAgent(ctx, f.owner.ID, agent.ID, f.stranger.ID, "", "")
			require.NoError(t, err)

			var msgs []string
			for _, tc := range []struct{ caller, target string }{
				{f.owner.ID, agent.ID},
				{f.admin.ID, agent.ID},
				{sibling.ID, agent.ID},
				{f.stranger.ID, unoffered.ID},
				{f.stranger.ID, f.owner.ID},
				{f.stranger.ID, "no-such-user"},
			} {
				err := answer(f, tc.caller, tc.target)
				require.ErrorIs(t, err, ErrPermissionDenied, tc)
				msgs = append(msgs, err.Error())
			}
			for _, m := range msgs[1:] {
				assert.Equal(t, msgs[0], m)
			}
			require.ErrorIs(t, answer(f, "", agent.ID), ErrUnauthenticated)
			require.ErrorIs(t, answer(f, f.stranger.ID, " "), ErrInvalidArgument)

			stored, _ := f.repo.GetUser(ctx, agent.ID)
			assert.Equal(t, f.owner.ID, stored.OwnerUserID)
			assert.Equal(t, f.stranger.ID, stored.PendingOwnerUserID)
		})
	}
}

func TestDeclineAgentTransfer(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)
	_, err := f.svc.TransferAgent(ctx, f.owner.ID, agent.ID, f.stranger.ID, "", "")
	require.NoError(t, err)

	got, err := f.svc.DeclineAgentTransfer(ctx, f.stranger.ID, agent.ID, "", "")
	require.NoError(t, err)
	assert.Equal(t, f.owner.ID, got.OwnerUserID)
	assert.Empty(t, got.PendingOwnerUserID)
	stored, _ := f.repo.GetUser(ctx, agent.ID)
	assert.Equal(t, f.owner.ID, stored.OwnerUserID)
	assert.Empty(t, stored.PendingOwnerUserID)
	assert.Equal(t, 1, f.writer.countByEventTypeActorTarget(string(audit.EventAgentTransferDeclined), f.stranger.ID, agent.ID))

	_, err = f.svc.AcceptAgentTransfer(ctx, f.stranger.ID, agent.ID, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied, "a declined offer cannot be accepted")
}

func TestCancelAgentTransfer(t *testing.T) {
	for _, who := range []string{"owner", "admin"} {
		t.Run(who, func(t *testing.T) {
			f := newAgentFixture(t)
			ctx := context.Background()
			agent := seedAgent(f.repo, f.owner.ID)
			_, err := f.svc.TransferAgent(ctx, f.owner.ID, agent.ID, f.stranger.ID, "", "")
			require.NoError(t, err)
			caller := f.owner.ID
			if who == "admin" {
				caller = f.admin.ID
			}

			got, err := f.svc.CancelAgentTransfer(ctx, caller, agent.ID, "", "")
			require.NoError(t, err)
			assert.Empty(t, got.PendingOwnerUserID)
			stored, _ := f.repo.GetUser(ctx, agent.ID)
			assert.Equal(t, f.owner.ID, stored.OwnerUserID)
			assert.Empty(t, stored.PendingOwnerUserID)
			assert.Equal(t, 1, f.writer.countByEventTypeActorTarget(string(audit.EventAgentTransferCancelled), caller, agent.ID))

			_, err = f.svc.AcceptAgentTransfer(ctx, f.stranger.ID, agent.ID, "", "")
			require.ErrorIs(t, err, ErrPermissionDenied, "a cancelled offer cannot be accepted")
			// Cancelling again: nothing pending, the agent comes back as it is.
			_, err = f.svc.CancelAgentTransfer(ctx, caller, agent.ID, "", "")
			require.NoError(t, err)
		})
	}
}

// A new offer replaces a pending one: the first recipient can no longer
// accept.
func TestTransferAgent_ReplacesAPendingOffer(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)
	_, err := f.svc.TransferAgent(ctx, f.owner.ID, agent.ID, f.stranger.ID, "", "")
	require.NoError(t, err)
	_, err = f.svc.TransferAgent(ctx, f.owner.ID, agent.ID, f.admin.ID, "", "")
	require.NoError(t, err)

	_, err = f.svc.AcceptAgentTransfer(ctx, f.stranger.ID, agent.ID, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied)
	got, err := f.svc.AcceptAgentTransfer(ctx, f.admin.ID, agent.ID, "", "")
	require.NoError(t, err)
	assert.Equal(t, f.admin.ID, got.OwnerUserID)
}

// An answer lands only on the offer it read: an offer withdrawn between the
// read and the write is refused, not applied.
func TestAcceptAgentTransfer_StaleOfferRefused(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)
	_, err := f.svc.TransferAgent(ctx, f.owner.ID, agent.ID, f.stranger.ID, "", "")
	require.NoError(t, err)
	stale, _ := f.repo.GetUser(ctx, agent.ID)
	staleCopy := *stale
	_, err = f.svc.CancelAgentTransfer(ctx, f.owner.ID, agent.ID, "", "")
	require.NoError(t, err)

	err = f.svc.settleAgentTransfer(ctx, agentOpTransfer, f.stranger.ID, &staleCopy, true, f.svc.nowMs(), "", "")
	require.ErrorIs(t, err, ErrPermissionDenied)
	stored, _ := f.repo.GetUser(ctx, agent.ID)
	assert.Equal(t, f.owner.ID, stored.OwnerUserID)
}

func TestTransferAgent_RecipientMustBeEligible(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)
	other := seedAgent(f.repo, f.owner.ID)
	inactive := seedPerson(f.repo, "inactive@example.com")
	f.setStatus(inactive.ID, StatusDeactivated)
	anon := seedUser(f.repo, "", "", StatusActive)
	anon.IsAnonymous = true
	merged := seedPerson(f.repo, "merged@example.com")
	merged.MergedIntoUserID = f.stranger.ID

	for _, to := range []string{other.ID, inactive.ID, anon.ID, merged.ID, "no-such-user"} {
		_, err := f.svc.TransferAgent(ctx, f.owner.ID, agent.ID, to, "", "")
		require.ErrorIs(t, err, ErrInvalidArgument, to)
	}
	_, err := f.svc.TransferAgent(ctx, f.owner.ID, agent.ID, " ", "", "")
	require.ErrorIs(t, err, ErrInvalidArgument)

	stored, _ := f.repo.GetUser(ctx, agent.ID)
	assert.Equal(t, f.owner.ID, stored.OwnerUserID, "a refused transfer changes nothing")
}

// The recipient's cap is checked when they accept, not when the offer is
// made: their count can change in between.
func TestAcceptAgentTransfer_RespectsRecipientCap(t *testing.T) {
	f := newAgentFixture(t)
	f.svc.cfg.AgentsMaxPerOwner = 1
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)
	held := seedAgent(f.repo, f.stranger.ID)

	_, err := f.svc.TransferAgent(ctx, f.owner.ID, agent.ID, f.stranger.ID, "", "")
	require.NoError(t, err, "the offer is not capped")
	_, err = f.svc.AcceptAgentTransfer(ctx, f.stranger.ID, agent.ID, "", "")
	require.ErrorIs(t, err, ErrAgentLimitReached)
	stored, _ := f.repo.GetUser(ctx, agent.ID)
	assert.Equal(t, f.owner.ID, stored.OwnerUserID)
	assert.Equal(t, f.stranger.ID, stored.PendingOwnerUserID, "a capped accept leaves the offer to retry")

	require.NoError(t, f.svc.DeleteAgent(ctx, f.stranger.ID, held.ID, "", ""))
	_, err = f.svc.AcceptAgentTransfer(ctx, f.stranger.ID, agent.ID, "", "")
	require.NoError(t, err)
}

// An orphan (its owner no longer exists) has nobody to hand it over, so a
// project admin's transfer takes effect at once, under the recipient's cap.
func TestTransferAgent_OrphanReassignedByAdmin(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)
	seedChildSession(t, f.repo, agent.ID)
	require.NoError(t, f.repo.DeleteUser(ctx, f.owner.ID))

	got, err := f.svc.TransferAgent(ctx, f.admin.ID, agent.ID, f.stranger.ID, "", "")
	require.NoError(t, err)
	assert.Equal(t, f.stranger.ID, got.OwnerUserID)
	assert.Empty(t, got.PendingOwnerUserID)
	stored, _ := f.repo.GetUser(ctx, agent.ID)
	assert.Equal(t, f.stranger.ID, stored.OwnerUserID)
	assert.Empty(t, stored.PendingOwnerUserID)
	assert.False(t, liveSessions(f.repo, agent.ID))
	assert.Equal(t, 1, f.writer.countByEventTypeActorTarget(string(audit.EventAgentTransferred), f.admin.ID, agent.ID))
	issueAgentTokens(t, f, stored)
}

func TestTransferAgent_OrphanRespectsRecipientCap(t *testing.T) {
	f := newAgentFixture(t)
	f.svc.cfg.AgentsMaxPerOwner = 1
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)
	seedAgent(f.repo, f.stranger.ID)
	require.NoError(t, f.repo.DeleteUser(ctx, f.owner.ID))

	_, err := f.svc.TransferAgent(ctx, f.admin.ID, agent.ID, f.stranger.ID, "", "")
	require.ErrorIs(t, err, ErrAgentLimitReached)
	stored, _ := f.repo.GetUser(ctx, agent.ID)
	assert.Equal(t, f.owner.ID, stored.OwnerUserID)
}

// An agent whose owner is suspended is not an orphan: the owner exists and
// may come back, so an admin's transfer is still an offer.
func TestTransferAgent_SuspendedOwnerIsNotAnOrphan(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)
	f.setStatus(f.owner.ID, StatusDeactivated)

	got, err := f.svc.TransferAgent(ctx, f.admin.ID, agent.ID, f.stranger.ID, "", "")
	require.NoError(t, err)
	assert.Equal(t, f.owner.ID, got.OwnerUserID)
	assert.Equal(t, f.stranger.ID, got.PendingOwnerUserID)
}

// A merge re-points the offers made to the merged-away account at the
// survivor, and clears one the survivor would make to itself.
func TestAccountMerge_RepointsPendingTransfers(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	toOther := seedAgent(f.repo, f.owner.ID)
	ownedBySurvivor := seedAgent(f.repo, f.admin.ID)
	_, err := f.svc.TransferAgent(ctx, f.owner.ID, toOther.ID, f.stranger.ID, "", "")
	require.NoError(t, err)
	_, err = f.svc.TransferAgent(ctx, f.admin.ID, ownedBySurvivor.ID, f.stranger.ID, "", "")
	require.NoError(t, err)

	require.NoError(t, f.repo.ApplyAccountMerge(ctx, AccountMerge{SurvivorID: f.admin.ID, OtherID: f.stranger.ID, AtMs: 1}))
	stored, _ := f.repo.GetUser(ctx, toOther.ID)
	assert.Equal(t, f.admin.ID, stored.PendingOwnerUserID)
	stored, _ = f.repo.GetUser(ctx, ownedBySurvivor.ID)
	assert.Empty(t, stored.PendingOwnerUserID)
}

// ── Deactivate / reactivate / delete ───────────────────────────────────

func TestDeactivateAndReactivateAgent(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)
	seedChildSession(t, f.repo, agent.ID)

	require.NoError(t, f.svc.DeactivateAgent(ctx, f.owner.ID, agent.ID, "paused", "", ""))
	stored, _ := f.repo.GetUser(ctx, agent.ID)
	assert.Equal(t, StatusDeactivated, stored.Status)
	assert.False(t, liveSessions(f.repo, agent.ID))
	// Idempotent.
	require.NoError(t, f.svc.DeactivateAgent(ctx, f.owner.ID, agent.ID, "paused", "", ""))

	require.NoError(t, f.svc.ReactivateAgent(ctx, f.owner.ID, agent.ID, "", ""))
	stored, _ = f.repo.GetUser(ctx, agent.ID)
	assert.Equal(t, StatusActive, stored.Status)
	require.NoError(t, f.svc.ReactivateAgent(ctx, f.owner.ID, agent.ID, "", ""))

	// Another state is refused, not overwritten.
	f.setStatus(agent.ID, StatusPendingDeletion)
	require.ErrorIs(t, f.svc.DeactivateAgent(ctx, f.owner.ID, agent.ID, "", "", ""), ErrAccountNotActive)
	require.ErrorIs(t, f.svc.ReactivateAgent(ctx, f.owner.ID, agent.ID, "", ""), ErrAccountNotActive)

	types := make([]events.EventType, 0)
	for _, e := range f.pub.all() {
		types = append(types, e.Type)
	}
	assert.Equal(t, []events.EventType{events.EventUserDeactivated, events.EventUserUpdated}, types)
}

func TestDeleteAgent_DelegatesToThePurger(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)

	require.NoError(t, f.svc.DeleteAgent(ctx, f.owner.ID, agent.ID, "", ""))
	assert.Equal(t, []string{f.owner.ID + "->" + agent.ID}, f.purger.calls)
	stored, _ := f.repo.GetUser(ctx, agent.ID)
	assert.Nil(t, stored)
	assert.Equal(t, 1, f.writer.countByEventTypeActorTarget(string(audit.EventAgentDeleted), f.owner.ID, agent.ID))

	f.svc.purger = nil
	other := seedAgent(f.repo, f.owner.ID)
	require.ErrorIs(t, f.svc.DeleteAgent(ctx, f.owner.ID, other.ID, "", ""), ErrServiceUnavailable)
}

// ── Standing: derived from the owner, checked on every issue ───────────

// issueAgentTokens mints a token pair for the agent through the issue
// chokepoint, the way the delegation flow will: no sign-in.
func issueAgentTokens(t *testing.T, f *agentFixture, agent *User) (string, string) {
	t.Helper()
	access, refresh, err := f.svc.issueTokensWithSessionStart(context.Background(), agent, "", "", 0, 0)
	require.NoError(t, err)
	return access, refresh
}

func TestAgentTokens_CarryTheKindClaim(t *testing.T) {
	f := newAgentFixture(t)
	agent := seedAgent(f.repo, f.owner.ID)

	access, refresh := issueAgentTokens(t, f, agent)
	claims, err := jwt.VerifyAccessToken(access, f.svc.signer, "", "", false)
	require.NoError(t, err)
	assert.Equal(t, UserKindAgent, claims.Kind)
	assert.Zero(t, claims.AuthTime, "no sign-in vouches for an agent's session")

	_, access, _, err = f.svc.RefreshToken(context.Background(), refresh, "", "")
	require.NoError(t, err)
	claims, err = jwt.VerifyAccessToken(access, f.svc.signer, "", "", false)
	require.NoError(t, err)
	assert.Equal(t, UserKindAgent, claims.Kind)
}

func TestPersonTokens_CarryNoKindClaim(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	seedUser(repo, "person@example.com", hashPW(t, strongPW), StatusActive)
	login, err := svc.PasswordLogin(context.Background(), "person@example.com", strongPW, "", "")
	require.NoError(t, err)
	claims, err := jwt.VerifyAccessToken(login.AccessToken, svc.signer, "", "", false)
	require.NoError(t, err)
	assert.Empty(t, claims.Kind)
}

// Whatever ends the owner's standing ends the agent's: the refresh is
// refused, and no new session material is written.
func TestAgentStanding_FollowsTheOwner(t *testing.T) {
	for _, tc := range []struct {
		name string
		lose func(f *agentFixture, agent *User)
	}{
		{"owner_deactivated", func(f *agentFixture, _ *User) { f.setStatus(f.owner.ID, StatusDeactivated) }},
		{"owner_pending_deletion", func(f *agentFixture, _ *User) { f.setStatus(f.owner.ID, StatusPendingDeletion) }},
		{"owner_deleted", func(f *agentFixture, _ *User) {
			require.NoError(t, f.repo.DeleteUser(context.Background(), f.owner.ID))
		}},
		{"owner_merged", func(f *agentFixture, _ *User) {
			f.repo.mu.Lock()
			f.repo.users[f.owner.ID].MergedIntoUserID = f.stranger.ID
			f.repo.mu.Unlock()
		}},
		{"agent_deactivated", func(f *agentFixture, agent *User) { f.setStatus(agent.ID, StatusDeactivated) }},
		{"no_owner", func(f *agentFixture, agent *User) {
			f.repo.mu.Lock()
			f.repo.users[agent.ID].OwnerUserID = ""
			f.repo.mu.Unlock()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAgentFixture(t)
			agent := seedAgent(f.repo, f.owner.ID)
			_, refresh := issueAgentTokens(t, f, agent)

			tc.lose(f, agent)
			_, _, _, err := f.svc.RefreshToken(context.Background(), refresh, "", "")
			require.ErrorIs(t, err, ErrAccountNotActive)

			stored, _ := f.repo.GetUser(context.Background(), agent.ID)
			if stored != nil {
				_, _, err = f.svc.issueTokensWithSessionStart(context.Background(), stored, "", "", 0, 0)
				require.ErrorIs(t, err, ErrAccountNotActive)
			}
		})
	}
}

// The owner's standing returning makes the agent usable again: nothing was
// written to the agent.
func TestAgentStanding_RestoredWithTheOwner(t *testing.T) {
	f := newAgentFixture(t)
	agent := seedAgent(f.repo, f.owner.ID)
	f.setStatus(f.owner.ID, StatusDeactivated)
	_, _, err := f.svc.issueTokensWithSessionStart(context.Background(), agent, "", "", 0, 0)
	require.ErrorIs(t, err, ErrAccountNotActive)

	f.setStatus(f.owner.ID, StatusActive)
	issueAgentTokens(t, f, agent)
}

// ── Admission: an agent is admitted as its owner is ──────────────────

// agentAccessScope is a resolved project with the given access config.
func agentAccessScope(t *testing.T, cfg ProjectAccessConfig) context.Context {
	t.Helper()
	access, err := NewProjectAccessConfig(cfg)
	require.NoError(t, err)
	return WithProjectScope(context.Background(), &ProjectScope{ProjectID: "project-a", Access: access})
}

// Under every access mode, an agent refreshes exactly when its owner could:
// the agent has no address of its own for the mode to judge, and can never
// do more than its owner.
func TestAgentAdmission_FollowsTheOwner(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   ProjectAccessConfig
		admit bool
	}{
		{"open", ProjectAccessConfig{Mode: AccessModeOpen}, true},
		{"invite", ProjectAccessConfig{Mode: AccessModeInvite}, true},
		{"allowlist_owner_listed", ProjectAccessConfig{Mode: AccessModeAllowlist, AllowedEmails: []string{"owner@example.com"}}, true},
		{"allowlist_owner_not_listed", ProjectAccessConfig{Mode: AccessModeAllowlist, AllowedEmails: []string{"stranger@example.com"}}, false},
		{"open_owner_domain_blocked", ProjectAccessConfig{Mode: AccessModeOpen, BlockedDomains: []string{"example.com"}}, false},
		{"closed", ProjectAccessConfig{Mode: AccessModeClosed}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAgentFixture(t)
			agent := seedAgent(f.repo, f.owner.ID)
			_, refresh := issueAgentTokens(t, f, agent)

			ctx := agentAccessScope(t, tc.cfg)
			_, _, _, err := f.svc.RefreshToken(ctx, refresh, "", "")
			if tc.admit {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrAccessNotAllowed)
			_, _, err = f.svc.issueTokensWithSessionStart(ctx, agent, "", "", 0, 0)
			require.ErrorIs(t, err, ErrAccessNotAllowed, "the token chokepoint refuses too")
		})
	}
}

// Where identity verification is required, the owner's verification is the
// one that counts: an agent cannot verify anyone.
func TestAgentAdmission_IdentityVerificationIsTheOwners(t *testing.T) {
	f := newAgentFixture(t)
	agent := seedAgent(f.repo, f.owner.ID)
	_, refresh := issueAgentTokens(t, f, agent)
	f.svc.cfg.IDVRequired = true

	_, _, _, err := f.svc.RefreshToken(context.Background(), refresh, "", "")
	require.ErrorIs(t, err, ErrIDVRequired, "an unverified owner's agent is refused")

	f.repo.mu.Lock()
	f.repo.users[f.owner.ID].IDVVerified = true
	f.repo.mu.Unlock()
	_, refresh = issueAgentTokens(t, f, agent)
	_, _, _, err = f.svc.RefreshToken(context.Background(), refresh, "", "")
	require.NoError(t, err, "a verified owner's agent is admitted, unverified itself")
}

// ── Cascade: a change to the owner's standing cuts the agents off ──────

func TestRevokeUserAccess_ReachesOwnedAgents(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	mine := seedAgent(f.repo, f.owner.ID)
	theirs := seedAgent(f.repo, f.stranger.ID)
	for _, id := range []string{f.owner.ID, mine.ID, theirs.ID} {
		seedChildSession(t, f.repo, id)
	}

	require.NoError(t, RevokeUserAccess(ctx, f.repo, f.owner.ID, time.Now().UnixMilli()))
	assert.False(t, liveSessions(f.repo, f.owner.ID))
	assert.False(t, liveSessions(f.repo, mine.ID))
	assert.True(t, liveSessions(f.repo, theirs.ID), "another owner's agent is untouched")
}

func TestDeleteMyAccount_CutsOffOwnedAgents(t *testing.T) {
	repo := newFakeRepo()
	owner := seedPerson(repo, "leaver@example.com")
	agent := seedAgent(repo, owner.ID)
	seedChildSession(t, repo, agent.ID)

	ps := newTestProfileServiceForDeletion(repo, newRecordingAuditWriter())
	_, err := ps.DeleteMyAccount(context.Background(), owner.ID, "")
	require.NoError(t, err)
	assert.False(t, liveSessions(repo, agent.ID))
}

// ── Merge: agents follow their owner; an agent is never merged ─────────

func TestAccountMerge_ApplyToUsersRefusesAgents(t *testing.T) {
	agent := &User{ID: "a", Kind: UserKindAgent, OwnerUserID: "p", Status: StatusActive}
	person := &User{ID: "p", Kind: UserKindPerson, Status: StatusActive}
	m := AccountMerge{SurvivorID: person.ID, OtherID: agent.ID}
	require.ErrorIs(t, m.ApplyToUsers(person, agent), ErrMergeConflict)
	m = AccountMerge{SurvivorID: agent.ID, OtherID: person.ID}
	require.ErrorIs(t, m.ApplyToUsers(agent, person), ErrMergeConflict)
}

// Both merge entry points share checkMergeable: an agent is refused on
// either side, before anything is moved.
func TestCheckMergeable_RefusesAgents(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)

	require.ErrorIs(t, checkMergeable(ctx, f.repo, f.owner, agent), ErrMergeRefused)
	require.ErrorIs(t, checkMergeable(ctx, f.repo, agent, f.owner), ErrMergeRefused)
	require.ErrorIs(t, checkSurvivor(ctx, f.repo, agent), ErrMergeRefused)
	require.NoError(t, checkMergeable(ctx, f.repo, f.owner, f.stranger), "two people still merge")
}

// ── Sign-in: an agent has no sign-in method ────────────────────────────

// requireAgentSignInRefusal asserts the refusal and that no session
// material was written for the agent.
func requireAgentSignInRefusal(t *testing.T, repo *fakeRepo, err error, agentID string) {
	t.Helper()
	require.ErrorIs(t, err, ErrAgentSignIn)
	assert.False(t, liveSessions(repo, agentID), "a refused sign-in writes no session material")
}

func TestAgentSignIn_Chokepoint(t *testing.T) {
	f := newAgentFixture(t)
	agent := seedAgent(f.repo, f.owner.ID)
	_, _, err := f.svc.issueTokens(context.Background(), agent, "203.0.113.9", "ua")
	requireAgentSignInRefusal(t, f.repo, err, agent.ID)
	assert.Equal(t, 1, f.writer.countByEventTypeActorTarget(string(audit.EventAgentSignInRefused), agent.ID, agent.ID))
}

func TestAgentSignIn_Password(t *testing.T) {
	f := newAgentFixture(t)
	u := seedUser(f.repo, "pw-agent@example.com", hashPW(t, strongPW), StatusActive)
	forceAgent(f.repo, u, f.owner.ID)
	_, err := f.svc.PasswordLogin(context.Background(), "pw-agent@example.com", strongPW, "", "")
	requireAgentSignInRefusal(t, f.repo, err, u.ID)
}

func TestAgentSignIn_UsernamePassword(t *testing.T) {
	f := newAgentFixture(t)
	u := seedManagedChild(t, f.repo, "agent.handle", 0)
	forceAgent(f.repo, u, f.owner.ID)
	_, err := f.svc.PasswordLogin(context.Background(), "agent.handle", strongPW, "", "")
	requireAgentSignInRefusal(t, f.repo, err, u.ID)
}

func TestAgentSignIn_OAuth(t *testing.T) {
	f := newAgentFixture(t)
	u := verified(seedUser(f.repo, "oauth-agent@example.com", "", StatusActive))
	forceAgent(f.repo, u, f.owner.ID)
	_, err := f.svc.OAuthLogin(context.Background(), OAuthLoginParams{
		Code:     fakeOAuthCode("oauth-agent@example.com", "Agent", "", "google"),
		Provider: "google", RedirectURI: "https://app/cb",
	})
	requireAgentSignInRefusal(t, f.repo, err, u.ID)
}

func TestAgentSignIn_NativeOAuth(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), nil)
	owner := seedPerson(repo, "native-owner@example.com")
	u := verified(seedUser(repo, "native-agent@example.com", "", StatusActive))
	forceAgent(repo, u, owner.ID)

	tok := signer.googleToken(t, "g-sub-agent", "native-agent@example.com", nativeGoogleAud)
	_, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: tok, Product: "acme",
	})
	requireAgentSignInRefusal(t, repo, err, u.ID)
}

func TestAgentSignIn_HostedOAuth(t *testing.T) {
	f := newAgentFixture(t)
	u := verified(seedUser(f.repo, "hosted-agent@example.com", "", StatusActive))
	forceAgent(f.repo, u, f.owner.ID)
	ctx := withProject("proj-1")

	begin, err := f.svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-123", "")
	require.NoError(t, err)
	_, err = f.svc.CompleteHostedOAuth(ctx, "google",
		fakeOAuthCode("hosted-agent@example.com", "Hosted", "", "google"),
		stateTokenFromAuthURL(t, begin.AuthorizationURL), "", "", "", []string{"csrf-123"})
	requireAgentSignInRefusal(t, f.repo, err, u.ID)
}

func TestAgentSignIn_EmailCode(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	ctx := context.Background()
	owner := seedPerson(repo, "otp-owner@test.com")
	u := verified(seedUser(repo, "otp-agent@test.com", "", StatusActive))
	forceAgent(repo, u, owner.ID)

	require.NoError(t, svc.RequestEmailLoginCode(ctx, "otp-agent@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)
	_, err := svc.VerifyEmailLoginCode(ctx, "otp-agent@test.com", code, "", "")
	requireAgentSignInRefusal(t, repo, err, u.ID)
}

func TestAgentSignIn_MagicLink(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	ctx := context.Background()
	owner := seedPerson(repo, "ml-owner@test.com")
	u := verified(seedUser(repo, "ml-agent@test.com", "", StatusActive))
	forceAgent(repo, u, owner.ID)

	require.NoError(t, svc.RequestMagicLink(ctx, "ml-agent@test.com", "https://app.test/cb"))
	token := extractTokenFromLink(t, rec.Sent()[0].Text)
	_, err := svc.RedeemMagicLink(ctx, token, "", "")
	requireAgentSignInRefusal(t, repo, err, u.ID)
}

func TestAgentSignIn_Passkey(t *testing.T) {
	svc, repo, rec := newPasskeyVectorSvc(t)
	ctx := context.Background()
	owner := seedPerson(repo, "pk-owner@example.com")

	_, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "My Key")
	require.NoError(t, err)
	otp := passkeySignupOTP(t, rec, pkVectorEmail)
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))
	res, err := svc.CompletePasskeySignup(ctx, challengeID, pkRegCredentialJSON(t), pkVectorEmail, otp, "My Key", "", "")
	require.NoError(t, err)
	stored, _ := repo.GetUser(ctx, res.User.ID)
	forceAgent(repo, stored, owner.ID)
	require.NoError(t, repo.DeleteRefreshTokensForUser(ctx, stored.ID))
	require.NoError(t, repo.RevokeSessionsForUser(ctx, stored.ID, time.Now().UnixMilli()))

	_, loginChallengeID, err := svc.BeginPasskeyLogin(ctx, pkVectorEmail)
	require.NoError(t, err)
	setFakeChallengeValue(repo, loginChallengeID, pkB64URL(t, pkLoginChallengeHex))
	_, err = svc.CompletePasskeyLogin(ctx, loginChallengeID, pkAssertionCredentialJSON(t), "", "")
	requireAgentSignInRefusal(t, repo, err, stored.ID)
}

func TestAgentSignIn_Totp(t *testing.T) {
	f := newAgentFixture(t)
	u := seedUser(f.repo, "totp-agent@example.com", hashPW(t, strongPW), StatusActive)
	forceAgent(f.repo, u, f.owner.ID)

	encrypted, err := secretcrypto.Encrypt("JBSWY3DPEHPK3PXP", testTotpKey())
	require.NoError(t, err)
	recoveryCode := "ABCDEFGHJK"
	f.repo.mu.Lock()
	f.repo.users[u.ID].TotpRequired = true
	credID := nextNodeID()
	f.repo.totpCreds[credID] = &TotpCredRecord{NodeID: credID, UserID: u.ID, SecretEncrypted: encrypted, Verified: true}
	rcID := nextNodeID()
	f.repo.recoveryCodes[rcID] = &RecoveryCodeRecord{
		NodeID: rcID, UserID: u.ID, CodeHash: totp.HashRecoveryCode(recoveryCode, testTotpRecoveryPepper()),
	}
	lcID := nextNodeID()
	f.repo.loginChallenges[lcID] = &LoginChallengeRecord{
		NodeID: lcID, ChallengeID: "agent-totp-challenge", UserID: u.ID,
		ExpiresAt: time.Now().Add(5 * time.Minute).UnixMilli(), CreatedAt: time.Now().UnixMilli(),
	}
	f.repo.mu.Unlock()

	_, err = f.svc.VerifyTotp(context.Background(), "agent-totp-challenge", recoveryCode, "", "")
	requireAgentSignInRefusal(t, f.repo, err, u.ID)
}

func TestAgentSignIn_QR(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)

	init, err := f.svc.InitiateQrLogin(ctx, "Pixel 8", "ua", "10.0.0.1")
	require.NoError(t, err)
	_, err = f.svc.ApproveQrLogin(ctx, init.SessionID, true, agent.ID, "ua")
	require.NoError(t, err)
	_, err = f.svc.PollQrLogin(ctx, init.SessionID, init.PollSecret, "10.0.0.1", "ua")
	requireAgentSignInRefusal(t, f.repo, err, agent.ID)
}

func TestAgentSignIn_Invitation(t *testing.T) {
	f := newAgentFixture(t)
	u := seedUser(f.repo, "invited-agent@example.com", "", "invited")
	forceAgent(f.repo, u, f.owner.ID)
	seedInvitation(f.repo, &InvitationRecord{
		TokenHash: hashInvitationToken("agent-invite-token"),
		Email:     "invited-agent@example.com",
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})
	_, err := f.svc.AcceptInvitation(context.Background(), "agent-invite-token", strongPW, "Invitee", "", "")
	requireAgentSignInRefusal(t, f.repo, err, u.ID)
}

// ── Credentials are never attached to an agent ─────────────────────────

func TestAgentCredentialAttach_Refused(t *testing.T) {
	f := newAgentFixture(t)
	f.svc.cfg.SMSEnabled = true
	ctx := context.Background()
	agent := seedAgent(f.repo, f.owner.ID)

	_, _, err := f.svc.BeginPasskeyRegistration(ctx, agent.ID, "Key")
	require.ErrorIs(t, err, ErrAgentCredential, "passkey")
	_, err = f.svc.LinkIdentity(ctx, agent.ID, "code", "google", "https://app/cb", "", "", "")
	require.ErrorIs(t, err, ErrAgentCredential, "provider identity")
	require.ErrorIs(t, f.svc.RequestPhoneVerification(ctx, agent.ID, "+15555550100"), ErrAgentCredential, "phone")
	_, err = f.svc.VerifyPhoneCode(ctx, agent.ID, "+15555550100", "123456")
	require.ErrorIs(t, err, ErrAgentCredential, "phone verify")
	_, _, _, err = f.svc.BeginTotpSetup(ctx, agent.ID)
	require.ErrorIs(t, err, ErrAgentCredential, "totp")
	idvSvc := NewIdentityVerificationService(f.repo, idv.NewStubProvider(), "proj-1", nil)
	_, err = idvSvc.BeginIdentityVerification(ctx, agent.ID)
	require.ErrorIs(t, err, ErrAgentCredential, "identity verification")
}

// ── Admin surfaces ─────────────────────────────────────────────────────

func addAgentNode(db *fakeDB, id, ownerID string) {
	db.addUser(id, "", "Helper", "member", "active")
	db.mu.Lock()
	db.nodes[id].Payload[ufKind] = UserKindAgent
	db.nodes[id].Payload[ufOwnerUserID] = ownerID
	db.mu.Unlock()
}

func TestAdminListUsers_AgentsOnlyWhenAsked(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("user-1", "alice@test.com", "Alice", "member", "active")
	addAgentNode(db, "agent-1", "user-1")
	svc := newTestAdminService(db)

	users, _, total, err := svc.ListUsers(context.Background(), "admin-1", "", "", "", 50, false)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.NotContains(t, idsOf(users), "agent-1")

	users, _, total, err = svc.ListUsers(context.Background(), "admin-1", "", "", "", 50, true)
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	require.Contains(t, idsOf(users), "agent-1")
	for _, u := range users {
		if u.ID == "agent-1" {
			assert.True(t, u.IsAgent())
			assert.Equal(t, "user-1", u.OwnerUserID)
		}
	}
}

func TestAdminUpdateUser_RefusesAgents(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	addAgentNode(db, "agent-1", "admin-1")
	svc := newTestAdminService(db)

	for _, tc := range []struct{ name, role, avatar string }{
		{"", "admin", ""},
		{strings.Repeat("x", agentNameMaxRunes+1), "", ""},
		{"", "", "http://example.com/a.png"},
	} {
		_, err := svc.UpdateUser(context.Background(), "admin-1", "agent-1", tc.name, tc.role, tc.avatar)
		require.ErrorIs(t, err, ErrInvalidArgument)
	}
	assert.Equal(t, "member", db.nodes["agent-1"].Payload[ufRole])
	assert.Equal(t, "Helper", db.nodes["agent-1"].Payload[ufName])
}

func TestAdminResetUserPassword_RefusesAgents(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	addAgentNode(db, "agent-1", "admin-1")
	svc := newTestAdminService(db)

	_, err := svc.ResetUserPassword(context.Background(), "admin-1", "agent-1", true)
	require.ErrorIs(t, err, ErrAgentCredential)
}

// ── Directory ──────────────────────────────────────────────────────────

func TestDirectory_NeverReturnsAgents(t *testing.T) {
	agent := &User{ID: "a", Kind: UserKindAgent, OwnerUserID: "p", Email: "forced@example.com", Status: StatusActive}
	assert.False(t, isActiveDirectoryAccount(agent))
	assert.True(t, isActiveDirectoryAccount(&User{ID: "p", Email: "p@example.com", Status: StatusActive}))
}

// ── Events ─────────────────────────────────────────────────────────────

// Kind and owner ride on an agent's event only; a person's payload is
// unchanged.
func TestToEventUser_KindAndOwner(t *testing.T) {
	ev := toEventUser(&User{ID: "a", Kind: UserKindAgent, OwnerUserID: "p", PendingOwnerUserID: "q"})
	assert.Equal(t, UserKindAgent, ev.Kind)
	assert.Equal(t, "p", ev.OwnerUserID)
	assert.Equal(t, "q", ev.PendingOwnerUserID)

	ev = toEventUser(&User{ID: "p", Kind: UserKindPerson})
	assert.Empty(t, ev.Kind)
	assert.Empty(t, ev.OwnerUserID)
	assert.Empty(t, ev.PendingOwnerUserID)
}
