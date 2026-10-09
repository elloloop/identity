package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
)

// agentCall is one agent-management RPC, parameterized by caller and
// target, so the session requirement is checked across the whole surface.
type agentCall struct {
	name string
	call func(h *testHarness, caller, agentID string) error
}

func agentCalls() []agentCall {
	ctx := context.Background()
	return []agentCall{
		{"CreateAgent", func(h *testHarness, c, _ string) error {
			_, err := h.client.CreateAgent(ctx, authedReq(connect.NewRequest(&identitypb.CreateAgentRequest{Name: "A"}), c))
			return err
		}},
		{"ListAgents", func(h *testHarness, c, _ string) error {
			_, err := h.client.ListAgents(ctx, authedReq(connect.NewRequest(&identitypb.ListAgentsRequest{}), c))
			return err
		}},
		{"ListIncomingAgentTransfers", func(h *testHarness, c, _ string) error {
			_, err := h.client.ListIncomingAgentTransfers(ctx, authedReq(connect.NewRequest(&identitypb.ListIncomingAgentTransfersRequest{}), c))
			return err
		}},
		{"UpdateAgent", func(h *testHarness, c, a string) error {
			_, err := h.client.UpdateAgent(ctx, authedReq(connect.NewRequest(&identitypb.UpdateAgentRequest{AgentUserId: a, Name: "B"}), c))
			return err
		}},
		{"TransferAgent", func(h *testHarness, c, a string) error {
			_, err := h.client.TransferAgent(ctx, authedReq(connect.NewRequest(&identitypb.TransferAgentRequest{AgentUserId: a, NewOwnerUserId: c}), c))
			return err
		}},
		{"AcceptAgentTransfer", func(h *testHarness, c, a string) error {
			_, err := h.client.AcceptAgentTransfer(ctx, authedReq(connect.NewRequest(&identitypb.AcceptAgentTransferRequest{AgentUserId: a}), c))
			return err
		}},
		{"DeclineAgentTransfer", func(h *testHarness, c, a string) error {
			_, err := h.client.DeclineAgentTransfer(ctx, authedReq(connect.NewRequest(&identitypb.DeclineAgentTransferRequest{AgentUserId: a}), c))
			return err
		}},
		{"CancelAgentTransfer", func(h *testHarness, c, a string) error {
			_, err := h.client.CancelAgentTransfer(ctx, authedReq(connect.NewRequest(&identitypb.CancelAgentTransferRequest{AgentUserId: a}), c))
			return err
		}},
		{"DeactivateAgent", func(h *testHarness, c, a string) error {
			_, err := h.client.DeactivateAgent(ctx, authedReq(connect.NewRequest(&identitypb.DeactivateAgentRequest{AgentUserId: a}), c))
			return err
		}},
		{"ReactivateAgent", func(h *testHarness, c, a string) error {
			_, err := h.client.ReactivateAgent(ctx, authedReq(connect.NewRequest(&identitypb.ReactivateAgentRequest{AgentUserId: a}), c))
			return err
		}},
		{"DeleteAgent", func(h *testHarness, c, a string) error {
			_, err := h.client.DeleteAgent(ctx, authedReq(connect.NewRequest(&identitypb.DeleteAgentRequest{AgentUserId: a}), c))
			return err
		}},
	}
}

// newAgentHarness is a harness with agent accounts switched on.
func newAgentHarness(t *testing.T) *testHarness {
	t.Helper()
	return newHarnessWithWebAssurance(t, nil, func(c *config.Config) { c.AgentsEnabled = true })
}

// Off by default: the whole surface answers FAILED_PRECONDITION.
func TestHandler_AgentSurface_DisabledByDefault(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	owner := seedConsentAdult(ctx, t, h, "owner@example.com", false)
	for _, op := range agentCalls() {
		t.Run(op.name, func(t *testing.T) {
			if got := connectCodeOf(op.call(h, owner, "agent-1")); got != connect.CodeFailedPrecondition {
				t.Fatalf("code = %v, want FailedPrecondition", got)
			}
		})
	}
}

func TestHandler_AgentSurface_RequiresSession(t *testing.T) {
	for _, op := range agentCalls() {
		t.Run(op.name, func(t *testing.T) {
			h := newAgentHarness(t)
			if got := connectCodeOf(op.call(h, "", "agent-1")); got != connect.CodeUnauthenticated {
				t.Fatalf("code = %v, want Unauthenticated", got)
			}
		})
	}
}

// The full lifecycle over the wire: the owner creates, lists, renames,
// pauses, resumes and offers it; the recipient accepts and deletes it; a
// stranger is refused; the User
// message carries the kind and the owner.
func TestHandler_AgentLifecycle(t *testing.T) {
	ctx := context.Background()
	h := newAgentHarness(t)
	owner := seedConsentAdult(ctx, t, h, "owner@example.com", false)
	recipient := seedConsentAdult(ctx, t, h, "recipient@example.com", false)
	stranger := seedConsentAdult(ctx, t, h, "stranger@example.com", false)

	created, err := h.client.CreateAgent(ctx, authedReq(connect.NewRequest(&identitypb.CreateAgentRequest{
		Name: "Research helper", AvatarUrl: "https://cdn.example.com/a.png",
	}), owner))
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	agent := created.Msg.GetAgent()
	if agent.GetKind() != identitypb.UserKind_USER_KIND_AGENT || agent.GetOwnerUserId() != owner {
		t.Fatalf("agent kind/owner = %v/%q, want AGENT/%q", agent.GetKind(), agent.GetOwnerUserId(), owner)
	}
	if agent.GetName() != "Research helper" || agent.GetAvatarUrl() != "https://cdn.example.com/a.png" {
		t.Fatalf("agent profile = %q/%q", agent.GetName(), agent.GetAvatarUrl())
	}

	listed, err := h.client.ListAgents(ctx, authedReq(connect.NewRequest(&identitypb.ListAgentsRequest{}), owner))
	if err != nil || len(listed.Msg.GetAgents()) != 1 || listed.Msg.GetAgents()[0].GetId() != agent.GetId() {
		t.Fatalf("ListAgents = %v, %v", listed, err)
	}

	// Every call on an existing agent (all but the create and the two lists).
	for _, op := range agentCalls()[3:] {
		if got := connectCodeOf(op.call(h, stranger, agent.GetId())); got != connect.CodePermissionDenied {
			t.Fatalf("%s by a stranger: code = %v, want PermissionDenied", op.name, got)
		}
	}

	updated, err := h.client.UpdateAgent(ctx, authedReq(connect.NewRequest(&identitypb.UpdateAgentRequest{
		AgentUserId: agent.GetId(), Name: "Renamed",
	}), owner))
	if err != nil || updated.Msg.GetAgent().GetName() != "Renamed" {
		t.Fatalf("UpdateAgent = %v, %v", updated, err)
	}
	if _, err := h.client.DeactivateAgent(ctx, authedReq(connect.NewRequest(&identitypb.DeactivateAgentRequest{AgentUserId: agent.GetId()}), owner)); err != nil {
		t.Fatalf("DeactivateAgent: %v", err)
	}
	if _, err := h.client.ReactivateAgent(ctx, authedReq(connect.NewRequest(&identitypb.ReactivateAgentRequest{AgentUserId: agent.GetId()}), owner)); err != nil {
		t.Fatalf("ReactivateAgent: %v", err)
	}
	moved, err := h.client.TransferAgent(ctx, authedReq(connect.NewRequest(&identitypb.TransferAgentRequest{
		AgentUserId: agent.GetId(), NewOwnerUserId: recipient,
	}), owner))
	if err != nil || moved.Msg.GetAgent().GetOwnerUserId() != owner || moved.Msg.GetAgent().GetPendingOwnerUserId() != recipient {
		t.Fatalf("TransferAgent = %v, %v, want an offer to the recipient", moved, err)
	}
	incoming, err := h.client.ListIncomingAgentTransfers(ctx, authedReq(connect.NewRequest(&identitypb.ListIncomingAgentTransfersRequest{}), recipient))
	if err != nil || len(incoming.Msg.GetAgents()) != 1 || incoming.Msg.GetAgents()[0].GetId() != agent.GetId() {
		t.Fatalf("ListIncomingAgentTransfers = %v, %v", incoming, err)
	}
	if _, err := h.client.AcceptAgentTransfer(ctx, authedReq(connect.NewRequest(&identitypb.AcceptAgentTransferRequest{AgentUserId: agent.GetId()}), owner)); connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("AcceptAgentTransfer by the sender: %v, want PermissionDenied", err)
	}
	accepted, err := h.client.AcceptAgentTransfer(ctx, authedReq(connect.NewRequest(&identitypb.AcceptAgentTransferRequest{AgentUserId: agent.GetId()}), recipient))
	if err != nil || accepted.Msg.GetAgent().GetOwnerUserId() != recipient || accepted.Msg.GetAgent().GetPendingOwnerUserId() != "" {
		t.Fatalf("AcceptAgentTransfer = %v, %v", accepted, err)
	}
	if _, err := h.client.DeleteAgent(ctx, authedReq(connect.NewRequest(&identitypb.DeleteAgentRequest{AgentUserId: agent.GetId()}), owner)); connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("DeleteAgent by the previous owner: %v, want PermissionDenied", err)
	}
	if _, err := h.client.DeleteAgent(ctx, authedReq(connect.NewRequest(&identitypb.DeleteAgentRequest{AgentUserId: agent.GetId()}), recipient)); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
	if u, _ := h.repo.GetUser(ctx, agent.GetId()); u != nil {
		t.Fatalf("agent still stored after delete")
	}
}

// A person's User message reports PERSON and no owner.
func TestUserToProto_PersonKind(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	id := seedConsentAdult(ctx, t, h, "person@example.com", false)
	u, err := h.repo.GetUser(ctx, id)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	pb := userToProto(u)
	if pb.GetKind() != identitypb.UserKind_USER_KIND_PERSON || pb.GetOwnerUserId() != "" {
		t.Fatalf("person kind/owner = %v/%q", pb.GetKind(), pb.GetOwnerUserId())
	}
}
