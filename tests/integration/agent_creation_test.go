//go:build integration

package integration

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
	"github.com/stretchr/testify/require"
)

func TestAgentCreationRetryLifecycleOverHTTP(t *testing.T) {
	ctx := context.Background()
	h := StartServer(t, WithConfig(func(c *config.Config) { c.AgentsEnabled = true; c.AgentsMaxPerOwner = 1 }))
	access, _, _ := signupViaClient(t, h, "agent-retry-owner@example.com")
	client := h.AuthedClient(access)
	create := func(name, key string) (*connect.Response[identitypb.CreateAgentResponse], error) {
		return client.CreateAgent(ctx, connect.NewRequest(&identitypb.CreateAgentRequest{Name: name, ClientRequestId: key}))
	}
	first, err := create("Helper", "lost-response")
	require.NoError(t, err)
	replay, err := create(" Helper ", "lost-response")
	require.NoError(t, err)
	require.Equal(t, first.Msg.Agent.Id, replay.Msg.Agent.Id)
	_, err = create("Different", "lost-response")
	require.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))
	_, err = create("Helper", "")
	require.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
	_, err = client.DeactivateAgent(ctx, connect.NewRequest(&identitypb.DeactivateAgentRequest{AgentUserId: first.Msg.Agent.Id}))
	require.NoError(t, err)
	_, err = client.ReactivateAgent(ctx, connect.NewRequest(&identitypb.ReactivateAgentRequest{AgentUserId: first.Msg.Agent.Id}))
	require.NoError(t, err)
	_, err = create("Helper", "lost-response")
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}
