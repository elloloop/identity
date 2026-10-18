package identityserver

import (
	"strings"
	"testing"
	"time"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnect "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGRPCMachineUsesSharedBudgetAndRefusesUnboundedRequests(t *testing.T) {
	procedure := identityconnect.IdentityServiceIntrospectAgentMachineProcedure
	limit := middleware.PathLimit{PathPrefix: procedure, Tag: "agent_machine_introspection", Limiter: middleware.NewFixedWindowLimiter(time.Minute, 2, 0)}
	bridge := &grpcBridge{logger: zap.NewNop(), machineLimits: map[string]middleware.PathLimit{procedure: limit}}
	ctx := peerContext("198.51.100.4", nil)
	require.True(t, limit.Allow("198.51.100.4", time.Now()), "HTTP consumes this same budget")
	require.NoError(t, bridge.admitMachine(ctx, procedure, &identitypb.IntrospectAgentMachineRequest{}))
	require.Equal(t, codes.ResourceExhausted, status.Code(bridge.admitMachine(ctx, procedure, &identitypb.IntrospectAgentMachineRequest{})))
	other := peerContext("198.51.100.5", nil)
	require.Equal(t, codes.ResourceExhausted, status.Code(bridge.admitMachine(other, procedure, &identitypb.IntrospectAgentMachineRequest{Proof: &identitypb.AgentMachineProof{ChallengeId: strings.Repeat("x", config.AgentMachineRequestMaxBytes+1)}})))
	bridge.machineLimits = nil
	require.Equal(t, codes.FailedPrecondition, status.Code(bridge.admitMachine(other, procedure, &identitypb.IntrospectAgentMachineRequest{})))
}
