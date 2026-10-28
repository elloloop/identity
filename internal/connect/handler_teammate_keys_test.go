package connect

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
)

func TestTeammateKeyRequestsAreRefusedWhileDisabled(t *testing.T) {
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, testConfig())
	_, err := h.CreateAgentMachineChallenge(context.Background(), connect.NewRequest(&identitypb.CreateAgentMachineChallengeRequest{TeammateKeyId: "key", Operation: identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_EXCHANGE_AGENT}))
	require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	_, err = h.ExchangeAgentMachineCredential(context.Background(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{TeammateKeyId: "key"}))
	require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	_, err = h.ExchangeAgentMachineCredential(context.Background(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: "machine"}))
	require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestAgentExchangesAreCountedByKeyKindAndResult(t *testing.T) {
	reg := prometheus.NewRegistry()
	exchanges, err := NewAgentExchangeMetrics(reg)
	require.NoError(t, err)
	_, err = NewAgentExchangeMetrics(reg)
	require.Error(t, err)
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, testConfig()).WithAgentExchangeMetrics(exchanges)
	_, _ = h.ExchangeAgentMachineCredential(context.Background(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{MachineId: "machine"}))
	_, _ = h.ExchangeAgentMachineCredential(context.Background(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{TeammateKeyId: "key"}))
	h.countExchange(exchangeKindTeammate, nil)
	h.countExchange(exchangeKindTeammate, errors.New("database down"))
	h.countExchange(exchangeKindTeammate, connect.NewError(connect.CodeUnavailable, errors.New("busy")))
	require.InDelta(t, 1, testutil.ToFloat64(exchanges.WithLabelValues(exchangeKindAgentMachine, "refused")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(exchanges.WithLabelValues(exchangeKindTeammate, "refused")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(exchanges.WithLabelValues(exchangeKindTeammate, "issued")), 0)
	require.InDelta(t, 2, testutil.ToFloat64(exchanges.WithLabelValues(exchangeKindTeammate, "error")), 0)
	_, err = NewAgentExchangeMetrics(nil)
	require.NoError(t, err)
	NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, testConfig()).countExchange(exchangeKindTeammate, nil)
}
