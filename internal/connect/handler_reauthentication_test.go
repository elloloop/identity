package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/stretchr/testify/require"
)

func TestReauthenticationRPCRequiresAuthenticatedCaller(t *testing.T) {
	h := newHarness(t)
	_, err := h.client.BeginReauthentication(context.Background(), connect.NewRequest(&identitypb.BeginReauthenticationRequest{Action: "account.pin.set", ResourceId: "parent"}))
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = h.client.VerifyReauthentication(context.Background(), connect.NewRequest(&identitypb.VerifyReauthenticationRequest{Action: "account.pin.set", ResourceId: "parent", ChallengeId: "arbitrary", CredentialJson: "{}"}))
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestPasskeyReauthenticationConversion(t *testing.T) {
	require.Nil(t, passkeyReauthentication(nil))
	proof := passkeyReauthentication(&identitypb.PasskeyReauthentication{ChallengeId: "id", CredentialJson: "{}"})
	require.Equal(t, "id", proof.ChallengeID)
	require.Equal(t, "{}", proof.CredentialJSON)
}
