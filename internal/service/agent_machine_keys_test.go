package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMachineSignedChallengeBoundaries(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	request := AgentMachineChallengeRequest{MachineID: "workstation", Operation: AgentMachineRoster, Offset: 20}
	binding, err := request.binding()
	require.NoError(t, err)
	challenge := &AgentMachineChallenge{ID: "nonce", MachineID: request.MachineID, Operation: request.Operation, Binding: binding, PublicKey: hex.EncodeToString(pub), Message: `{"domain":"identity.agent-machine.v1","issuer":"https://identity.example.test","project":"project","nonce":"random"}`, CreatedAtMs: 1000, ExpiresAtMs: 61000}
	proof := AgentMachineProof{ChallengeID: challenge.ID, Signature: ed25519.Sign(private, []byte(challenge.Message))}
	require.True(t, verifyMachineSignature(challenge, proof, binding, 1000))
	require.False(t, verifyMachineSignature(challenge, proof, binding, 999))
	require.False(t, verifyMachineSignature(challenge, proof, binding, 61000))
	require.False(t, verifyMachineSignature(challenge, proof, "another request", 1000))
	proof.ChallengeID = "another nonce"
	require.False(t, verifyMachineSignature(challenge, proof, binding, 1000))
	proof.ChallengeID = challenge.ID
	proof.Signature[0] ^= 1
	require.False(t, verifyMachineSignature(challenge, proof, binding, 1000))
	proof.Signature = ed25519.Sign(private, []byte(challenge.Message))
	challenge.Message += " "
	require.False(t, verifyMachineSignature(challenge, proof, binding, 1000))
}

func TestMachineChallengeRequestSeparatesEngineAndAgentOperations(t *testing.T) {
	key := hex.EncodeToString(make([]byte, ed25519.PublicKeySize))
	valid := []AgentMachineChallengeRequest{
		{MachineID: "machine", Operation: AgentMachineEnroll, AgentID: "agent", PublicKey: key},
		{MachineID: "machine", Operation: AgentMachineExchange, AgentID: "agent"},
		{MachineID: "machine", Operation: AgentMachineRoster},
		{MachineID: "machine", Operation: AgentMachineInspect},
	}
	for _, request := range valid {
		_, err := request.binding()
		require.NoError(t, err)
	}
	invalid := []AgentMachineChallengeRequest{
		{MachineID: "machine", Operation: "unknown"},
		{MachineID: "machine", Operation: AgentMachineEnroll, AgentID: "agent"},
		{MachineID: "machine", Operation: AgentMachineExchange, AgentID: "agent", PublicKey: key},
		{MachineID: "machine", Operation: AgentMachineRoster, AgentID: "agent"},
		{MachineID: "machine", Operation: AgentMachineRoster, Offset: -1},
		{MachineID: "machine", Operation: AgentMachineInspect, Offset: 1},
	}
	for _, request := range invalid {
		_, err := request.binding()
		require.ErrorIs(t, err, ErrInvalidArgument)
	}
	require.False(t, validMachinePublicKey("not a key"))
	require.False(t, validMachinePublicKey(key+"00"))
}
