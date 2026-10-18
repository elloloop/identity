package service

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
)

const (
	AgentMachineEnroll                    = "enroll_agent"
	AgentMachineExchange                  = "exchange_agent"
	AgentMachineRoster                    = "list_agents"
	AgentMachineInspect                   = "inspect_machine"
	AgentMachineChallengeLifetimeMs int64 = 60_000
	MaxAgentMachineChallenges             = 128
)

type AgentMachineProof struct {
	ChallengeID string
	Signature   []byte
}

type AgentMachineChallengeRequest struct {
	MachineID string
	AgentID   string
	Operation string
	PublicKey string
	Offset    int
}

// Message is the exact server-created UTF-8 document the client signs. PublicKey
// is the registered signer, never a key selected by the proof's caller.
type AgentMachineChallenge struct {
	ID          string
	MachineID   string
	AgentID     string
	Operation   string
	Binding     string
	PublicKey   string
	Message     string
	CreatedAtMs int64
	ExpiresAtMs int64
}

func validMachinePublicKey(value string) bool {
	key, err := hex.DecodeString(value)
	return err == nil && len(key) == ed25519.PublicKeySize && hex.EncodeToString(key) == value
}

func (r AgentMachineChallengeRequest) binding() (string, error) {
	if !validOAuthClientID(r.MachineID) {
		return "", ErrInvalidArgument
	}
	switch r.Operation {
	case AgentMachineEnroll:
		if !validOAuthClientID(r.AgentID) || !validMachinePublicKey(r.PublicKey) || r.Offset != 0 {
			return "", ErrInvalidArgument
		}
	case AgentMachineExchange:
		if !validOAuthClientID(r.AgentID) || r.PublicKey != "" || r.Offset != 0 {
			return "", ErrInvalidArgument
		}
	case AgentMachineRoster:
		if r.AgentID != "" || r.PublicKey != "" || r.Offset < 0 || r.Offset > math.MaxInt32-agentOAuthChoicePage {
			return "", ErrInvalidArgument
		}
	case AgentMachineInspect:
		if r.AgentID != "" || r.PublicKey != "" || r.Offset != 0 {
			return "", ErrInvalidArgument
		}
	default:
		return "", ErrInvalidArgument
	}
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func ValidAgentMachineChallenge(c *AgentMachineChallenge) bool {
	return c != nil && validOAuthClientID(c.ID) && validOAuthClientID(c.MachineID) && validMachinePublicKey(c.PublicKey) && len(c.Binding) == sha256.Size*2 && len(c.Message) > 0 && len(c.Message) <= 4096 && c.CreatedAtMs > 0 && c.ExpiresAtMs > c.CreatedAtMs && c.ExpiresAtMs-c.CreatedAtMs <= AgentMachineChallengeLifetimeMs
}

func verifyMachineSignature(c *AgentMachineChallenge, proof AgentMachineProof, binding string, now int64) bool {
	if !ValidAgentMachineChallenge(c) || c.ID != proof.ChallengeID || c.Binding != binding || c.CreatedAtMs > now || c.ExpiresAtMs <= now || len(proof.Signature) != ed25519.SignatureSize {
		return false
	}
	key, err := hex.DecodeString(c.PublicKey)
	return err == nil && ed25519.Verify(ed25519.PublicKey(key), []byte(c.Message), proof.Signature)
}

var ErrAgentMachineChallengeLimit = errors.New("too many pending machine challenges")
