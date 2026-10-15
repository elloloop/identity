package service

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// AgentCreation contains the already-normalized creation request. A repository
// must commit the subject and receipt together, under current authority.
type AgentCreation struct {
	CallerID    string
	RequestID   string
	Fingerprint string
	Agent       *User
	OwnerLimit  int
}

// AgentCreationReceipt survives subject erasure so a retry cannot recreate it.
// It is scoped to a project by its repository and is never an authority grant.
type AgentCreationReceipt struct {
	CallerID    string
	RequestID   string
	Fingerprint string
	AgentID     string
	OwnerID     string
	Invalidated bool
}

func validateAgentCreationKey(key string) error {
	if len(key) > 128 || !utf8.ValidString(key) || strings.IndexFunc(key, unicode.IsControl) >= 0 {
		return fmt.Errorf("%w: client_request_id must be at most 128 UTF-8 bytes without controls", ErrInvalidArgument)
	}
	return nil
}

func agentCreationFingerprint(values ...string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("agent-create-v1"))
	for _, value := range values {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CheckAgentCreationAuthority is checked again within the storage transaction:
// the service's earlier reads cannot authorize a write after standing changes.
func CheckAgentCreationAuthority(caller, owner *User) error {
	if !isEligibleAgentOwner(caller) || !isEligibleAgentOwner(owner) ||
		(caller.ID != owner.ID && !strings.EqualFold(caller.Role, RoleAdmin)) {
		return fmt.Errorf("%w: %s", ErrPermissionDenied, agentRefusalNotAllowed)
	}
	return nil
}

// CheckAgentCreationReplay never re-grants access after a lifecycle change.
func CheckAgentCreationReplay(receipt AgentCreationReceipt, request AgentCreation, agent *User) error {
	if receipt.Invalidated || agent == nil || !agent.IsAgent() || !isActiveStatus(agent.Status) || agent.OwnerUserID != receipt.OwnerID {
		return fmt.Errorf("%w: %s", ErrPermissionDenied, agentRefusalNotAllowed)
	}
	if receipt.Fingerprint != request.Fingerprint {
		return fmt.Errorf("%w: client_request_id already used for another request", ErrAlreadyExists)
	}
	return nil
}

// AgentCreationAuthorityLost fences reactivation and transfer-back. Pending
// offers and profile edits leave authority intact and preserve safe retries.
func AgentCreationAuthorityLost(before, after *User) bool {
	if before == nil {
		return false
	}
	if after == nil {
		return true
	}
	return before.OwnerUserID != after.OwnerUserID || before.Kind != after.Kind ||
		(!isActiveStatus(after.Status) && before.Status != after.Status) ||
		(!before.IsAnonymous && after.IsAnonymous) ||
		(before.MergedIntoUserID != after.MergedIntoUserID && after.MergedIntoUserID != "") ||
		(strings.EqualFold(before.Role, RoleAdmin) && !strings.EqualFold(after.Role, RoleAdmin))
}

// ValidateAgentCreation guards the atomic storage operation's invariants.
func ValidateAgentCreation(request AgentCreation) error {
	if request.Agent == nil || request.Agent.ID != "" || !request.Agent.IsAgent() || request.Agent.OwnerUserID == "" ||
		request.CallerID == "" || len(request.Fingerprint) != 64 || request.OwnerLimit <= 0 {
		return fmt.Errorf("%w: invalid agent creation receipt", ErrInvalidArgument)
	}
	return validateAgentCreationKey(request.RequestID)
}
