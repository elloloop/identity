package service

import (
	"context"
	"reflect"
	"slices"
)

const (
	OAuthGrantAgentMachine   = "agent_machine"
	AgentMachineSelect       = "select"
	AgentMachineRevoke       = "revoke"
	MaxAgentMachineSelection = 1000
)

// AgentMachine is owner-authorized orchestration access. Its engine private key
// never enters an agent workspace; each child binds a separate agent public key.
// RegistrationSID is audit provenance, not continuing session authority.
type AgentMachine struct {
	ID               string
	OwnerID          string
	ClientID         string
	ClientRevision   int64
	Resource         string
	Product          string
	Scopes           []string
	DisplayName      string
	PublicKey        string
	RegistrationSID  string
	AllAgents        bool
	AgentIDs         []string
	ExcludedAgentIDs []string
	CreatedAtMs      int64
	Revision         int64
	RevokedAtMs      int64
	// RenewedAfterRevokedAtMs is the RevokedAtMs of the registration this one
	// replaced under the same installation id, or zero for a first registration.
	// A delegation the same revocation ended may be ensured again for it; one
	// the owner ended by excluding the agent may not.
	RenewedAfterRevokedAtMs int64
	// RetiredPublicKeys are the engine keys every earlier registration of this
	// installation id held, oldest first. None of them registers again.
	RetiredPublicKeys []string
}

func (m *AgentMachine) Clone() *AgentMachine {
	if m == nil {
		return nil
	}
	copy := *m
	copy.Scopes = slices.Clone(m.Scopes)
	copy.AgentIDs = slices.Clone(m.AgentIDs)
	copy.ExcludedAgentIDs = slices.Clone(m.ExcludedAgentIDs)
	copy.RetiredPublicKeys = slices.Clone(m.RetiredPublicKeys)
	return &copy
}

func (m *AgentMachine) Allows(agent string) bool {
	return m != nil && m.RevokedAtMs == 0 && agent != "" && !slices.Contains(m.ExcludedAgentIDs, agent) && (m.AllAgents || slices.Contains(m.AgentIDs, agent))
}

func validMachineSelection(all bool, ids, excluded []string) bool {
	if len(ids) > MaxAgentMachineSelection || len(excluded) > MaxAgentMachineSelection || all && len(ids) != 0 {
		return false
	}
	for _, values := range [][]string{ids, excluded} {
		seen := make(map[string]bool, len(values))
		for _, id := range values {
			if !validOAuthClientID(id) || seen[id] {
				return false
			}
			seen[id] = true
		}
	}
	for _, id := range ids {
		if slices.Contains(excluded, id) {
			return false
		}
	}
	return true
}

func ValidateAgentMachine(m *AgentMachine) error {
	if m == nil || !validOAuthClientID(m.ID) || !validOAuthClientID(m.OwnerID) || !validOAuthClientID(m.ClientID) || m.ClientRevision < 1 || m.RegistrationSID == "" || !validOAuthClientName(m.DisplayName) || m.CreatedAtMs <= 0 || m.Revision != 1 || m.RevokedAtMs != 0 || !boundedOAuthStrings(m.Scopes, maxOAuthScopes) || !validMachineSelection(m.AllAgents, m.AgentIDs, m.ExcludedAgentIDs) {
		return ErrInvalidArgument
	}
	if !validMachinePublicKey(m.PublicKey) {
		return ErrInvalidArgument
	}
	return nil
}

func (a AgentOAuthAuthority) ValidMachine(m *AgentMachine) bool {
	if m == nil || a.Client == nil {
		return false
	}
	product := ""
	for _, bound := range a.Client.Registration.Resources {
		if bound.Resource == m.Resource {
			product = bound.Product
			break
		}
	}
	return product != "" && product == m.Product && m.RevokedAtMs == 0 && isEligibleAgentOwner(a.Owner) && a.Owner.ID == m.OwnerID && a.Client.ID == m.ClientID && a.Client.Revision == m.ClientRevision && a.Client.ValidateMachineRequest(m.Resource, m.Scopes) == nil
}

func (a AgentOAuthAuthority) ValidMachineRegistration(m *AgentMachine) bool {
	return a.ValidMachine(m) && a.HumanSession != nil && a.HumanSession.SID == m.RegistrationSID && a.HumanSession.UserID == m.OwnerID && a.HumanSession.RevokedAtMs == 0
}

type AgentMachineMutation struct {
	Operation        string
	OwnerID          string
	AtMs             int64
	ExpectedRevision int64
	AllAgents        bool
	AgentIDs         []string
	ExcludedAgentIDs []string
}

func ApplyAgentMachineMutation(current *AgentMachine, mutation AgentMachineMutation) (*AgentMachine, error) {
	if current == nil || mutation.OwnerID == "" || mutation.OwnerID != current.OwnerID {
		return nil, ErrPermissionDenied
	}
	if mutation.AtMs <= 0 {
		return nil, ErrInvalidArgument
	}
	if mutation.Operation == AgentMachineRevoke {
		next := current.Clone()
		if next.RevokedAtMs == 0 {
			next.RevokedAtMs = mutation.AtMs
			next.Revision++
		}
		return next, nil
	}
	if mutation.Operation != AgentMachineSelect || !validMachineSelection(mutation.AllAgents, mutation.AgentIDs, mutation.ExcludedAgentIDs) {
		return nil, ErrInvalidArgument
	}
	if current.RevokedAtMs != 0 {
		return nil, ErrAgentOAuthGrant
	}
	if mutation.ExpectedRevision != current.Revision {
		return nil, ErrAgentOAuthRevision
	}
	next := current.Clone()
	next.AllAgents = mutation.AllAgents
	next.AgentIDs = slices.Clone(mutation.AgentIDs)
	next.ExcludedAgentIDs = slices.Clone(mutation.ExcludedAgentIDs)
	next.Revision++
	return next, nil
}

// Stores lock current owner/agent/client authority before the machine and child
// grant. Ensure never replaces a revoked child. Registration repeats may return
// the identical record only; a changed engine key or selection is a conflict.
type AgentMachineRepository interface {
	CreateAgentMachine(context.Context, *AgentMachine, string) (*AgentMachine, error)
	GetAgentMachine(context.Context, string) (*AgentMachine, error)
	ListAgentMachines(context.Context, string, string, int) ([]*AgentMachine, error)
	MutateAgentMachine(context.Context, string, AgentMachineMutation) (*AgentMachine, error)
	AgentMachineAuthority(context.Context, string, string) (AgentOAuthAuthority, error)
	GetAgentMachineDelegation(context.Context, string, string) (*AgentAuthorization, error)
	CreateAgentMachineChallenge(context.Context, *AgentMachineChallenge) error
	GetAgentMachineChallenge(context.Context, string) (*AgentMachineChallenge, error)
	ConsumeAgentMachineChallenge(context.Context, string, int64) (bool, error)
	DeleteExpiredAgentMachineChallenges(context.Context, int64, int) error
	EnsureAgentMachineDelegation(context.Context, string, *AgentAuthorization, string, string) (*AgentAuthorization, error)
}

func ValidateMachineDelegation(machine *AgentMachine, authority AgentOAuthAuthority, grant *AgentAuthorization, enginePublicKey, fingerprint string) error {
	if !authority.ValidMachine(machine) || machine.PublicKey != enginePublicKey || authority.Fingerprint() != fingerprint || grant == nil || !validOAuthClientID(grant.ID) || !validOAuthClientID(grant.SessionID) || grant.MachineID != machine.ID || !validMachinePublicKey(grant.MachinePublicKey) || grant.MachinePublicKey == machine.PublicKey || grant.OwnerID != machine.OwnerID || grant.ClientID != machine.ClientID || grant.ClientRevision != machine.ClientRevision || grant.Resource != machine.Resource || grant.Product != machine.Product || !slices.Equal(grant.Scopes, machine.Scopes) || !machine.Allows(grant.AgentID) || !authority.Valid(grant) || grant.Revision != 1 || grant.Decision != AgentAuthorizationApproved || grant.CreatedAtMs <= 0 || grant.ConsentAtMs != grant.CreatedAtMs || grant.GrantExpiresAtMs != 0 || grant.ExpiresAtMs != 0 || grant.RevokedAtMs != 0 || grant.HumanSID != "" || grant.CodeHash != "" || grant.RedirectURI != "" || grant.Challenge != "" {
		return ErrAgentOAuthGrant
	}
	return nil
}

// SameAgentMachineRegistration compares the original request, excluding server
// audit provenance so an identical retry can recover its result after sign-in.
func SameAgentMachineRegistration(a, b *AgentMachine) bool {
	if a == nil || b == nil {
		return false
	}
	left, right := a.Clone(), b.Clone()
	if !slices.Equal(left.Scopes, right.Scopes) || !slices.Equal(left.AgentIDs, right.AgentIDs) || !slices.Equal(left.ExcludedAgentIDs, right.ExcludedAgentIDs) {
		return false
	}
	left.Scopes, right.Scopes = nil, nil
	left.AgentIDs, right.AgentIDs = nil, nil
	left.ExcludedAgentIDs, right.ExcludedAgentIDs = nil, nil
	left.CreatedAtMs, right.CreatedAtMs = 0, 0
	left.RegistrationSID, right.RegistrationSID = "", ""
	left.RenewedAfterRevokedAtMs, right.RenewedAfterRevokedAtMs = 0, 0
	left.RetiredPublicKeys, right.RetiredPublicKeys = nil, nil
	return reflect.DeepEqual(left, right)
}

// RenewedAgentMachine is the registration that replaces current, a revoked
// registration of an installation id, when input is the same owner's new
// registration with an engine key the installation has never held. It is the one
// rule every store applies in CreateAgentMachine after an exact replay of the
// current registration has been recognised. ErrAlreadyExists otherwise: current is
// still active, input is another owner's, or its key is the current or a retired
// one, which is what an exact replay of an earlier registration presents.
func RenewedAgentMachine(current, input *AgentMachine) (*AgentMachine, error) {
	if current == nil || input == nil || current.RevokedAtMs == 0 || current.OwnerID != input.OwnerID ||
		current.PublicKey == input.PublicKey || slices.Contains(current.RetiredPublicKeys, input.PublicKey) {
		return nil, ErrAlreadyExists
	}
	renewed := input.Clone()
	renewed.Revision, renewed.RevokedAtMs, renewed.RenewedAfterRevokedAtMs = current.Revision+1, 0, current.RevokedAtMs
	renewed.RetiredPublicKeys = append(slices.Clone(current.RetiredPublicKeys), current.PublicKey)
	return renewed, nil
}

// RenewedAgentMachineDelegation is the delegation that replaces existing, in
// place, when the revocation machine registered again after is the one that ended
// existing and candidate presents an agent key the delegation has never held.
// renews is false when existing was ended at any other time, such as by the owner
// excluding the agent, and the caller applies its usual rules; it is true with
// ErrAgentOAuthGrant when the key is the one just revoked or a retired one.
//
// The equality of the two times is load-bearing: a machine's revocation stamps
// its still-active delegations with its own revoked_at_ms (migration 0042 and
// its sqlite twin), and nothing else writes that value to a delegation, so it is
// the mark of the delegations that revocation ended. The stores keep it true
// across renewals by moving delegations left at an earlier recovered revocation
// to the latest one (replaceRevokedAgentMachine).
func RenewedAgentMachineDelegation(machine *AgentMachine, existing, candidate *AgentAuthorization) (renewed *AgentAuthorization, renews bool, err error) {
	if machine == nil || existing == nil || candidate == nil || existing.RevokedAtMs == 0 ||
		machine.RenewedAfterRevokedAtMs == 0 || existing.RevokedAtMs != machine.RenewedAfterRevokedAtMs {
		return nil, false, nil
	}
	if candidate.MachinePublicKey == existing.MachinePublicKey ||
		slices.Contains(existing.RetiredMachinePublicKeys, candidate.MachinePublicKey) {
		return nil, true, ErrAgentOAuthGrant
	}
	renewed = candidate.Clone()
	renewed.ID, renewed.Revision, renewed.RevokedAtMs, renewed.ExpiresAtMs = existing.ID, existing.Revision+1, 0, 0
	renewed.RetiredMachinePublicKeys = append(slices.Clone(existing.RetiredMachinePublicKeys), existing.MachinePublicKey)
	return renewed, true, nil
}
