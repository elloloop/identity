package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
)

const (
	AgentAuthorizationPending  = "pending"
	AgentAuthorizationApproved = "approved"
	AgentAuthorizationDenied   = "denied"
	AgentOAuthApprove          = "approve"
	AgentOAuthDeny             = "deny"
	AgentOAuthRedeem           = "redeem"
	AgentOAuthRotate           = "rotate"
	AgentOAuthRevoke           = "revoke"
	AgentOAuthValidate         = "validate"
)

var (
	ErrAgentOAuthGrant    = errors.New("invalid delegated grant")
	ErrAgentOAuthRevision = errors.New("authorization request changed")
)

// AgentAuthorization is the durable aggregate a consent decision owns. Only
// hashes of codes and refresh credentials are persisted. Revocation is terminal.
type AgentAuthorization struct {
	ID               string
	MachineID        string
	MachinePublicKey string
	ClientID         string
	ClientRevision   int64
	RedirectURI      string
	State            string
	Resource         string
	Product          string
	Scopes           []string
	Challenge        string
	CreatedAtMs      int64
	ExpiresAtMs      int64
	Revision         int64
	Decision         string
	OwnerID          string
	AgentID          string
	HumanSID         string
	ConsentAtMs      int64
	GrantExpiresAtMs int64
	CodeHash         string
	CodeExpiresAtMs  int64
	CodeUsedAtMs     int64
	SessionID        string
	RevokedAtMs      int64
}

func (r *AgentAuthorization) Clone() *AgentAuthorization {
	if r == nil {
		return nil
	}
	out := *r
	out.Scopes = slices.Clone(r.Scopes)
	return &out
}

type AgentOAuthAuthority struct {
	Owner        *User
	Agent        *User
	HumanSession *SessionRecord
	Client       *OAuthClient
	HasGuardian  bool
	Machine      *AgentMachine
}

type agentOAuthUserAuthority struct {
	ID, Kind, OwnerID, Status, MergedID, Email, Username, Role, PasswordHash, Market string
	Anonymous, EmailVerified, IDVVerified, PasswordChangeRequired                    bool
	DOB                                                                              int64
}

func agentOAuthUserSnapshot(u *User) *agentOAuthUserAuthority {
	if u == nil {
		return nil
	}
	return &agentOAuthUserAuthority{ID: u.ID, Kind: u.Kind, OwnerID: u.OwnerUserID, Status: u.Status, MergedID: u.MergedIntoUserID, Email: u.Email, Username: u.Username, Role: u.Role, PasswordHash: u.PasswordHash, Market: u.Market, Anonymous: u.IsAnonymous, EmailVerified: u.EmailVerified, IDVVerified: u.IDVVerified, PasswordChangeRequired: u.PasswordChangeRequired, DOB: u.DateOfBirthMs}
}

// Fingerprint binds admission to the exact authority rows re-read under locks.
func (a AgentOAuthAuthority) Fingerprint() string {
	snapshot := struct {
		Owner, Agent *agentOAuthUserAuthority
		Session      *SessionRecord
		Client       *OAuthClient
		HasGuardian  bool
		Machine      *AgentMachine
	}{agentOAuthUserSnapshot(a.Owner), agentOAuthUserSnapshot(a.Agent), a.HumanSession, a.Client, a.HasGuardian, a.Machine}
	data, _ := json.Marshal(snapshot)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (a AgentOAuthAuthority) Valid(r *AgentAuthorization) bool {
	if r != nil && r.MachineID != "" {
		return a.ValidMachine(a.Machine) && a.Machine.ID == r.MachineID && validMachinePublicKey(r.MachinePublicKey) && r.MachinePublicKey != a.Machine.PublicKey && a.Machine.Allows(r.AgentID) && a.Agent != nil && a.Agent.IsAgent() && isActiveStatus(a.Agent.Status) && a.Agent.OwnerUserID == r.OwnerID && a.Agent.ID == r.AgentID && a.Machine.OwnerID == r.OwnerID && r.ClientID == a.Machine.ClientID && r.ClientRevision == a.Machine.ClientRevision && r.Resource == a.Machine.Resource && r.Product == a.Machine.Product && slices.Equal(r.Scopes, a.Machine.Scopes) && r.HumanSID == "" && r.GrantExpiresAtMs == 0
	}
	return r != nil && isEligibleAgentOwner(a.Owner) && a.Agent != nil && a.Agent.IsAgent() &&
		isActiveStatus(a.Agent.Status) && a.Agent.OwnerUserID == a.Owner.ID && a.Owner.ID == r.OwnerID &&
		a.Agent.ID == r.AgentID && a.HumanSession != nil && a.HumanSession.SID == r.HumanSID &&
		a.HumanSession.UserID == r.OwnerID && a.HumanSession.RevokedAtMs == 0 &&
		a.Client != nil && a.Client.ID == r.ClientID && a.Client.Revision == r.ClientRevision &&
		a.Client.ValidateOAuthRequest(r.RedirectURI, r.Resource, r.Scopes, OAuthGrantAuthorizationCode) == nil
}

type AgentOAuthMutation struct {
	Operation            string
	AtMs                 int64
	ExpectedRevision     int64
	AuthorityFingerprint string
	OwnerID              string
	AgentID              string
	HumanSID             string
	GrantExpiresAtMs     int64
	CodeHash             string
	CodeExpiresAtMs      int64
	SessionID            string
	RefreshHash          string
	NextRefreshHash      string
	RefreshExpiresAtMs   int64
}

type AgentOAuthRefresh struct {
	Hash            string
	AuthorizationID string
	ExpiresAtMs     int64
	ConsumedAtMs    int64
}

// AgentOAuthRepository operations are project scoped. Mutate re-reads and locks
// persons before agents, client, human session and authorization. It commits a
// replay-triggered revocation even though that transition returns ErrAgentOAuthGrant.
type AgentOAuthRepository interface {
	CreateAgentAuthorization(context.Context, *AgentAuthorization) error
	GetAgentAuthorization(context.Context, string) (*AgentAuthorization, error)
	FindAgentAuthorizationByCode(context.Context, string) (*AgentAuthorization, error)
	FindAgentAuthorizationByRefresh(context.Context, string) (*AgentAuthorization, error)
	AgentOAuthAuthority(context.Context, string, string, string, string) (AgentOAuthAuthority, error)
	MutateAgentAuthorization(context.Context, string, AgentOAuthMutation) (*AgentAuthorization, error)
	ListAgentAuthorizations(context.Context, string, string, int) ([]*AgentAuthorization, error)
	DeleteExpiredAgentAuthorizations(context.Context, int64, int) error
}

func ValidateAgentAuthorization(r *AgentAuthorization) error {
	if r == nil || !validOAuthClientID(r.ID) || !validOAuthClientID(r.ClientID) || r.ClientRevision <= 0 ||
		r.Revision != 1 || r.Decision != AgentAuthorizationPending || r.CreatedAtMs <= 0 || r.ExpiresAtMs <= r.CreatedAtMs ||
		r.MachineID != "" || r.MachinePublicKey != "" || r.OwnerID != "" || r.AgentID != "" || r.HumanSID != "" || r.CodeHash != "" || r.SessionID != "" ||
		r.GrantExpiresAtMs != 0 || r.RevokedAtMs != 0 || !boundedOAuthStrings(r.Scopes, maxOAuthScopes) || !ValidS256Challenge(r.Challenge) {
		return ErrInvalidArgument
	}
	return nil
}

func ValidS256Challenge(challenge string) bool {
	if len(challenge) != (sha256.Size*8+5)/6 {
		return false
	}
	for _, r := range challenge {
		if r < 'a' || r > 'z' {
			if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
				continue
			}
			return false
		}
	}
	return true
}

func hashEqual(left, right string) bool {
	return len(left) == hex.EncodedLen(sha256.Size) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

// ApplyAgentOAuthMutation is pure. Stores persist its returned aggregate even
// on a refusal when a valid-family replay has terminally revoked authority.
func ApplyAgentOAuthMutation(current *AgentAuthorization, authority AgentOAuthAuthority, refresh *AgentOAuthRefresh, m AgentOAuthMutation) (*AgentAuthorization, error) {
	if current == nil || m.AtMs <= 0 {
		return nil, ErrAgentOAuthGrant
	}
	next := current.Clone()
	if m.Operation == AgentOAuthRevoke {
		if m.OwnerID == "" || m.OwnerID != next.OwnerID {
			return nil, ErrPermissionDenied
		}
		if next.RevokedAtMs == 0 {
			next.RevokedAtMs = m.AtMs
			next.Revision++
		}
		return next, nil
	}
	if next.RevokedAtMs != 0 {
		return nil, ErrAgentOAuthGrant
	}
	if m.Operation == AgentOAuthApprove || m.Operation == AgentOAuthDeny {
		return applyAgentOAuthConsent(next, authority, m)
	}
	if next.Decision != AgentAuthorizationApproved || (next.MachineID == "" && next.GrantExpiresAtMs <= m.AtMs) || !authority.Valid(next) || authority.Fingerprint() != m.AuthorityFingerprint {
		return nil, ErrAgentOAuthGrant
	}
	if next.MachineID != "" && m.Operation != AgentOAuthValidate {
		return nil, ErrAgentOAuthGrant
	}
	switch m.Operation {
	case AgentOAuthValidate:
		return next, nil
	case AgentOAuthRedeem:
		if next.CodeUsedAtMs != 0 || next.CodeExpiresAtMs <= m.AtMs || !hashEqual(next.CodeHash, m.CodeHash) || !validOAuthClientID(m.SessionID) {
			return nil, ErrAgentOAuthGrant
		}
		if m.NextRefreshHash != "" && (!slices.Contains(authority.Client.Registration.GrantTypes, OAuthGrantRefreshToken) || !validAgentOAuthRefresh(m, next)) {
			return nil, ErrAgentOAuthGrant
		}
		next.CodeUsedAtMs = m.AtMs
		next.SessionID = m.SessionID
		next.Revision++
	case AgentOAuthRotate:
		if refresh == nil || !hashEqual(refresh.Hash, m.RefreshHash) || refresh.AuthorizationID != next.ID {
			return nil, ErrAgentOAuthGrant
		}
		if refresh.ConsumedAtMs != 0 {
			next.RevokedAtMs = m.AtMs
			next.Revision++
			return next, ErrAgentOAuthGrant
		}
		if refresh.ExpiresAtMs <= m.AtMs || next.SessionID == "" || !validAgentOAuthRefresh(m, next) {
			return nil, ErrAgentOAuthGrant
		}
		next.Revision++
	default:
		return nil, ErrInvalidArgument
	}
	return next, nil
}

func AgentOAuthAuthorityLost(before, after *User) bool {
	if before == nil {
		return false
	}
	return after == nil || before.OwnerUserID != after.OwnerUserID || before.Kind != after.Kind ||
		before.Status != after.Status || before.IsAnonymous != after.IsAnonymous || before.MergedIntoUserID != after.MergedIntoUserID ||
		before.PasswordHash != after.PasswordHash || before.PasswordChangeRequired != after.PasswordChangeRequired || before.Email != after.Email || before.EmailVerified != after.EmailVerified || before.IDVVerified != after.IDVVerified ||
		before.DateOfBirthMs != after.DateOfBirthMs || before.Market != after.Market || before.Role != after.Role
}

func applyAgentOAuthConsent(next *AgentAuthorization, authority AgentOAuthAuthority, m AgentOAuthMutation) (*AgentAuthorization, error) {
	if next.Decision != AgentAuthorizationPending || next.ExpiresAtMs <= m.AtMs || next.Revision != m.ExpectedRevision {
		return nil, ErrAgentOAuthRevision
	}
	if m.Operation == AgentOAuthDeny {
		if !isEligibleAgentOwner(authority.Owner) || authority.Owner.ID != m.OwnerID || authority.HumanSession == nil || authority.HumanSession.UserID != m.OwnerID || authority.HumanSession.SID != m.HumanSID || authority.HumanSession.RevokedAtMs != 0 || authority.Fingerprint() != m.AuthorityFingerprint {
			return nil, ErrPermissionDenied
		}
		next.OwnerID = m.OwnerID
		next.HumanSID = m.HumanSID
		next.Decision = AgentAuthorizationDenied
		next.Revision++
		return next, nil
	}
	next.OwnerID = m.OwnerID
	next.AgentID = m.AgentID
	next.HumanSID = m.HumanSID
	if !authority.Valid(next) || authority.Fingerprint() != m.AuthorityFingerprint || m.GrantExpiresAtMs <= m.AtMs || m.CodeExpiresAtMs <= m.AtMs || m.CodeExpiresAtMs > next.ExpiresAtMs || len(m.CodeHash) != hex.EncodedLen(sha256.Size) {
		return nil, ErrPermissionDenied
	}
	next.Decision = AgentAuthorizationApproved
	next.ConsentAtMs = m.AtMs
	next.GrantExpiresAtMs = m.GrantExpiresAtMs
	next.CodeHash = m.CodeHash
	next.CodeExpiresAtMs = m.CodeExpiresAtMs
	next.Revision++
	return next, nil
}

func validAgentOAuthRefresh(m AgentOAuthMutation, grant *AgentAuthorization) bool {
	return len(m.NextRefreshHash) == hex.EncodedLen(sha256.Size) && m.RefreshExpiresAtMs > m.AtMs && m.RefreshExpiresAtMs <= grant.GrantExpiresAtMs
}
