package service

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func machineGrantFixture() (*AgentMachine, AgentOAuthAuthority, *AgentAuthorization) {
	_, authority, _ := agentOAuthFixture()
	authority.Client.Registration.GrantTypes = append(authority.Client.Registration.GrantTypes, OAuthGrantAgentMachine)
	authority.Client.Registration.Resources[0].Product = "files"
	machine := &AgentMachine{ID: "machine", OwnerID: authority.Owner.ID, ClientID: authority.Client.ID, ClientRevision: 1, Resource: "https://files.example.test", Product: "files", Scopes: []string{"files:read"}, DisplayName: "Example desktop", CredentialHash: oauthHash("credential"), RegistrationSID: authority.HumanSession.SID, AllAgents: true, CreatedAtMs: 1000, Revision: 1}
	authority.Machine = machine
	grant := &AgentAuthorization{ID: "grant", MachineID: machine.ID, ClientID: machine.ClientID, ClientRevision: 1, Resource: machine.Resource, Product: machine.Product, Scopes: []string{"files:read"}, CreatedAtMs: 2000, ConsentAtMs: 2000, Revision: 1, Decision: AgentAuthorizationApproved, OwnerID: machine.OwnerID, AgentID: authority.Agent.ID, SessionID: "agent-session"}
	return machine, authority, grant
}

func TestMachineAuthoritySurvivesHumanSessionLossButNeverOwnerOrAgentLoss(t *testing.T) {
	machine, authority, grant := machineGrantFixture()
	require.NoError(t, ValidateAgentMachine(machine))
	require.True(t, authority.ValidMachineRegistration(machine))
	authority.HumanSession = nil
	require.True(t, authority.ValidMachine(machine))
	require.True(t, authority.Valid(grant))
	require.False(t, authority.ValidMachineRegistration(machine))
	require.NoError(t, ValidateMachineDelegation(machine, authority, grant, machine.CredentialHash, authority.Fingerprint()))
	next, err := ApplyAgentOAuthMutation(grant, authority, nil, AgentOAuthMutation{Operation: AgentOAuthValidate, AtMs: 9999999999999, AuthorityFingerprint: authority.Fingerprint()})
	require.NoError(t, err)
	require.Equal(t, grant, next)
	for name, change := range map[string]func(*AgentOAuthAuthority){
		"transfer":                func(a *AgentOAuthAuthority) { a.Agent.OwnerUserID = "other" },
		"agent paused":            func(a *AgentOAuthAuthority) { a.Agent.Status = "inactive" },
		"human suspended":         func(a *AgentOAuthAuthority) { a.Owner.Status = "inactive" },
		"human replaced by agent": func(a *AgentOAuthAuthority) { a.Owner.Kind = UserKindAgent },
		"client revision":         func(a *AgentOAuthAuthority) { a.Client.Revision++ },
		"machine revoked":         func(a *AgentOAuthAuthority) { a.Machine.RevokedAtMs = 3000 },
		"agent excluded":          func(a *AgentOAuthAuthority) { a.Machine.ExcludedAgentIDs = []string{grant.AgentID} },
		"scope widened":           func(a *AgentOAuthAuthority) { a.Machine.Scopes = append(a.Machine.Scopes, "files:write") },
	} {
		t.Run(name, func(t *testing.T) { _, a, g := machineGrantFixture(); change(&a); require.False(t, a.Valid(g)) })
	}
}

func TestMachineSelectionRevisionAndRevocation(t *testing.T) {
	machine, _, _ := machineGrantFixture()
	require.True(t, machine.Allows("future-agent"))
	selected, err := ApplyAgentMachineMutation(machine, AgentMachineMutation{Operation: AgentMachineSelect, OwnerID: machine.OwnerID, AtMs: 2000, ExpectedRevision: 1, AllAgents: false, AgentIDs: []string{"agent"}})
	require.NoError(t, err)
	require.True(t, selected.Allows("agent"))
	require.False(t, selected.Allows("future-agent"))
	require.True(t, machine.Allows("future-agent"))
	_, err = ApplyAgentMachineMutation(selected, AgentMachineMutation{Operation: AgentMachineSelect, OwnerID: machine.OwnerID, AtMs: 2001, ExpectedRevision: 1, AllAgents: true})
	require.ErrorIs(t, err, ErrAgentOAuthRevision)
	_, err = ApplyAgentMachineMutation(selected, AgentMachineMutation{Operation: AgentMachineRevoke, OwnerID: "other", AtMs: 2001})
	require.ErrorIs(t, err, ErrPermissionDenied)
	revoked, err := ApplyAgentMachineMutation(selected, AgentMachineMutation{Operation: AgentMachineRevoke, OwnerID: machine.OwnerID, AtMs: 2001})
	require.NoError(t, err)
	require.False(t, revoked.Allows("agent"))
	_, err = ApplyAgentMachineMutation(revoked, AgentMachineMutation{Operation: AgentMachineSelect, OwnerID: machine.OwnerID, AtMs: 2002, ExpectedRevision: revoked.Revision, AllAgents: true})
	require.ErrorIs(t, err, ErrAgentOAuthGrant)
	again, err := ApplyAgentMachineMutation(revoked, AgentMachineMutation{Operation: AgentMachineRevoke, OwnerID: machine.OwnerID, AtMs: 2003})
	require.NoError(t, err)
	require.Equal(t, revoked, again)
}

func TestMachineInputAndCredentialBounds(t *testing.T) {
	for _, selection := range []struct {
		all           bool
		ids, excluded []string
	}{
		{true, []string{"agent"}, nil}, {false, []string{"agent", "agent"}, nil}, {false, []string{"agent"}, []string{"agent"}}, {true, nil, []string{"bad/id"}}, {false, make([]string, MaxAgentMachineSelection+1), nil},
	} {
		require.False(t, validMachineSelection(selection.all, selection.ids, selection.excluded))
	}
	raw := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	require.True(t, validAgentMachineCredential(raw))
	for _, bad := range []string{"", raw + "=", raw[:42], strings.Repeat("x", 100000), strings.Repeat("/", 43), strings.Repeat("A", 42) + "B"} {
		require.False(t, validAgentMachineCredential(bad))
	}
	machine, _, _ := machineGrantFixture()
	clone := machine.Clone()
	clone.Scopes[0] = "changed"
	require.Equal(t, "files:read", machine.Scopes[0])
	changed := machine.Clone()
	changed.RegistrationSID = "fresh-human-session"
	changed.CreatedAtMs++
	require.True(t, SameAgentMachineRegistration(machine, changed))
	changed.CredentialHash = oauthHash("different")
	require.False(t, SameAgentMachineRegistration(machine, changed))
	changed = machine.Clone()
	changed.CredentialHash = strings.Repeat("A", 64)
	require.ErrorIs(t, ValidateAgentMachine(changed), ErrInvalidArgument)
	require.False(t, SameAgentMachineRegistration(nil, machine))
}

func TestMachineExchangeCannotUseBrowserCodeOrRefreshPaths(t *testing.T) {
	_, authority, grant := machineGrantFixture()
	for _, operation := range []string{AgentOAuthRedeem, AgentOAuthRotate} {
		_, err := ApplyAgentOAuthMutation(grant, authority, nil, AgentOAuthMutation{Operation: operation, AtMs: 3000, AuthorityFingerprint: authority.Fingerprint()})
		require.ErrorIs(t, err, ErrAgentOAuthGrant)
	}
}
