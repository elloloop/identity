package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/elloloop/identity/pkg/audit"
	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

type AgentMachineRegistration struct {
	ID, ClientID, Resource, DisplayName, CredentialHash string
	Scopes                                              []string
	AllAgents                                           bool
	AgentIDs, ExcludedAgentIDs                          []string
}

type AgentMachineAgents struct {
	Agents     []*User
	NextOffset int32
}

func (s *AgentOAuthService) machineRepo(ctx context.Context) (AgentMachineRepository, error) {
	if !s.auth.cfg.AgentMachineEnabled {
		return nil, ErrAgentOAuthDisabled
	}
	repo, ok := s.base.WithProject(s.auth.projectID(ctx)).(AgentMachineRepository)
	if !ok {
		return nil, errors.New("durable agent access requires a supported repository")
	}
	return repo, nil
}

func (s *AgentOAuthService) RegisterMachine(ctx context.Context, human AgentOAuthHuman, input AgentMachineRegistration) (*AgentMachine, error) {
	repo, err := s.machineRepo(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = s.human(ctx, human, true); err != nil {
		return nil, err
	}
	client, err := s.auth.repo(ctx).GetOAuthClient(ctx, input.ClientID)
	if err != nil {
		return nil, err
	}
	if client.ValidateMachineRequest(input.Resource, input.Scopes) != nil || !s.resourceConfigured(ctx, input.Resource) {
		return nil, ErrPermissionDenied
	}
	product := ""
	for _, bound := range client.Registration.Resources {
		if bound.Resource == input.Resource {
			product = bound.Product
			break
		}
	}
	authority, err := s.repo(ctx).AgentOAuthAuthority(ctx, human.UserID, "", human.SID, input.ClientID)
	if err != nil {
		return nil, err
	}
	if err = s.admitOwner(ctx, authority.Owner, product); err != nil {
		return nil, err
	}
	machine := &AgentMachine{ID: input.ID, OwnerID: human.UserID, ClientID: input.ClientID, ClientRevision: client.Revision, Resource: input.Resource, Product: product, Scopes: slices.Clone(input.Scopes), DisplayName: input.DisplayName, CredentialHash: input.CredentialHash, RegistrationSID: human.SID, AllAgents: input.AllAgents, AgentIDs: slices.Clone(input.AgentIDs), ExcludedAgentIDs: slices.Clone(input.ExcludedAgentIDs), CreatedAtMs: s.auth.nowMs(), Revision: 1}
	if err = ValidateAgentMachine(machine); err != nil {
		return nil, err
	}
	saved, err := repo.CreateAgentMachine(ctx, machine, authority.Fingerprint())
	if err == nil {
		s.auth.audit.Log(ctx, audit.EventAgentMachineRegistered, audit.WithActor(human.UserID), audit.WithTarget(saved.ID), audit.WithSuccess(true))
	}
	return saved, err
}

func (s *AgentOAuthService) ListMachines(ctx context.Context, human AgentOAuthHuman, after string, limit int) ([]*AgentMachine, error) {
	repo, err := s.machineRepo(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = s.human(ctx, human, false); err != nil {
		return nil, err
	}
	if limit == 0 {
		limit = defaultAgentOAuthListLimit
	}
	if limit < 1 || limit > MaxAgentOAuthListLimit || after != "" && !validOAuthClientID(after) {
		return nil, ErrInvalidArgument
	}
	return repo.ListAgentMachines(ctx, human.UserID, after, limit)
}

func (s *AgentOAuthService) SelectMachineAgents(ctx context.Context, human AgentOAuthHuman, id string, revision int64, all bool, ids, excluded []string) (*AgentMachine, error) {
	repo, err := s.machineRepo(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = s.human(ctx, human, true); err != nil {
		return nil, err
	}
	if !validOAuthClientID(id) {
		return nil, ErrInvalidArgument
	}
	saved, err := repo.MutateAgentMachine(ctx, id, AgentMachineMutation{Operation: AgentMachineSelect, OwnerID: human.UserID, AtMs: s.auth.nowMs(), ExpectedRevision: revision, AllAgents: all, AgentIDs: ids, ExcludedAgentIDs: excluded})
	if err == nil {
		s.auth.audit.Log(ctx, audit.EventAgentMachineSelection, audit.WithActor(human.UserID), audit.WithTarget(id), audit.WithSuccess(true))
	}
	return saved, err
}

func (s *AgentOAuthService) RevokeMachine(ctx context.Context, human AgentOAuthHuman, id string) error {
	repo, err := s.machineRepo(ctx)
	if err != nil {
		return err
	}
	if _, err = s.human(ctx, human, false); err != nil {
		return err
	}
	if !validOAuthClientID(id) {
		return ErrInvalidArgument
	}
	_, err = repo.MutateAgentMachine(ctx, id, AgentMachineMutation{Operation: AgentMachineRevoke, OwnerID: human.UserID, AtMs: s.auth.nowMs()})
	if err == nil {
		s.auth.audit.Log(ctx, audit.EventAgentMachineRevoked, audit.WithActor(human.UserID), audit.WithTarget(id), audit.WithSuccess(true))
	}
	return err
}

func validAgentMachineCredential(raw string) bool {
	if len(raw) != 43 {
		return false
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	return err == nil && len(data) == 32 && base64.RawURLEncoding.EncodeToString(data) == raw
}

func (s *AgentOAuthService) machineAccess(ctx context.Context, id, credential, agent string) (*AgentMachine, AgentOAuthAuthority, error) {
	repo, err := s.machineRepo(ctx)
	if err != nil {
		return nil, AgentOAuthAuthority{}, err
	}
	if !validOAuthClientID(id) || !validAgentMachineCredential(credential) {
		return nil, AgentOAuthAuthority{}, ErrUnauthenticated
	}
	authority, err := repo.AgentMachineAuthority(ctx, id, agent)
	if err != nil {
		return nil, authority, err
	}
	machine := authority.Machine
	if machine == nil || !hashEqual(machine.CredentialHash, agentOAuthHash(credential)) {
		return nil, authority, ErrUnauthenticated
	}
	if !authority.ValidMachine(machine) {
		return nil, authority, ErrAgentOAuthGrant
	}
	if !s.resourceConfigured(ctx, machine.Resource) {
		return nil, authority, s.invalidateMachine(ctx, machine)
	}
	if err = s.admitOwner(ctx, authority.Owner, machine.Product); err != nil {
		if isAgentOAuthAdmissionRefusal(err) {
			return nil, authority, s.invalidateMachine(ctx, machine)
		}
		return nil, authority, err
	}
	return machine, authority, nil
}

func (s *AgentOAuthService) invalidateMachine(ctx context.Context, machine *AgentMachine) error {
	repo, err := s.machineRepo(ctx)
	if err != nil {
		return err
	}
	_, err = repo.MutateAgentMachine(ctx, machine.ID, AgentMachineMutation{Operation: AgentMachineRevoke, OwnerID: machine.OwnerID, AtMs: s.auth.nowMs()})
	if err != nil {
		return err
	}
	s.auth.audit.Log(ctx, audit.EventAgentMachineRevoked, audit.WithActor(machine.OwnerID), audit.WithTarget(machine.ID), audit.WithSuccess(true))
	return ErrAgentOAuthGrant
}

func (s *AgentOAuthService) ExchangeMachine(ctx context.Context, id, credential, agent string) (*AgentOAuthTokens, error) {
	if !validOAuthClientID(agent) {
		return nil, ErrInvalidArgument
	}
	machine, authority, err := s.machineAccess(ctx, id, credential, agent)
	if err != nil {
		return nil, err
	}
	now := s.auth.nowMs()
	proposal := &AgentAuthorization{ID: rand.Text(), MachineID: machine.ID, ClientID: machine.ClientID, ClientRevision: machine.ClientRevision, Resource: machine.Resource, Product: machine.Product, Scopes: slices.Clone(machine.Scopes), CreatedAtMs: now, ConsentAtMs: now, Revision: 1, Decision: AgentAuthorizationApproved, OwnerID: machine.OwnerID, AgentID: agent, SessionID: rand.Text()}
	repo, err := s.machineRepo(ctx)
	if err != nil {
		return nil, err
	}
	grant, err := repo.EnsureAgentMachineDelegation(ctx, id, proposal, agentOAuthHash(credential), authority.Fingerprint())
	if err != nil {
		return nil, err
	}
	if grant.RevokedAtMs != 0 {
		return nil, ErrAgentOAuthGrant
	}
	authority, _, err = s.admittedAuthority(ctx, grant)
	if err != nil {
		return nil, err
	}
	expires := now + int64(s.auth.cfg.AgentOAuthAccessSeconds)*time.Second.Milliseconds()
	if expires <= now {
		return nil, ErrAgentOAuthGrant
	}
	owner := *authority.Owner
	s.auth.stampAgeBand(WithProduct(ctx, grant.Product), &owner)
	claims := jwtpkg.DelegatedAccessClaims{Sub: grant.AgentID, Kind: UserKindAgent, Actor: jwtpkg.DelegatedActor{Sub: grant.OwnerID}, Issuer: s.auth.cfg.JWTIssuer, Project: s.auth.projectID(ctx), Audience: []string{grant.Resource}, ClientID: grant.ClientID, Scope: strings.Join(grant.Scopes, " "), GrantID: grant.ID, SID: grant.SessionID, IssuedAt: now / 1000, ExpiresAt: expires / 1000, JWTID: rand.Text(), IsMinor: owner.IsMinor}
	token, err := s.signer.SignDelegatedAccessToken(ctx, claims)
	if err != nil {
		return nil, err
	}
	if _, err = s.repo(ctx).MutateAgentAuthorization(ctx, grant.ID, AgentOAuthMutation{Operation: AgentOAuthValidate, AtMs: now, AuthorityFingerprint: authority.Fingerprint()}); err != nil {
		return nil, err
	}
	s.auth.audit.Log(ctx, audit.EventAgentOAuthIssued, audit.WithActor(grant.OwnerID), audit.WithTarget(grant.ID), audit.WithSuccess(true), audit.WithDetails(map[string]any{"agent_id": grant.AgentID, "client_id": grant.ClientID, "operation": OAuthGrantAgentMachine}))
	lifetime := claims.ExpiresAt - claims.IssuedAt
	if lifetime <= 0 {
		return nil, ErrAgentOAuthGrant
	}
	return &AgentOAuthTokens{AccessToken: token, ExpiresIn: uint64(lifetime), Scope: claims.Scope}, nil
}

func (s *AgentOAuthService) MachineAgents(ctx context.Context, id, credential string, offset int) (*AgentMachineAgents, error) {
	if offset < 0 || offset > math.MaxInt32-agentOAuthChoicePage {
		return nil, ErrInvalidArgument
	}
	machine, authority, err := s.machineAccess(ctx, id, credential, "")
	if err != nil {
		return nil, err
	}
	users, err := s.auth.repo(ctx).ListUsers(ctx, UserListFilter{IncludeAgents: true, OwnerUserID: machine.OwnerID, Offset: offset, Limit: agentOAuthChoicePage})
	if err != nil {
		return nil, err
	}
	out := &AgentMachineAgents{NextOffset: -1}
	for _, user := range users {
		if user.IsAgent() && isActiveStatus(user.Status) && machine.Allows(user.ID) {
			out.Agents = append(out.Agents, user)
		}
	}
	if len(users) == agentOAuthChoicePage {
		nextOffset := int64(offset) + int64(len(users))
		if nextOffset > math.MaxInt32 || nextOffset < 0 {
			return nil, ErrInvalidArgument
		}
		out.NextOffset = int32(nextOffset)
	}

	repo, err := s.machineRepo(ctx)
	if err != nil {
		return nil, err
	}
	current, err := repo.AgentMachineAuthority(ctx, id, "")
	if err != nil {
		return nil, err
	}
	if !current.ValidMachine(current.Machine) || current.Fingerprint() != authority.Fingerprint() {
		return nil, ErrAgentOAuthGrant
	}
	return out, nil
}

type AgentMachineIntrospection struct {
	Active  bool
	Machine *AgentMachine
}

// IntrospectMachine is called only after the handler authenticates the resource.
func (s *AgentOAuthService) IntrospectMachine(ctx context.Context, resource, id, credential string) (*AgentMachineIntrospection, error) {
	inactive := &AgentMachineIntrospection{}
	machine, authority, err := s.machineAccess(ctx, id, credential, "")
	if errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrAgentOAuthGrant) {
		return inactive, nil
	}
	if err != nil {
		return nil, err
	}
	if machine.Resource != resource {
		return inactive, nil
	}
	repo, err := s.machineRepo(ctx)
	if err != nil {
		return nil, err
	}
	current, err := repo.AgentMachineAuthority(ctx, id, "")
	if err != nil {
		return nil, err
	}
	if !current.ValidMachine(current.Machine) || current.Fingerprint() != authority.Fingerprint() {
		return inactive, nil
	}
	return &AgentMachineIntrospection{Active: true, Machine: current.Machine}, nil
}
