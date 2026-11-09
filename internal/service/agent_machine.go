package service

import (
	"context"
	"crypto/rand"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

// Stable reason codes emitted on rpc_refused warnings across agent-machine and
// agent-OAuth RPCs.
const (
	ReasonUnauthenticated        = "unauthenticated"
	ReasonSessionLookupFailed    = "session_lookup_failed"
	ReasonSessionRevoked         = "session_revoked"
	ReasonSessionProjectMismatch = "session_project_mismatch"
	ReasonSignInNotRecent        = "sign_in_not_recent"
	ReasonMachineNotFound        = "machine_not_found"
	ReasonMachineRevoked         = "machine_revoked"
	ReasonChallengeExpired       = "challenge_expired"
	ReasonSignatureInvalid       = "signature_invalid"
	ReasonKeyInvalid             = "key_invalid"
)

func (s *AgentOAuthService) recordHumanRefusal(ctx context.Context, human AgentOAuthHuman, reason string, extra ...zap.Field) {
	reqProjectID := s.auth.projectID(ctx)
	projectID := reqProjectID
	tenantID := s.auth.tenantID(ctx)
	if info := RefusalInfoFromContext(ctx); info != nil {
		if info.ProjectID != "" {
			projectID = info.ProjectID
		}
		if info.TenantID != "" {
			tenantID = info.TenantID
		}
	}
	fields := make([]zap.Field, 0, len(extra)+6)
	fields = append(fields,
		zap.String("request_project_id", reqProjectID),
		zap.String("project_id", projectID),
		zap.String("tenant_id", tenantID),
	)
	if human.UserID != "" {
		fields = append(fields, zap.String("user_id", human.UserID))
	}
	if human.SID != "" {
		fields = append(fields, zap.String("session_id", human.SID))
	}
	if human.AuthTime > 0 {
		fields = append(fields, zap.Int64("auth_time_age_s", s.auth.nowMs()/1000-human.AuthTime))
	}
	fields = append(fields, extra...)
	RecordRefusal(ctx, s.auth.logger, "rpc_refused", reason, fields...)
}

func (s *AgentOAuthService) recordMachineRefusal(ctx context.Context, machine *AgentMachine, reason string, extra ...zap.Field) {
	reqProjectID := s.auth.projectID(ctx)
	fields := make([]zap.Field, 0, len(extra)+5)
	fields = append(fields,
		zap.String("request_project_id", reqProjectID),
		zap.String("project_id", reqProjectID),
		zap.String("tenant_id", s.auth.tenantID(ctx)),
	)
	if machine != nil {
		if machine.OwnerID != "" {
			fields = append(fields, zap.String("user_id", machine.OwnerID))
		}
		if machine.RegistrationSID != "" {
			fields = append(fields, zap.String("session_id", machine.RegistrationSID))
		}
	}
	fields = append(fields, extra...)
	RecordRefusal(ctx, s.auth.logger, "rpc_refused", reason, fields...)
}

type AgentMachineRegistration struct {
	ID, ClientID, Resource, DisplayName, PublicKey string
	Scopes                                         []string
	AllAgents                                      bool
	AgentIDs, ExcludedAgentIDs                     []string
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
	machine := &AgentMachine{ID: input.ID, OwnerID: human.UserID, ClientID: input.ClientID, ClientRevision: client.Revision, Resource: input.Resource, Product: product, Scopes: slices.Clone(input.Scopes), DisplayName: input.DisplayName, PublicKey: input.PublicKey, RegistrationSID: human.SID, AllAgents: input.AllAgents, AgentIDs: slices.Clone(input.AgentIDs), ExcludedAgentIDs: slices.Clone(input.ExcludedAgentIDs), CreatedAtMs: s.auth.nowMs(), Revision: 1}
	if !validMachinePublicKey(input.PublicKey) {
		s.recordHumanRefusal(ctx, human, ReasonKeyInvalid)
	}
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
	if errors.Is(err, ErrNotFound) {
		s.recordHumanRefusal(ctx, human, ReasonMachineNotFound)
		if errors.Is(err, ErrPermissionDenied) {
			err = ErrPermissionDenied
		}
	} else if errors.Is(err, ErrAgentOAuthGrant) || errors.Is(err, ErrPermissionDenied) {
		s.recordHumanRefusal(ctx, human, ReasonMachineRevoked)
	}
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
	if errors.Is(err, ErrNotFound) {
		s.recordHumanRefusal(ctx, human, ReasonMachineNotFound)
		if errors.Is(err, ErrPermissionDenied) {
			err = ErrPermissionDenied
		}
	} else if errors.Is(err, ErrAgentOAuthGrant) || errors.Is(err, ErrPermissionDenied) {
		s.recordHumanRefusal(ctx, human, ReasonMachineRevoked)
	}
	if err == nil {
		s.auth.audit.Log(ctx, audit.EventAgentMachineRevoked, audit.WithActor(human.UserID), audit.WithTarget(id), audit.WithSuccess(true))
	}
	return err
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

func (s *AgentOAuthService) ExchangeMachine(ctx context.Context, id, agent string, proof AgentMachineProof) (*AgentOAuthTokens, error) {
	machine, _, grant, err := s.machineAccess(ctx, AgentMachineChallengeRequest{MachineID: id, AgentID: agent, Operation: AgentMachineExchange}, proof)
	if err != nil {
		return nil, err
	}
	now := s.auth.nowMs()
	authority, _, err := s.admittedAuthority(ctx, grant)
	if err != nil {
		if errors.Is(err, ErrAgentOAuthGrant) {
			s.recordMachineRefusal(ctx, machine, ReasonMachineRevoked)
		}
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

func (s *AgentOAuthService) MachineAgents(ctx context.Context, id string, proof AgentMachineProof, offset int) (*AgentMachineAgents, error) {
	if offset < 0 || offset > math.MaxInt32-agentOAuthChoicePage {
		return nil, ErrInvalidArgument
	}
	machine, authority, _, err := s.machineAccess(ctx, AgentMachineChallengeRequest{MachineID: id, Operation: AgentMachineRoster, Offset: offset}, proof)
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
		if current.Machine == nil {
			s.recordMachineRefusal(ctx, machine, ReasonMachineNotFound)
		} else {
			s.recordMachineRefusal(ctx, machine, ReasonMachineRevoked)
		}
		return nil, ErrAgentOAuthGrant
	}
	return out, nil
}

type AgentMachineIntrospection struct {
	Active  bool
	Machine *AgentMachine
}

// IntrospectMachine is called only after the handler authenticates the resource.
func (s *AgentOAuthService) IntrospectMachine(ctx context.Context, resource, id string, proof AgentMachineProof) (*AgentMachineIntrospection, error) {
	inactive := &AgentMachineIntrospection{}
	machine, authority, _, err := s.machineAccess(ctx, AgentMachineChallengeRequest{MachineID: id, Operation: AgentMachineInspect}, proof)
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
