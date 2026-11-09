package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"github.com/elloloop/identity/pkg/audit"
)

func (s *AgentOAuthService) currentMachine(ctx context.Context, id, agent string) (*AgentMachine, AgentOAuthAuthority, error) {
	repo, err := s.machineRepo(ctx)
	if err != nil {
		return nil, AgentOAuthAuthority{}, err
	}
	if !validOAuthClientID(id) {
		s.recordMachineRefusal(ctx, nil, ReasonMachineNotFound)
		return nil, AgentOAuthAuthority{}, ErrUnauthenticated
	}
	authority, err := repo.AgentMachineAuthority(ctx, id, agent)
	if err != nil {
		return nil, authority, err
	}
	machine := authority.Machine
	if machine == nil {
		s.recordMachineRefusal(ctx, nil, ReasonMachineNotFound)
		return nil, authority, ErrUnauthenticated
	}
	if !authority.ValidMachine(machine) {
		s.recordMachineRefusal(ctx, machine, ReasonMachineRevoked)
		return nil, authority, ErrAgentOAuthGrant
	}
	if !s.resourceConfigured(ctx, machine.Resource) {
		s.recordMachineRefusal(ctx, machine, ReasonMachineRevoked)
		return nil, authority, s.invalidateMachine(ctx, machine)
	}
	if err = s.admitOwner(ctx, authority.Owner, machine.Product); err != nil {
		if isAgentOAuthAdmissionRefusal(err) {
			s.recordMachineRefusal(ctx, machine, ReasonMachineRevoked)
			return nil, authority, s.invalidateMachine(ctx, machine)
		}
		return nil, authority, err
	}
	return machine, authority, nil
}

func (s *AgentOAuthService) challengeSigner(ctx context.Context, request AgentMachineChallengeRequest) (*AgentMachine, AgentOAuthAuthority, string, *AgentAuthorization, error) {
	machine, authority, err := s.currentMachine(ctx, request.MachineID, request.AgentID)
	if err != nil {
		return nil, authority, "", nil, err
	}
	if request.Operation == AgentMachineEnroll {
		if request.PublicKey == machine.PublicKey {
			s.recordMachineRefusal(ctx, machine, ReasonKeyInvalid)
			return nil, authority, "", nil, ErrPermissionDenied
		}
		agent := authority.Agent
		if agent == nil || !agent.IsAgent() || !isActiveStatus(agent.Status) || agent.OwnerUserID != machine.OwnerID || !machine.Allows(agent.ID) {
			s.recordMachineRefusal(ctx, machine, ReasonMachineRevoked)
			return nil, authority, "", nil, ErrPermissionDenied
		}
	}
	if request.Operation != AgentMachineExchange {
		return machine, authority, machine.PublicKey, nil, nil
	}
	repo, err := s.machineRepo(ctx)
	if err != nil {
		return nil, authority, "", nil, err
	}
	grant, err := repo.GetAgentMachineDelegation(ctx, machine.ID, request.AgentID)
	if err != nil {
		return nil, authority, "", nil, err
	}
	if grant == nil {
		s.recordMachineRefusal(ctx, machine, ReasonMachineRevoked)
		return nil, authority, "", nil, ErrAgentOAuthGrant
	}
	admitted, _, err := s.admittedAuthority(ctx, grant)
	if err != nil {
		if errors.Is(err, ErrAgentOAuthGrant) {
			s.recordMachineRefusal(ctx, machine, ReasonMachineRevoked)
		}
		return nil, authority, "", nil, err
	}
	return admitted.Machine, admitted, grant.MachinePublicKey, grant, nil
}

func (s *AgentOAuthService) CreateMachineChallenge(ctx context.Context, request AgentMachineChallengeRequest) (*AgentMachineChallenge, error) {
	if request.Operation == AgentMachineEnroll && validOAuthClientID(request.MachineID) && validOAuthClientID(request.AgentID) && !validMachinePublicKey(request.PublicKey) {
		if _, err := s.machineRepo(ctx); err == nil {
			s.recordMachineRefusal(ctx, nil, ReasonKeyInvalid)
		}
	}
	binding, err := request.binding()
	if err != nil {
		return nil, err
	}
	machine, _, key, _, err := s.challengeSigner(ctx, request)
	if err != nil {
		return nil, err
	}
	now := s.auth.nowMs()
	challenge := &AgentMachineChallenge{ID: rand.Text(), MachineID: machine.ID, AgentID: request.AgentID, Operation: request.Operation, Binding: binding, PublicKey: key, CreatedAtMs: now, ExpiresAtMs: now + AgentMachineChallengeLifetimeMs}
	message, err := json.Marshal(struct {
		Domain      string `json:"domain"`
		Issuer      string `json:"issuer"`
		Project     string `json:"project"`
		Machine     string `json:"machine"`
		Agent       string `json:"agent"`
		Operation   string `json:"operation"`
		Binding     string `json:"binding"`
		Nonce       string `json:"nonce"`
		ExpiresAtMs int64  `json:"expires_at_ms"`
	}{"identity.agent-machine.v1", s.auth.cfg.JWTIssuer, s.auth.projectID(ctx), machine.ID, request.AgentID, request.Operation, binding, challenge.ID, challenge.ExpiresAtMs})
	if err != nil {
		return nil, err
	}
	challenge.Message = string(message)
	repo, err := s.machineRepo(ctx)
	if err != nil {
		return nil, err
	}
	if err = repo.CreateAgentMachineChallenge(ctx, challenge); err != nil {
		if errors.Is(err, ErrNotFound) {
			s.recordMachineRefusal(ctx, machine, ReasonMachineNotFound)
			return nil, ErrAgentOAuthGrant
		}
		if errors.Is(err, ErrAgentOAuthGrant) {
			s.recordMachineRefusal(ctx, machine, ReasonMachineRevoked)
		}
		return nil, err
	}
	return challenge, nil
}

func (s *AgentOAuthService) machineAccess(ctx context.Context, request AgentMachineChallengeRequest, proof AgentMachineProof) (*AgentMachine, AgentOAuthAuthority, *AgentAuthorization, error) {
	if request.Operation == AgentMachineEnroll && validOAuthClientID(request.MachineID) && validOAuthClientID(request.AgentID) && !validMachinePublicKey(request.PublicKey) {
		if _, err := s.machineRepo(ctx); err == nil {
			s.recordMachineRefusal(ctx, nil, ReasonKeyInvalid)
		}
	}
	binding, err := request.binding()
	if err != nil {
		return nil, AgentOAuthAuthority{}, nil, err
	}
	machine, authority, key, grant, err := s.challengeSigner(ctx, request)
	if err != nil {
		return nil, authority, nil, err
	}
	if len(proof.Signature) != ed25519.SignatureSize {
		s.recordMachineRefusal(ctx, machine, ReasonSignatureInvalid)
		return nil, authority, nil, ErrUnauthenticated
	}
	if !validOAuthClientID(proof.ChallengeID) {
		s.recordMachineRefusal(ctx, machine, ReasonChallengeExpired)
		return nil, authority, nil, ErrUnauthenticated
	}
	repo, err := s.machineRepo(ctx)
	if err != nil {
		return nil, authority, nil, err
	}
	challenge, err := repo.GetAgentMachineChallenge(ctx, proof.ChallengeID)
	if err != nil {
		return nil, authority, nil, err
	}
	now := s.auth.nowMs()
	if challenge == nil || !ValidAgentMachineChallenge(challenge) || challenge.CreatedAtMs > now || challenge.ExpiresAtMs <= now {
		s.recordMachineRefusal(ctx, machine, ReasonChallengeExpired)
		return nil, authority, nil, ErrUnauthenticated
	}
	if challenge.PublicKey != key || challenge.MachineID != request.MachineID || challenge.AgentID != request.AgentID || challenge.Operation != request.Operation || !verifyMachineSignature(challenge, proof, binding, now) {
		s.recordMachineRefusal(ctx, machine, ReasonSignatureInvalid)
		return nil, authority, nil, ErrUnauthenticated
	}
	consumed, err := repo.ConsumeAgentMachineChallenge(ctx, challenge.ID, s.auth.nowMs())
	if err != nil {
		return nil, authority, nil, err
	}
	if !consumed {
		s.recordMachineRefusal(ctx, machine, ReasonChallengeExpired)
		return nil, authority, nil, ErrUnauthenticated
	}
	return machine, authority, grant, nil
}

func (s *AgentOAuthService) RegisterMachineAgentKey(ctx context.Context, id, agent, key string, proof AgentMachineProof) (*AgentAuthorization, error) {
	machine, authority, _, err := s.machineAccess(ctx, AgentMachineChallengeRequest{MachineID: id, AgentID: agent, Operation: AgentMachineEnroll, PublicKey: key}, proof)
	if err != nil {
		return nil, err
	}
	now := s.auth.nowMs()
	proposal := &AgentAuthorization{ID: rand.Text(), MachineID: machine.ID, MachinePublicKey: key, ClientID: machine.ClientID, ClientRevision: machine.ClientRevision, Resource: machine.Resource, Product: machine.Product, Scopes: slices.Clone(machine.Scopes), CreatedAtMs: now, ConsentAtMs: now, Revision: 1, Decision: AgentAuthorizationApproved, OwnerID: machine.OwnerID, AgentID: agent, SessionID: rand.Text()}
	repo, err := s.machineRepo(ctx)
	if err != nil {
		return nil, err
	}
	grant, err := repo.EnsureAgentMachineDelegation(ctx, id, proposal, machine.PublicKey, authority.Fingerprint())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.recordMachineRefusal(ctx, machine, ReasonMachineNotFound)
			return nil, ErrAgentOAuthGrant
		}
		if errors.Is(err, ErrAgentOAuthGrant) {
			s.recordMachineRefusal(ctx, machine, ReasonMachineRevoked)
		}
		return nil, err
	}
	if grant.RevokedAtMs != 0 {
		s.recordMachineRefusal(ctx, machine, ReasonMachineRevoked)
		return nil, ErrAgentOAuthGrant
	}
	fingerprint := sha256.Sum256([]byte(key))
	s.auth.audit.Log(ctx, audit.EventAgentMachineAgentEnrolled, audit.WithActor(machine.OwnerID), audit.WithTarget(agent), audit.WithSuccess(true), audit.WithDetails(map[string]any{"machine_id": machine.ID, "delegation_id": grant.ID, "key_fingerprint": hex.EncodeToString(fingerprint[:]), "recovered": grant.ID != proposal.ID}))
	return grant, nil
}
