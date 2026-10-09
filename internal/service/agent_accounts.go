package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/events"
)

// ── Agent accounts ──────────────────────────────────────────────────────
//
// An agent account is a non-human account (an assistant, a bot, an
// automation) that a person owns. It is a user row like any other — it has
// a stable id other records can name, a display name and an avatar — with
// two differences that everything below follows from:
//
//  1. It has no sign-in method. No password, passkey, provider identity,
//     email, phone, TOTP or username is ever attached to it, and every
//     interactive sign-in into it is refused at issueSignInTokens, the one
//     chokepoint every sign-in reaches, whatever credential a corrupt row
//     might hold.
//  2. Its standing is DERIVED from its owner's. An agent is usable only
//     while it is active AND its owner is an active person in the same
//     project. Suspending, scheduling for deletion or deleting the owner
//     makes every agent they own unusable at once, without a write to the
//     agents: the check runs wherever a token pair is issued, refresh
//     included, so it cannot be skipped by a path added later.
//
// Who may act on an agent is the owner or a project admin — nothing else.
// Identity holds no notion of what an agent may do inside an application:
// that is the application's to decide.

const (
	// UserKindPerson is the kind of every account a human signs in to.
	UserKindPerson = "person"
	// UserKindAgent is the kind of a non-human account a person owns.
	UserKindAgent = "agent"
)

// IsAgent reports whether u is an agent account.
func (u *User) IsAgent() bool { return u != nil && u.Kind == UserKindAgent }

const (
	// agentNameMaxRunes bounds an agent's display name.
	agentNameMaxRunes = 200
	// agentAvatarURLMaxBytes bounds an agent's avatar URL.
	agentAvatarURLMaxBytes = 2048
)

var (
	// ErrAgentsDisabled is returned by every agent management operation when
	// the deployment has not turned agent accounts on
	// (GATEWAY_AGENTS_ENABLED). Mapped to CodeFailedPrecondition.
	ErrAgentsDisabled = errors.New("agent accounts are not enabled on this server")
	// ErrAgentSignIn is returned when an interactive sign-in resolves to an
	// agent account. Mapped to CodePermissionDenied.
	ErrAgentSignIn = errors.New("agent accounts cannot sign in")
	// ErrAgentCredential is returned when a sign-in credential would be
	// attached to an agent account. Mapped to CodeFailedPrecondition.
	ErrAgentCredential = errors.New("agent accounts hold no sign-in credentials")
	// ErrAgentLimitReached is returned when an owner already holds the
	// configured maximum number of agents (GATEWAY_AGENTS_MAX_PER_OWNER).
	// Mapped to CodeResourceExhausted.
	ErrAgentLimitReached = errors.New("the owner already holds the maximum number of agent accounts")
	// errAgentOwnerNotEligible is the one message every refused owner
	// carries, so the answer does not say which check failed.
	errAgentOwnerNotEligible = fmt.Errorf("%w: the owner must be an active person account in this project", ErrInvalidArgument)
	// errAgentOwnerNotActive is the standing refusal for an agent whose
	// owner may not hold a session.
	errAgentOwnerNotActive = fmt.Errorf("%w: the agent's owner is not active", ErrAccountNotActive)
)

// agentRefusalNotAllowed is the ONE message every unauthorized agent
// operation carries, whether the agent exists or not.
const agentRefusalNotAllowed = "caller may not manage this agent"

// agentOperation is one agent management operation, named by the audit
// event it emits on success and on refusal.
type agentOperation struct {
	event audit.EventType
}

var (
	agentOpCreate     = agentOperation{audit.EventAgentCreated}
	agentOpUpdate     = agentOperation{audit.EventAgentUpdated}
	agentOpTransfer   = agentOperation{audit.EventAgentTransferred}
	agentOpDeactivate = agentOperation{audit.EventAgentDeactivated}
	agentOpReactivate = agentOperation{audit.EventAgentReactivated}
	agentOpDelete     = agentOperation{audit.EventAgentDeleted}
	agentOpList       = agentOperation{audit.EventAgentsListed}
)

// auditAgentAction records one agent management operation. Refusals carry
// the failing step, so probing someone else's agent shows in the trail.
func (s *AuthService) auditAgentAction(
	ctx context.Context, op agentOperation, callerID, agentID string, ok bool, ip, userAgent string, details map[string]any,
) {
	opts := []audit.Option{
		audit.WithActor(callerID), audit.WithTarget(agentID),
		audit.WithIP(ip), audit.WithUserAgent(userAgent), audit.WithSuccess(ok),
	}
	if len(details) > 0 {
		opts = append(opts, audit.WithDetails(details))
	}
	s.audit.Log(ctx, op.event, opts...)
}

// isPermanentPerson reports whether u is a person who may take part in
// agent management at all: not an agent, not anonymous (the retention sweep
// would orphan what it owns), not merged away.
func isPermanentPerson(u *User) bool {
	return u != nil && !u.IsAgent() && !u.IsAnonymous && u.MergedIntoUserID == ""
}

// isEligibleAgentOwner reports whether u may own an agent: an active
// permanent person. The same rule backs creation, transfer and the standing
// check, so an agent can never be handed to an account it would be unusable
// under.
func isEligibleAgentOwner(u *User) bool {
	return isPermanentPerson(u) && isActiveStatus(u.Status)
}

// checkAgentStanding returns nil when the agent may hold a session now, and
// ErrAccountNotActive otherwise: the agent itself is not active, or its
// owner is missing, not active, merged away, anonymous or not a person. It
// is evaluated on every token issue, so an owner's suspension or deletion
// takes effect at the agent's next refresh at the latest.
func (s *AuthService) checkAgentStanding(ctx context.Context, agent *User) error {
	if !isActiveStatus(agent.Status) {
		return ErrAccountNotActive
	}
	if agent.OwnerUserID == "" {
		return errAgentOwnerNotActive
	}
	owner, err := s.repo(ctx).GetUser(ctx, agent.OwnerUserID)
	if err != nil {
		return fmt.Errorf("fetch agent owner: %w", err)
	}
	if !isEligibleAgentOwner(owner) {
		return errAgentOwnerNotActive
	}
	return nil
}

// refuseAgentSignIn is the interactive sign-in refusal, run at the sign-in
// chokepoint before any state is touched.
func (s *AuthService) refuseAgentSignIn(ctx context.Context, user *User, ip, userAgent string) error {
	if !user.IsAgent() {
		return nil
	}
	s.audit.Log(ctx, audit.EventAgentSignInRefused,
		audit.WithActor(user.ID), audit.WithTarget(user.ID),
		audit.WithIP(ip), audit.WithUserAgent(userAgent), audit.WithSuccess(false))
	return ErrAgentSignIn
}

// agentCaller resolves the authenticated caller of an agent operation, and
// is where every operation is refused while agent accounts are off. Only an
// active permanent person may manage agents.
func (s *AuthService) agentCaller(ctx context.Context, op agentOperation, callerID, agentID, ip, userAgent string) (*User, bool, error) {
	if !s.cfg.AgentsEnabled {
		return nil, false, ErrAgentsDisabled
	}
	if callerID == "" {
		return nil, false, ErrUnauthenticated
	}
	caller, err := s.repo(ctx).GetUser(ctx, callerID)
	if err != nil {
		return nil, false, fmt.Errorf("fetch caller: %w", err)
	}
	if !isPermanentPerson(caller) {
		s.auditAgentAction(ctx, op, callerID, agentID, false, ip, userAgent,
			map[string]any{"step": "caller_kind"})
		return nil, false, fmt.Errorf("%w: %s", ErrPermissionDenied, agentRefusalNotAllowed)
	}
	if !isActiveStatus(caller.Status) {
		s.auditAgentAction(ctx, op, callerID, agentID, false, ip, userAgent,
			map[string]any{"step": "caller_inactive"})
		return nil, false, ErrAccountNotActive
	}
	return caller, strings.EqualFold(caller.Role, RoleAdmin), nil
}

// authorizeAgentAction is the single chokepoint every operation on an
// existing agent passes through. It admits the agent's owner and a project
// admin. Every other caller gets the identical ErrPermissionDenied whether
// the id names an agent, a person, or nothing, so the surface is not an
// enumeration oracle.
func (s *AuthService) authorizeAgentAction(
	ctx context.Context, op agentOperation, callerID, agentID, ip, userAgent string,
) (*User, error) {
	agentID = strings.TrimSpace(agentID)
	caller, isAdmin, err := s.agentCaller(ctx, op, callerID, agentID, ip, userAgent)
	if err != nil {
		return nil, err
	}
	if agentID == "" {
		return nil, fmt.Errorf("%w: agent_user_id is required", ErrInvalidArgument)
	}
	agent, err := s.repo(ctx).GetUser(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("fetch agent: %w", err)
	}
	if !agent.IsAgent() || (agent.OwnerUserID != caller.ID && !isAdmin) {
		s.auditAgentAction(ctx, op, callerID, agentID, false, ip, userAgent,
			map[string]any{"step": "not_permitted"})
		return nil, fmt.Errorf("%w: %s", ErrPermissionDenied, agentRefusalNotAllowed)
	}
	return agent, nil
}

// normalizeAgentProfile trims and validates an agent's name and avatar URL.
func normalizeAgentProfile(name, avatarURL string) (string, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", fmt.Errorf("%w: name is required", ErrInvalidArgument)
	}
	if utf8.RuneCountInString(name) > agentNameMaxRunes {
		return "", "", fmt.Errorf("%w: name is longer than %d characters", ErrInvalidArgument, agentNameMaxRunes)
	}
	avatarURL = strings.TrimSpace(avatarURL)
	if avatarURL == "" {
		return name, "", nil
	}
	if len(avatarURL) > agentAvatarURLMaxBytes {
		return "", "", fmt.Errorf("%w: avatar_url is longer than %d bytes", ErrInvalidArgument, agentAvatarURLMaxBytes)
	}
	u, err := url.Parse(avatarURL)
	// https only: other people's clients fetch it, and a plain-http fetch
	// would hand the viewer's address to whoever chose the URL in the clear.
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", "", fmt.Errorf("%w: avatar_url must be an absolute https URL", ErrInvalidArgument)
	}
	return name, avatarURL, nil
}

// checkAgentCapacity refuses when owner already holds the per-owner cap.
// The count and the write that follows are separate statements, so two
// racing requests can each pass it: the cap bounds an owner's agents, and
// the per-caller rate limit bounds the race.
func (s *AuthService) checkAgentCapacity(ctx context.Context, ownerID string) error {
	n, err := s.repo(ctx).CountUsers(ctx, UserListFilter{IncludeAgents: true, IncludeAnonymous: true, OwnerUserID: ownerID})
	if err != nil {
		return fmt.Errorf("count owner's agents: %w", err)
	}
	if n >= s.cfg.AgentsPerOwnerLimit() {
		return ErrAgentLimitReached
	}
	return nil
}

// emitAgentEvent publishes a lifecycle event for an agent.
func (s *AuthService) emitAgentEvent(ctx context.Context, t events.EventType, agent *User) {
	EmitUserEvent(ctx, s.publisher, s.logger, s.projectID(ctx), s.tenantID(ctx), t, agent)
}

// CreateAgent creates an agent account owned by ownerUserID, which defaults
// to the caller. Naming another owner requires a project admin, and that
// owner must be an active person in this project.
func (s *AuthService) CreateAgent(
	ctx context.Context, callerID, name, avatarURL, ownerUserID, ip, userAgent string,
) (*User, error) {
	caller, isAdmin, err := s.agentCaller(ctx, agentOpCreate, callerID, "", ip, userAgent)
	if err != nil {
		return nil, err
	}
	name, avatarURL, err = normalizeAgentProfile(name, avatarURL)
	if err != nil {
		return nil, err
	}
	repo := s.repo(ctx)
	owner := caller
	if id := strings.TrimSpace(ownerUserID); id != "" && id != caller.ID {
		if !isAdmin {
			s.auditAgentAction(ctx, agentOpCreate, callerID, "", false, ip, userAgent,
				map[string]any{"step": "not_permitted"})
			return nil, fmt.Errorf("%w: %s", ErrPermissionDenied, agentRefusalNotAllowed)
		}
		if owner, err = repo.GetUser(ctx, id); err != nil {
			return nil, fmt.Errorf("fetch owner: %w", err)
		}
		if !isEligibleAgentOwner(owner) {
			s.auditAgentAction(ctx, agentOpCreate, callerID, "", false, ip, userAgent,
				map[string]any{"step": "owner_not_eligible", "owner_user_id": id})
			return nil, errAgentOwnerNotEligible
		}
	}
	if err := s.checkAgentCapacity(ctx, owner.ID); err != nil {
		s.auditAgentAction(ctx, agentOpCreate, callerID, "", false, ip, userAgent,
			map[string]any{"step": "limit_reached", "owner_user_id": owner.ID})
		return nil, err
	}

	now := time.UnixMilli(s.nowMs())
	agent := &User{
		Kind:        UserKindAgent,
		OwnerUserID: owner.ID,
		Name:        name,
		AvatarURL:   avatarURL,
		Role:        RoleMember,
		Status:      StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	id, err := repo.CreateUser(ctx, agent)
	if err != nil {
		return nil, fmt.Errorf("create agent: %w", err)
	}
	agent.ID = id
	s.auditAgentAction(ctx, agentOpCreate, callerID, id, true, ip, userAgent,
		map[string]any{"owner_user_id": owner.ID})
	s.emitAgentEvent(ctx, events.EventUserCreated, agent)
	return agent, nil
}

// ListAgents returns the agents ownerUserID owns, which defaults to the
// caller. Listing another owner's agents requires a project admin; the owner
// need not exist, so an admin can find the agents a deleted owner left.
func (s *AuthService) ListAgents(ctx context.Context, callerID, ownerUserID string) ([]*User, error) {
	caller, isAdmin, err := s.agentCaller(ctx, agentOpList, callerID, "", "", "")
	if err != nil {
		return nil, err
	}
	ownerID := strings.TrimSpace(ownerUserID)
	if ownerID == "" {
		ownerID = caller.ID
	}
	if ownerID != caller.ID {
		if !isAdmin {
			s.auditAgentAction(ctx, agentOpList, callerID, ownerID, false, "", "",
				map[string]any{"step": "not_permitted"})
			return nil, fmt.Errorf("%w: %s", ErrPermissionDenied, agentRefusalNotAllowed)
		}
		s.auditAgentAction(ctx, agentOpList, callerID, ownerID, true, "", "", nil)
	}
	return listOwnedAgents(ctx, s.repo(ctx), ownerID)
}

// UpdateAgent replaces an agent's display name and avatar URL.
func (s *AuthService) UpdateAgent(
	ctx context.Context, callerID, agentID, name, avatarURL, ip, userAgent string,
) (*User, error) {
	agent, err := s.authorizeAgentAction(ctx, agentOpUpdate, callerID, agentID, ip, userAgent)
	if err != nil {
		return nil, err
	}
	name, avatarURL, err = normalizeAgentProfile(name, avatarURL)
	if err != nil {
		return nil, err
	}
	now := s.nowMs()
	if err := s.repo(ctx).UpdateUser(ctx, agent.ID, map[string]any{
		"name":       name,
		"avatar_url": avatarURL,
		"updated_at": now,
	}); err != nil {
		return nil, fmt.Errorf("update agent: %w", err)
	}
	agent.Name, agent.AvatarURL, agent.UpdatedAt = name, avatarURL, time.UnixMilli(now)
	s.auditAgentAction(ctx, agentOpUpdate, callerID, agent.ID, true, ip, userAgent, nil)
	s.emitAgentEvent(ctx, events.EventUserUpdated, agent)
	return agent, nil
}

// TransferAgent hands an agent to another owner: an active person in this
// project, under the per-owner cap. The agent's sessions end, so nothing
// the previous owner set up keeps acting under the new owner's standing.
// Transferring to the current owner is a no-op.
func (s *AuthService) TransferAgent(
	ctx context.Context, callerID, agentID, newOwnerID, ip, userAgent string,
) (*User, error) {
	agent, err := s.authorizeAgentAction(ctx, agentOpTransfer, callerID, agentID, ip, userAgent)
	if err != nil {
		return nil, err
	}
	newOwnerID = strings.TrimSpace(newOwnerID)
	if newOwnerID == "" {
		return nil, fmt.Errorf("%w: new_owner_user_id is required", ErrInvalidArgument)
	}
	if newOwnerID == agent.OwnerUserID {
		s.auditAgentAction(ctx, agentOpTransfer, callerID, agent.ID, true, ip, userAgent,
			map[string]any{"owner_user_id": newOwnerID, "unchanged": true})
		return agent, nil
	}
	repo := s.repo(ctx)
	newOwner, err := repo.GetUser(ctx, newOwnerID)
	if err != nil {
		return nil, fmt.Errorf("fetch new owner: %w", err)
	}
	if !isEligibleAgentOwner(newOwner) {
		s.auditAgentAction(ctx, agentOpTransfer, callerID, agent.ID, false, ip, userAgent,
			map[string]any{"step": "owner_not_eligible"})
		return nil, errAgentOwnerNotEligible
	}
	if err := s.checkAgentCapacity(ctx, newOwner.ID); err != nil {
		s.auditAgentAction(ctx, agentOpTransfer, callerID, agent.ID, false, ip, userAgent,
			map[string]any{"step": "limit_reached", "owner_user_id": newOwner.ID})
		return nil, err
	}
	now := s.nowMs()
	if err := repo.UpdateUser(ctx, agent.ID, map[string]any{
		"owner_user_id": newOwner.ID,
		"updated_at":    now,
	}); err != nil {
		return nil, fmt.Errorf("transfer agent: %w", err)
	}
	if err := revokeAllUserSessions(ctx, repo, agent.ID, now); err != nil {
		return nil, fmt.Errorf("transfer agent: %w", err)
	}
	previous := agent.OwnerUserID
	agent.OwnerUserID, agent.UpdatedAt = newOwner.ID, time.UnixMilli(now)
	s.auditAgentAction(ctx, agentOpTransfer, callerID, agent.ID, true, ip, userAgent,
		map[string]any{"previous_owner_user_id": previous, "owner_user_id": newOwner.ID})
	s.emitAgentEvent(ctx, events.EventUserUpdated, agent)
	return agent, nil
}

// DeactivateAgent suspends an agent and ends its sessions at once. It is
// reversible with ReactivateAgent. Deactivating a deactivated agent re-runs
// the session cut (the status write and the cut are separate statements, so
// an earlier attempt may have stored one and not the other).
func (s *AuthService) DeactivateAgent(ctx context.Context, callerID, agentID, reason, ip, userAgent string) error {
	agent, err := s.authorizeAgentAction(ctx, agentOpDeactivate, callerID, agentID, ip, userAgent)
	if err != nil {
		return err
	}
	repo := s.repo(ctx)
	now := s.nowMs()
	status := strings.ToLower(agent.Status)
	switch {
	case status == StatusDeactivated:
		if err := revokeAllUserSessions(ctx, repo, agent.ID, now); err != nil {
			return fmt.Errorf("deactivate agent: %w", err)
		}
		s.auditAgentAction(ctx, agentOpDeactivate, callerID, agent.ID, true, ip, userAgent,
			map[string]any{"reason": reason, "unchanged": true})
		return nil
	case !isActiveStatus(status):
		s.auditAgentAction(ctx, agentOpDeactivate, callerID, agent.ID, false, ip, userAgent,
			map[string]any{"step": "agent_status", "status": agent.Status})
		return fmt.Errorf("%w: agent is %s", ErrAccountNotActive, agent.Status)
	}
	if err := repo.UpdateUser(ctx, agent.ID, map[string]any{
		"status":     StatusDeactivated,
		"updated_at": now,
	}); err != nil {
		return fmt.Errorf("deactivate agent: %w", err)
	}
	if err := revokeAllUserSessions(ctx, repo, agent.ID, now); err != nil {
		return fmt.Errorf("deactivate agent: %w", err)
	}
	agent.Status, agent.UpdatedAt = StatusDeactivated, time.UnixMilli(now)
	s.auditAgentAction(ctx, agentOpDeactivate, callerID, agent.ID, true, ip, userAgent,
		map[string]any{"reason": reason})
	s.emitAgentEvent(ctx, events.EventUserDeactivated, agent)
	return nil
}

// ReactivateAgent returns a deactivated agent to active. An active agent is
// left as it is. It does not make the agent usable on its own: an agent
// whose owner is not active stays unusable until the owner is.
func (s *AuthService) ReactivateAgent(ctx context.Context, callerID, agentID, ip, userAgent string) error {
	agent, err := s.authorizeAgentAction(ctx, agentOpReactivate, callerID, agentID, ip, userAgent)
	if err != nil {
		return err
	}
	status := strings.ToLower(agent.Status)
	switch {
	case isActiveStatus(status):
		s.auditAgentAction(ctx, agentOpReactivate, callerID, agent.ID, true, ip, userAgent,
			map[string]any{"unchanged": true})
		return nil
	case status != StatusDeactivated:
		s.auditAgentAction(ctx, agentOpReactivate, callerID, agent.ID, false, ip, userAgent,
			map[string]any{"step": "agent_status", "status": agent.Status})
		return fmt.Errorf("%w: agent is %s", ErrAccountNotActive, agent.Status)
	}
	now := s.nowMs()
	if err := s.repo(ctx).UpdateUser(ctx, agent.ID, map[string]any{
		"status":     StatusActive,
		"updated_at": now,
	}); err != nil {
		return fmt.Errorf("reactivate agent: %w", err)
	}
	agent.Status, agent.UpdatedAt = StatusActive, time.UnixMilli(now)
	s.auditAgentAction(ctx, agentOpReactivate, callerID, agent.ID, true, ip, userAgent, nil)
	s.emitAgentEvent(ctx, events.EventUserUpdated, agent)
	return nil
}

// DeleteAgent erases an agent through the same hard-delete cascade the
// admin DeleteUser RPC runs (the injected AccountPurger), which ends its
// sessions first and emits user.deactivated and user.deleted.
func (s *AuthService) DeleteAgent(ctx context.Context, callerID, agentID, ip, userAgent string) error {
	agent, err := s.authorizeAgentAction(ctx, agentOpDelete, callerID, agentID, ip, userAgent)
	if err != nil {
		return err
	}
	if s.purger == nil {
		return fmt.Errorf("%w: account erasure is not wired on this deployment", ErrServiceUnavailable)
	}
	if err := s.purger.PurgeAccount(ctx, callerID, agent); err != nil {
		return fmt.Errorf("delete agent: %w", err)
	}
	s.auditAgentAction(ctx, agentOpDelete, callerID, agent.ID, true, ip, userAgent, nil)
	return nil
}

// RevokeUserAccess ends a user's access at once: it revokes their sessions
// and refresh tokens and those of every agent they own, so a change to the
// user's standing (deactivation, a scheduled or completed deletion) takes
// effect for the agents too, rather than at their next refresh. A credential
// change, which leaves the owner's standing intact, uses
// revokeAllUserSessions and leaves the agents alone.
//
// Exported so the inbound SCIM server deprovisions through the same
// implementation as the admin and self-service paths.
func RevokeUserAccess(ctx context.Context, repo Repository, userID string, nowMs int64) error {
	if err := revokeAllUserSessions(ctx, repo, userID, nowMs); err != nil {
		return err
	}
	agents, err := listOwnedAgents(ctx, repo, userID)
	if err != nil {
		return err
	}
	for _, a := range agents {
		if err := revokeAllUserSessions(ctx, repo, a.ID, nowMs); err != nil {
			return fmt.Errorf("revoke owned agent: %w", err)
		}
	}
	return nil
}

// listOwnedAgents returns every agent ownerID owns, page by page: a merge
// can leave an owner holding more than the per-owner cap, so no single page
// is assumed to be all of them.
func listOwnedAgents(ctx context.Context, repo Repository, ownerID string) ([]*User, error) {
	var out []*User
	for {
		page, err := repo.ListUsers(ctx, UserListFilter{
			// An agent is never anonymous; including anonymous accounts
			// keeps the query to the owner index alone.
			IncludeAgents: true, IncludeAnonymous: true, OwnerUserID: ownerID,
			Offset: len(out), Limit: MaxUserListLimit,
		})
		if err != nil {
			return nil, fmt.Errorf("list owned agents: %w", err)
		}
		out = append(out, page...)
		if len(page) < MaxUserListLimit {
			return out, nil
		}
	}
}
