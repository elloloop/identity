package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// CreateUsernameUser creates an active account identified by a username,
// for a project whose accounts.username_signup is "admin" or "self". It is
// the admin half of username accounts: the account has no email, so instead
// of an invitation the admin receives a temporary password to hand over,
// and the account's address on the project's domain (when the project has
// one) is <username>@<domain>.
//
// Username accounts sign in through PasswordLogin with the username as the
// identifier, like managed child accounts.
func (s *AdminService) CreateUsernameUser(ctx context.Context, actorID, username, name, role string) (*InviteResult, error) {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, err
	}
	if accountsFor(ProjectScopeFromContext(ctx)).usernameSignup() == SignupOff {
		return nil, ErrAccountKindOff
	}
	username = normalizeUsername(username)
	if err := validateUsernameFormat(username); err != nil {
		return nil, err
	}
	role, err := normalizeAssignableRole(role)
	if err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = username
	}

	repo := s.repo(ctx)
	existing, err := repo.FindUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("check username: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("%w: username %q is already taken", ErrAlreadyExists, username)
	}

	tempPassword := generateTempPassword()
	hash, err := passwords.Hash(tempPassword)
	if err != nil {
		return nil, fmt.Errorf("hash temp password: %w", err)
	}
	now := time.UnixMilli(nowMs())
	user := &User{
		Username:     username,
		Name:         name,
		Role:         role,
		Status:       StatusActive,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	id, err := repo.CreateUser(ctx, user)
	if err != nil {
		// A racing create hits the unique index; report it like the check.
		if errors.Is(err, ErrAlreadyExists) {
			return nil, fmt.Errorf("%w: username %q is already taken", ErrAlreadyExists, username)
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	user.ID = id
	user.PasswordHash = ""
	ensureAccountAddress(ctx, repo, s.logger, user)

	s.audit.Log(
		ctx, audit.EventUserInvited,
		audit.WithActor(actorID), audit.WithTarget(id),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"username": username, "role": role}),
	)
	return &InviteResult{User: user, TemporaryPassword: tempPassword}, nil
}

// normalizeAssignableRole is the one rule for the role an admin gives an
// account it creates: admin, member or guest, member when unset.
func normalizeAssignableRole(role string) (string, error) {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		return "member", nil
	}
	if role != "admin" && role != "member" && role != "guest" {
		return "", fmt.Errorf("%w: role must be admin|member|guest", ErrInvalidArgument)
	}
	return role, nil
}
