package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/agegate"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/events"
	"github.com/elloloop/identity/pkg/passwords"
)

// UsernameSignup creates an account identified by a username and a password,
// for a project whose accounts.username_signup is "self", and issues tokens.
// The account has no email; when the project has an account domain its
// address is <username>@<domain>. It signs in through PasswordLogin with the
// username as the identifier.
//
// The project's access mode applies as it does to every self-signup, except
// that a username has no email for an allowlist or the deny layer to match:
// open admits, invite refuses with ErrSignupByInvitationOnly, and allowlist,
// closed, an unset mode and any configured deny layer refuse with
// ErrAccessNotAllowed.
//
// A username is a public handle the person chooses, so a taken one is
// reported as taken (ErrAlreadyExists) rather than hidden behind a decoy:
// the person has to pick another. That tells a caller whether a username
// exists in the project, managed child usernames included, so how much anyone
// can learn is bounded three ways: the per-IP signup limit, the per-username
// throttle, and a per-IP budget of "taken" answers (GATEWAY_USERNAME_TAKEN_PER_IP)
// after which every UsernameSignup from that IP is refused as throttled,
// available name or not, until the window ends. A date of birth that falls in the child
// band is refused — a child's username account is a guardian's to create
// (CreateManagedChildAccount), with consent.
func (s *AuthService) UsernameSignup(ctx context.Context, username, password, name string, dateOfBirthMs int64, market, ipAddr string) (*LoginResult, error) {
	if !s.cfg.AuthAllowLocal {
		return nil, ErrLocalAuthDisabled
	}
	if !s.cfg.PasswordSignupEnabled {
		return nil, ErrSignupDisabled
	}
	if err := usernameSelfSignupRefusal(ProjectScopeFromContext(ctx)); err != nil {
		return nil, err
	}
	username = normalizeUsername(username)
	if err := validateUsernameFormat(username); err != nil {
		return nil, err
	}
	if password == "" {
		return nil, fmt.Errorf("%w: password is required", ErrInvalidArgument)
	}
	if s.ageGate.Enabled() && s.cfg.AgeGateRequireDOB && dateOfBirthMs <= 0 {
		return nil, fmt.Errorf("%w: date of birth is required", ErrInvalidArgument)
	}
	market = normalizeJurisdictionCode(market)
	if err := s.validateAccountMarket(ctx, market); err != nil {
		return nil, err
	}
	gate := s.determinerForUser(ctx, &User{Market: market})
	if gate.Enabled() && gate.Determine(dateOfBirthMs, s.nowFunc()).Band == agegate.BandChild {
		return nil, fmt.Errorf("%w: a child's account is created by their guardian", ErrInvalidArgument)
	}
	if err := s.validatePasswordStrengthForEmail(ctx, username, password); err != nil {
		return nil, err
	}
	// The per-identifier signup throttle PasswordSignup keys on the email,
	// keyed here on the project and the username, so a username never shares a
	// bucket with an email or with the same username in another project.
	if !s.signupThrottle.allow(usernameThrottleKey(s.projectID(ctx), username), s.nowMs()) {
		s.logger.Info("username_signup_throttled", zap.String("project_id", s.projectID(ctx)))
		return nil, ErrSignupThrottled
	}

	if s.usernameProbes.exhausted(ipAddr, s.nowMs()) {
		s.logger.Info("username_signup_probe_budget_spent", zap.String("project_id", s.projectID(ctx)))
		return nil, ErrSignupThrottled
	}
	repo := s.repo(ctx)
	existing, err := repo.FindUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		s.usernameProbes.spend(ipAddr, s.nowMs())
		return nil, fmt.Errorf("%w: username %q is already taken", ErrAlreadyExists, username)
	}
	pwHash, err := passwords.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = username
	}
	now := time.UnixMilli(s.nowMs())
	user := &User{
		Username:      username,
		Name:          name,
		Role:          "member",
		Status:        StatusActive,
		PasswordHash:  pwHash,
		DateOfBirthMs: dateOfBirthMs,
		Market:        market,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	id, err := repo.CreateUser(ctx, user)
	if err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			s.usernameProbes.spend(ipAddr, s.nowMs())
			return nil, fmt.Errorf("%w: username %q is already taken", ErrAlreadyExists, username)
		}
		return nil, fmt.Errorf("creating user: %w", err)
	}
	user.ID = id
	user.PasswordHash = ""
	s.stampAgeBand(ctx, user)
	s.logger.Info("username_signup_success", zap.String("user_id", id))
	EmitUserEvent(ctx, s.publisher, s.logger, s.projectID(ctx), s.tenantID(ctx), events.EventUserCreated, user)

	accessToken, refreshToken, err := s.issueTokens(ctx, user, "", "")
	if err != nil {
		return nil, err
	}
	s.audit.Log(
		ctx, audit.EventLoginSuccess,
		audit.WithActor(id),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "username_signup"}),
	)
	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// usernameThrottleKey is the signup-throttle bucket for a username. An email
// key always contains '@' and this one never does, so the two cannot meet.
func usernameThrottleKey(projectID, username string) string {
	return "username:" + projectID + ":" + username
}

// usernameSelfSignupRefusal is the project half of the username self-signup
// rule, shared by UsernameSignup and the hosted page's options so the page
// offers exactly what the RPC accepts: the project lets people create their
// own username accounts, its access mode is open, and it has no deny layer
// (a username carries no email a deny layer could clear).
func usernameSelfSignupRefusal(scope *ProjectScope) error {
	if err := selfSignupRefusal(accountsFor(scope).usernameSignup()); err != nil {
		return err
	}
	if scope == nil {
		return nil
	}
	switch scope.Access.mode() {
	case AccessModeOpen:
	case AccessModeInvite:
		return ErrSignupByInvitationOnly
	default:
		return ErrAccessNotAllowed
	}
	if scope.Access.hasDenyLayer() {
		return ErrAccessNotAllowed
	}
	return nil
}
