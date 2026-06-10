package service

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// InstanceSignup bootstraps the first admin user of a single-tenant
// (`mode=single`) deployment. It resolves the bootstrap deadlock: every
// admin RPC requires an existing role=admin user, but self-serve signup
// (PasswordSignup, OAuth, passwordless) only ever mints role=member — so
// without this RPC a fresh instance would have no way to create its
// first admin and nobody could log in to add others.
//
// InstanceSignup is reachable WITHOUT authentication, but it
// self-disables: it succeeds only while the tenant has zero admins
// (HasAnyAdmin == false). The moment any admin exists it returns
// ErrInstanceAlreadyInitialized (mapped to CodeFailedPrecondition), so
// it can be used neither to mint additional admins nor to take over a
// running instance. In `mode=multi` it returns ErrUnimplemented — there
// the equivalent entry point is OrganizationSignup, which makes the org
// founder an admin.
//
// Concurrency: the no-admin guard is a service-layer pre-check, not an
// atomic compare-and-set. That matches the codebase's posture for
// naturally-serialised admin writes (cf. the entdb AddOrganizationMember
// note). The authoritative guarantee — "once an admin exists this RPC is
// permanently closed" — holds because CreateUser commits the admin
// before any later call's guard reads it. The only unguarded window is
// two genuinely-concurrent first-bootstraps on an un-provisioned
// instance, where both callers are by definition the operator;
// same-email racers still collapse to a single admin via the User.email
// uniqueness constraint (the loser is reported as already-initialized).
func (s *AuthService) InstanceSignup(ctx context.Context, email, password, name string) (*LoginResult, error) {
	if s.cfg.IsMultiMode() {
		return nil, fmt.Errorf("%w: InstanceSignup is mode=single only", ErrUnimplemented)
	}

	email = strings.TrimSpace(strings.ToLower(email))
	if err := validateEmailFormat(email); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidArgument, err.Error())
	}
	// Canonicalize identically to PasswordSignup so the bootstrap admin's
	// address dedups the same way any later login would resolve it.
	email = canonicalizeEmail(email)
	if password == "" {
		return nil, fmt.Errorf("%w: password is required", ErrInvalidArgument)
	}
	if err := validatePasswordStrength(password); err != nil {
		return nil, err
	}

	// Self-disabling guard: refuse the bootstrap once any admin exists.
	hasAdmin, err := s.repo(ctx).HasAnyAdmin(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking for existing admin: %w", err)
	}
	if hasAdmin {
		return nil, ErrInstanceAlreadyInitialized
	}

	pwHash, err := passwords.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	displayName := fallbackDisplayName(email, name)
	now := s.nowMs()
	userID, err := s.repo(ctx).CreateUser(ctx, &User{
		Email:        email,
		Name:         displayName,
		Role:         "admin",
		Status:       "active",
		PasswordHash: pwHash,
		CreatedAt:    msToTime(now),
		UpdatedAt:    msToTime(now),
	})
	if err != nil {
		// A same-email concurrent bootstrap loses here on the email
		// uniqueness constraint; if an admin now exists, surface the
		// self-disabled signal rather than a raw create error.
		if has, chkErr := s.repo(ctx).HasAnyAdmin(ctx); chkErr == nil && has {
			return nil, ErrInstanceAlreadyInitialized
		}
		return nil, fmt.Errorf("creating admin user: %w", err)
	}

	user := &User{
		ID:        userID,
		Email:     email,
		Name:      displayName,
		Role:      "admin",
		Status:    "active",
		CreatedAt: msToTime(now),
		UpdatedAt: msToTime(now),
	}

	accessToken, refreshToken, err := s.issueTokens(ctx, user, "", "")
	if err != nil {
		return nil, err
	}

	// The actor/target id already identifies the new admin; mirror
	// OrganizationSignup and keep the raw email out of the audit detail
	// map (it is PII and the row is keyed on the user id anyway).
	s.audit.Log(
		ctx, audit.EventInstanceSignup,
		audit.WithActor(userID),
		audit.WithTarget(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"tenant_id": s.tenantID(ctx),
		}),
	)
	s.logger.Info(
		"instance_signup_success",
		zap.String("email", redactEmail(email)),
		zap.String("user_id", userID),
	)

	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}
