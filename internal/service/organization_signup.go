package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/passwords"
)

// ── TenantAdmin abstraction ─────────────────────────────────────────────
//
// TenantAdmin is the narrow surface OrganizationSignup needs from the
// tenant-shard-db Admin handle: create a tenant, register a user in the
// global registry, add a tenant member. Identity uses a small interface
// rather than embedding *entdb.DbClient so the service layer stays
// testable with an in-memory fake.

// TenantAdmin is the cross-tenant admin surface required by
// OrganizationSignup. Implementations wrap the tenant-shard-db
// `Admin.CreateTenant`, `Admin.ChangeMemberRole`, and
// `Admin.RemoveTenantMember` calls (the first to provision the tenant,
// the second to promote the admin's storage-layer role from the
// default "member" assigned by Repository.CreateUser to "admin",
// the third for compensating rollback when later steps fail).
//
// Global-registry user creation and the default tenant-member row are
// handled by Repository.CreateUser (which calls Admin.CreateUser +
// Admin.AddTenantMember internally for the v1.12+ actor invariant).
// Identity does not duplicate those calls from OrganizationSignup.
//
// All methods must tolerate ALREADY_EXISTS / not-found shapes
// idempotently so partial-rollback re-runs stay safe.
type TenantAdmin interface {
	CreateTenant(ctx context.Context, tenantID, displayName string) error
	// PromoteTenantMember upgrades userID's storage-layer role inside
	// tenantID. Maps to tenant-shard-db's Admin.ChangeMemberRole. Must
	// be a no-op when the user already holds the requested role.
	PromoteTenantMember(ctx context.Context, tenantID, userID, role string) error
	// RemoveTenantMember drops the membership row. Compensating rollback
	// only; must tolerate "member not present" without error.
	RemoveTenantMember(ctx context.Context, tenantID, userID string) error
}

// RepositoryForTenant returns a service.Repository scoped to the
// given tenant id. In `mode=multi`, OrganizationSignup constructs a
// repository against the freshly-created tenant before writing the
// Organization, User, and OrganizationMembership rows. Implementations
// must return a distinct Repository per call so the new tenant's
// per-tenant state stays isolated from any other tenant's writes.
type RepositoryForTenant func(tenantID string) Repository

// ── OrganizationSignupService ───────────────────────────────────────────

// OrganizationSignupResult is returned by Signup on success.
type OrganizationSignupResult struct {
	Organization *Organization
	User         *User
	AccessToken  string
	RefreshToken string
	ExpiresIn    int32
}

// OrganizationSignupService implements the self-serve `mode=multi`
// organisation-signup flow: it creates a new tenant in tenant-shard-db,
// registers the admin user, and persists the identity-layer
// Organization / User / OrganizationMembership rows. Rollback story:
// compensating deletes when a step after Admin.CreateTenant fails. See
// docs/IDENTITY.md decision log.
type OrganizationSignupService struct {
	tenantAdmin   TenantAdmin
	repoForTenant RepositoryForTenant
	cfg           *config.Config
	signer        jwt.Signer
	audit         *audit.Logger
	logger        *zap.Logger
	nowFunc       func() time.Time
}

// NewOrganizationSignupService constructs an OrganizationSignupService.
// May only be wired in `mode=multi`; the caller is responsible for not
// invoking it in `mode=single` (the Connect handler returns
// Unimplemented in that case before reaching this layer).
func NewOrganizationSignupService(
	tenantAdmin TenantAdmin,
	repoForTenant RepositoryForTenant,
	cfg *config.Config,
	signer jwt.Signer,
	auditLog *audit.Logger,
	logger *zap.Logger,
) *OrganizationSignupService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &OrganizationSignupService{
		tenantAdmin:   tenantAdmin,
		repoForTenant: repoForTenant,
		cfg:           cfg,
		signer:        signer,
		audit:         auditLog,
		logger:        logger,
		nowFunc:       time.Now,
	}
}

// validateSlug enforces the URL-safe / hostname-segment shape the
// slug needs to carry: 2-63 chars, lowercase alphanumeric + hyphen,
// must start/end with an alphanumeric. The slug becomes a tenant id
// and (in glassa.work-shape deployments) a host subdomain, so the
// constraint is intentionally narrower than just "non-empty".
func validateSlug(slug string) error {
	if slug == "" {
		return fmt.Errorf("%w: slug is required", ErrInvalidArgument)
	}
	if len(slug) < 2 || len(slug) > 63 {
		return fmt.Errorf("%w: slug must be 2-63 characters", ErrInvalidArgument)
	}
	if !isSlugChar(rune(slug[0])) || slug[0] == '-' {
		return fmt.Errorf("%w: slug must start with a-z or 0-9", ErrInvalidArgument)
	}
	if slug[len(slug)-1] == '-' {
		return fmt.Errorf("%w: slug must not end with hyphen", ErrInvalidArgument)
	}
	for _, r := range slug {
		if !isSlugChar(r) && r != '-' {
			return fmt.Errorf("%w: slug may only contain a-z, 0-9, hyphen", ErrInvalidArgument)
		}
	}
	return nil
}

func isSlugChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= '0' && r <= '9':
		return true
	}
	return false
}

// Signup runs the OrganizationSignup flow. tenant-shard-db v1.12+
// requires every actor to be both a registered user and a tenant
// member before they can issue tenant-scoped writes; the typed
// `Repository.CreateUser` already performs the global registration
// + tenant member ("member") add internally, so this flow piggybacks
// on that rather than calling `Admin.CreateUser` /
// `Admin.AddTenantMember` a second time from here.
//
// Steps (see issue #93 DoD; the order is adapted to entdb's node-id
// model — the global registry id IS the typed node id):
//  1. Validate inputs (slug shape, email shape, password strength).
//  2. Admin.CreateTenant(slug, displayName) — slug uniqueness lives here.
//  3. Repository(slug).CreateUser(admin) — creates the User row AND
//     registers the user globally AND adds them as a "member" of the
//     tenant (the v1.12 actor invariant). Returns the assigned id.
//  4. Admin.PromoteTenantMember(slug, adminID, "admin") — upgrade the
//     storage-layer role from the default "member" to "admin". The
//     promotion is independent of identity's product role (decision
//     log §4).
//  5. Repository(slug).CreateOrganization(slug, displayName, ownerID).
//  6. Repository(slug).AddOrganizationMember(orgID, adminID, "admin").
//  7. Issue access + refresh tokens.
//
// On a failure after step 2 the partial identity-layer state is rolled
// back (best-effort); the tenant itself stays — tenant-shard-db
// (through v1.14.0 today) does not expose DeleteTenant. See
// docs/IDENTITY.md decision log.
func (s *OrganizationSignupService) Signup(
	ctx context.Context,
	slug, displayName, email, password, name string,
) (*OrganizationSignupResult, error) {
	if !s.cfg.IsMultiMode() {
		return nil, fmt.Errorf("%w: OrganizationSignup is mode=multi only", ErrUnimplemented)
	}
	if s.tenantAdmin == nil || s.repoForTenant == nil {
		return nil, errors.New("organization signup: service not wired")
	}

	slug = strings.ToLower(strings.TrimSpace(slug))
	if err := validateSlug(slug); err != nil {
		return nil, err
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return nil, fmt.Errorf("%w: display_name is required", ErrInvalidArgument)
	}
	email = strings.TrimSpace(strings.ToLower(email))
	if !strings.Contains(email, "@") {
		return nil, fmt.Errorf("%w: invalid admin email", ErrInvalidArgument)
	}
	if password == "" {
		return nil, fmt.Errorf("%w: admin_password is required", ErrInvalidArgument)
	}
	if err := validatePasswordStrength(password); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = fallbackDisplayName(email, "")
	}

	now := s.nowFunc()
	nowMs := now.UnixMilli()
	pwHash, err := passwords.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	// Step 2: create the tenant in tenant-shard-db. Slug uniqueness is
	// enforced here — Admin.CreateTenant returns AlreadyExists when the
	// slug is taken (it IS the tenant id; see decision log §2).
	if err := s.tenantAdmin.CreateTenant(ctx, slug, displayName); err != nil {
		if isAdminAlreadyExists(err) {
			return nil, fmt.Errorf("%w: slug %q is taken", ErrAlreadyExists, slug)
		}
		return nil, fmt.Errorf("create tenant %q: %w", slug, err)
	}

	repo := s.repoForTenant(slug)
	if repo == nil {
		s.logger.Error("organization_signup_repo_factory_nil", zap.String("slug", slug))
		return nil, fmt.Errorf("organization signup: repository factory returned nil for tenant %q", slug)
	}

	// Step 3: create the identity-layer User row in the new tenant.
	// The typed repo also registers the user globally + adds them as a
	// "member" of the tenant (v1.12+ actor invariant).
	adminUser := &User{
		Email:         email,
		Name:          name,
		Role:          "admin",
		Status:        "active",
		PasswordHash:  pwHash,
		EmailVerified: false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	adminID, err := repo.CreateUser(ctx, adminUser)
	if err != nil {
		// No identity-layer rows to clean up; the tenant exists but
		// has no members. Next retry with the same slug fails at
		// step 2 with AlreadyExists.
		s.logRollback(ctx, "admin_create_user_failed", slug, "", err)
		return nil, fmt.Errorf("create admin user row: %w", err)
	}
	if adminUser.ID == "" {
		adminUser.ID = adminID
	}

	// Step 4: promote the storage-layer role from "member" (assigned by
	// CreateUser) to "admin". Decision log §4: the storage role is
	// independent of identity's product role; this just gives the
	// admin upstream's "admin" capability for any cross-cutting Admin
	// RPCs.
	if err := s.tenantAdmin.PromoteTenantMember(ctx, slug, adminID, "admin"); err != nil {
		s.rollbackTenantMember(ctx, slug, adminID)
		return nil, fmt.Errorf("promote admin tenant member: %w", err)
	}

	// Step 5: persist the identity-layer Organization row.
	orgID, err := repo.CreateOrganization(ctx, &Organization{
		Slug:        slug,
		DisplayName: displayName,
		OwnerUserID: adminID,
		CreatedAtMs: nowMs,
		UpdatedAtMs: nowMs,
	})
	if err != nil {
		s.rollbackTenantMember(ctx, slug, adminID)
		return nil, fmt.Errorf("create organization row: %w", err)
	}

	// Step 6: link the admin to the organisation.
	if _, err := repo.AddOrganizationMember(ctx, &OrganizationMembership{
		OrganizationID: orgID,
		UserID:         adminID,
		Role:           "admin",
		CreatedAtMs:    nowMs,
	}); err != nil {
		s.rollbackPartialOrg(ctx, slug, adminID, orgID)
		return nil, fmt.Errorf("add organization member: %w", err)
	}

	org := &Organization{
		ID:          orgID,
		Slug:        slug,
		DisplayName: displayName,
		OwnerUserID: adminID,
		CreatedAtMs: nowMs,
		UpdatedAtMs: nowMs,
	}

	// Step 7: token issuance.
	accessToken, refreshToken, err := s.issueTokens(ctx, repo, slug, adminUser)
	if err != nil {
		// The Organization + User + Membership rows already exist, so
		// we return the error and leave the rows in place rather than
		// roll back a successful signup. The admin can re-authenticate
		// via PasswordLogin once slice 3 (per-request tenant resolution)
		// lands.
		return nil, fmt.Errorf("issue tokens: %w", err)
	}

	if s.audit != nil {
		s.audit.Log(
			ctx, audit.EventOrganizationSignup,
			audit.WithActor(adminID),
			audit.WithTarget(orgID),
			audit.WithSuccess(true),
			audit.WithDetails(map[string]any{
				"slug":      slug,
				"tenant_id": slug,
			}),
		)
	}

	s.logger.Info("organization_signup_success",
		zap.String("slug", slug),
		zap.String("organization_id", orgID),
		zap.String("admin_user_id", adminID),
	)

	return &OrganizationSignupResult{
		Organization: org,
		User:         adminUser,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// issueTokens mints a JWT access token + persists a refresh token for
// the freshly-created admin user. The refresh-token row lives in the
// new tenant so it is reachable by per-request tenant resolution
// (slice 3) on the very next call from the admin's session.
func (s *OrganizationSignupService) issueTokens(
	ctx context.Context, repo Repository, tenantID string, user *User,
) (string, string, error) {
	claims := jwt.Claims{
		Sub:    user.ID,
		Email:  user.Email,
		Name:   user.Name,
		Role:   user.Role,
		Tenant: tenantID,
	}
	if s.cfg.JWTAudience != "" {
		claims.Audience = []string{s.cfg.JWTAudience}
	}
	accessToken, err := s.signer.SignAccessToken(ctx, claims, s.cfg.JWTExpiry())
	if err != nil {
		return "", "", fmt.Errorf("creating access token: %w", err)
	}

	raw, hash := generateRefreshToken()
	now := s.nowFunc().UnixMilli()
	if _, err := repo.CreateRefreshToken(ctx, &RefreshTokenRecord{
		TokenHash:  hash,
		UserID:     user.ID,
		DeviceInfo: "organization-signup",
		DeviceName: "organization-signup",
		ExpiresAt:  now + int64(s.cfg.RefreshExpirySeconds)*1000,
		CreatedAt:  now,
		LastUsedAt: now,
	}); err != nil {
		return "", "", fmt.Errorf("storing refresh token: %w", err)
	}
	return accessToken, raw, nil
}

// rollbackTenantMember compensates for a failure after step 4 by
// dropping the admin from the new tenant's membership. The tenant
// itself cannot be deleted — tenant-shard-db (through v1.14.0 today)
// does not expose a DeleteTenant primitive. See docs/IDENTITY.md
// decision log entry on compensating rollback.
func (s *OrganizationSignupService) rollbackTenantMember(ctx context.Context, slug, adminID string) {
	if err := s.tenantAdmin.RemoveTenantMember(ctx, slug, adminID); err != nil {
		s.logger.Warn("organization_signup_rollback_tenant_member_failed",
			zap.String("slug", slug),
			zap.String("admin_id", adminID),
			zap.Error(err),
		)
	}
}

// rollbackPartialOrg compensates for a failure between steps 5–7 by
// removing the admin from the tenant. The Organization + (possibly)
// User rows already written in the tenant's data plane are NOT deleted
// here — tenant-shard-db doesn't expose typed deletes for these rows
// from the cross-tenant Admin handle, and the per-tenant Repository's
// CreateOrganization is the only path that writes them, so leaving
// them lets the operator clean up out-of-band if needed. The
// next signup attempt with the same slug fails at step 2.
func (s *OrganizationSignupService) rollbackPartialOrg(ctx context.Context, slug, adminID, orgID string) {
	s.logger.Warn("organization_signup_partial_rollback",
		zap.String("slug", slug),
		zap.String("organization_id", orgID),
		zap.String("admin_id", adminID),
	)
	s.rollbackTenantMember(ctx, slug, adminID)
}

func (s *OrganizationSignupService) logRollback(ctx context.Context, reason, slug, adminID string, err error) {
	_ = ctx
	s.logger.Warn(reason,
		zap.String("slug", slug),
		zap.String("admin_id", adminID),
		zap.Error(err),
	)
}

// isAdminAlreadyExists reports whether err signals that the tenant id
// (slug) was already registered in tenant-shard-db's global registry.
// The production TenantAdmin adapter normalises the upstream gRPC
// ALREADY_EXISTS into the service-layer sentinel by wrapping
// ErrAlreadyExists; in-memory fakes return the sentinel directly.
func isAdminAlreadyExists(err error) bool {
	return errors.Is(err, ErrAlreadyExists)
}
