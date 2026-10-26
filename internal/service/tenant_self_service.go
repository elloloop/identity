package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
)

// Self-service tenants: a signed-in person creates a tenant they own
// (CreateTenant) and lists the tenants they may act in (ListMyTenants).
// Choosing one of those for an access token is RefreshToken's tenant_id
// (AuthService.WithTenantSelection).

// tenantNameMaxRunes bounds a self-service tenant's name.
const tenantNameMaxRunes = 100

var (
	// ErrSelfServiceTenantsDisabled is returned by CreateTenant when the
	// caller's project has not turned self-service tenants on
	// (tenants.self_service, or GATEWAY_SELF_SERVICE_TENANTS_ENABLED for the
	// default project). Mapped to CodeFailedPrecondition.
	ErrSelfServiceTenantsDisabled = errors.New("this project does not let users create tenants")
	// ErrTenantSelectionDisabled is returned by RefreshToken when it names a
	// tenant and the server does not select tenants
	// (GATEWAY_TENANT_SELECTION_ENABLED off, or a driver without tenants).
	// Mapped to CodeFailedPrecondition.
	ErrTenantSelectionDisabled = errors.New("tenant selection is not enabled on this server")
	// ErrTenantCreationLimited is returned when the caller has already created
	// the configured number of tenants in the current window
	// (GATEWAY_SELF_SERVICE_TENANTS_MAX_PER_USER per
	// GATEWAY_SELF_SERVICE_TENANTS_WINDOW_SECONDS). Mapped to
	// CodeResourceExhausted.
	ErrTenantCreationLimited = errors.New("too many tenants created recently; try again later")
)

// auditReasonCreationLimit is the `reason` detail of a creation refused by
// the per-user limit.
const auditReasonCreationLimit = "creation_limit"

// WithAudit wires the audit trail CreateTenant records into. A nil logger
// (the default) records nothing.
func (s *MembershipService) WithAudit(l *audit.Logger) *MembershipService {
	s.audit = l
	return s
}

// CreatedTenant is the result of CreateTenant: the new tenant and the
// caller's owner membership in it.
type CreatedTenant struct {
	Tenant     *Tenant
	Membership *TenantMembership
}

// CreateTenant creates a claimed tenant named name with callerID as its
// active owner. The project must allow it (ProjectTenantsConfig.SelfService)
// and the caller must be an active, permanent person: an anonymous account is
// swept by retention and an agent cannot hold what it would own, so either
// would leave an ownerless tenant behind.
//
// There is no idempotency key, as for the other governance creates: a client
// that retries after a lost response may create a second tenant, bounded by
// the per-user limit, and reconciles with ListMyTenants.
func (s *MembershipService) CreateTenant(ctx context.Context, callerID, name, ip, userAgent string) (*CreatedTenant, error) {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return nil, err
	}
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	if !ProjectScopeFromContext(ctx).Tenants.SelfService {
		return nil, ErrSelfServiceTenantsDisabled
	}
	name, err = normalizeTenantName(name)
	if err != nil {
		return nil, err
	}

	caller, err := s.users.GetUserInProject(ctx, projectID, callerID)
	if err != nil {
		return nil, err
	}
	if caller == nil {
		return nil, fmt.Errorf("%w: caller", ErrNotFound)
	}
	if !isPermanentPerson(caller) || !isActiveStatus(caller.Status) {
		return nil, fmt.Errorf("%w: only an active, signed-up person may create a tenant", ErrPermissionDenied)
	}

	cfg := s.config()
	now := s.nowFunc()
	tenant, membership, err := s.tenants.CreateOwnedTenant(ctx, OwnedTenantRequest{
		ProjectID:     projectID,
		Name:          name,
		OwnerID:       callerID,
		MaxPerWindow:  cfg.SelfServiceTenantsLimit(),
		WindowStartMs: now.Add(-cfg.SelfServiceTenantsWindow()).UnixMilli(),
		NowMs:         now.UnixMilli(),
	})
	if errors.Is(err, ErrTenantCreationLimited) {
		s.auditTenantCreated(ctx, callerID, false, ip, userAgent, map[string]any{
			"project_id": projectID, "reason": auditReasonCreationLimit,
		})
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	s.auditTenantCreated(ctx, callerID, true, ip, userAgent, map[string]any{
		"project_id": projectID, "tenant_id": tenant.ID,
	})
	return &CreatedTenant{Tenant: tenant, Membership: membership}, nil
}

// ListMyTenants returns the tenants callerID may act in within the caller's
// project: every claimed tenant they hold an active membership in, however
// the membership began — except one they belong to only through their
// email's domain while that email is unverified. Suspended tenants and
// memberships that are not active are left out too, so the list is exactly
// the set RefreshToken may select from.
func (s *MembershipService) ListMyTenants(ctx context.Context, callerID string) ([]*UserTenant, error) {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return nil, err
	}
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	tenants, err := s.memberships.ListActiveTenantsForUser(ctx, projectID, callerID)
	if err != nil || len(tenants) == 0 {
		return tenants, err
	}
	caller, err := s.users.GetUserInProject(ctx, projectID, callerID)
	if err != nil {
		return nil, err
	}
	if caller == nil {
		return nil, fmt.Errorf("%w: caller", ErrNotFound)
	}
	out := tenants[:0]
	for _, t := range tenants {
		if actsInTenant(caller, t) {
			out = append(out, t)
		}
	}
	return out, nil
}

// actsInTenant reports whether user may act in t, one of their active
// memberships in a claimed tenant. A membership derived from the email's
// domain proves nothing until the email is: with
// GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL off, anyone may sign up with an
// address on a company's domain, and must not be able to act as that
// company's member.
func actsInTenant(user *User, t *UserTenant) bool {
	return t.Source != MembershipSourceDomain || user.EmailVerified
}

// config is the service's configuration, or the zero Config — whose getters
// answer the defaults — when none is wired.
func (s *MembershipService) config() *config.Config {
	if s.cfg == nil {
		return &config.Config{}
	}
	return s.cfg
}

// auditTenantCreated records one CreateTenant outcome; actor and target are
// both the creator.
func (s *MembershipService) auditTenantCreated(ctx context.Context, callerID string, ok bool, ip, userAgent string, details map[string]any) {
	if s.audit == nil {
		return
	}
	s.audit.Log(ctx, audit.EventTenantCreated,
		audit.WithActor(callerID), audit.WithTarget(callerID),
		audit.WithIP(ip), audit.WithUserAgent(userAgent),
		audit.WithSuccess(ok), audit.WithDetails(details),
	)
}

// normalizeTenantName trims a tenant name and refuses one that is blank,
// longer than tenantNameMaxRunes, not valid UTF-8, or carrying control or
// invisible formatting characters, such as the bidirectional overrides,
// which would let one name render as another. The zero-width joiner and
// non-joiner are formatting characters too, but Persian, the Indic scripts
// and emoji sequences need them, so they are allowed.
func normalizeTenantName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("%w: name is required", ErrInvalidArgument)
	}
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("%w: name is not valid UTF-8", ErrInvalidArgument)
	}
	if utf8.RuneCountInString(name) > tenantNameMaxRunes {
		return "", fmt.Errorf("%w: name is longer than %d characters", ErrInvalidArgument, tenantNameMaxRunes)
	}
	if strings.ContainsFunc(name, refusedNameRune) {
		return "", fmt.Errorf("%w: name contains control or invisible formatting characters", ErrInvalidArgument)
	}
	return name, nil
}

// refusedNameRune reports whether r may not appear in a tenant name: a
// control character, or a formatting one other than the zero-width
// non-joiner (U+200C) and joiner (U+200D).
func refusedNameRune(r rune) bool {
	if r == '\u200c' || r == '\u200d' {
		return false
	}
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}
