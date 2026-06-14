package service

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ControlPlaneAdminService implements the redesign's control-plane admin
// RPCs: PLATFORM-operator operations that provision projects, project
// credentials, project auth-domains, tenants and the first tenant admin —
// the out-of-band bootstrap a deployer runs before any human can self-serve.
//
// It is authenticated DIFFERENTLY from every other service: not by a user
// JWT but by a shared secret the operator presents on each call. The secret
// is held here and compared in CONSTANT TIME (crypto/subtle) against the
// per-request value, so a wrong or missing secret is rejected uniformly and
// without a timing side-channel. When the configured secret is empty the
// whole surface is DISABLED — every method returns ErrUnimplemented — so a
// deployer who never sets GATEWAY_ADMIN_API_SECRET cannot have these RPCs
// reached.
//
// Like the other governance services it is postgres-only: entdb/memory have
// no control plane, so the app constructs no ControlPlaneAdminService and the
// handler returns Unimplemented.
//
// TODO(redesign): the shared secret is the shipped auth mechanism. Future
// work hardens it with mTLS client-certificate auth and an optional
// internal-only listener port bound away from the public RPC surface.

// adminPublicIDBytes / adminSecretBytes size the two halves of a minted
// project credential. The public id is the (non-secret) lookup key; the
// secret half is the part shown once and stored only as a hash.
const (
	adminPublicIDBytes = 16
	adminSecretBytes   = 32
)

// Credential kinds an operator may mint. "publishable" is a public lookup
// key with no secret half; "secret" carries a secret shown exactly once.
const (
	CredentialKindPublishable = "publishable"
	CredentialKindSecret      = "secret"
)

// Credential public-id prefixes, so a key is self-describing at a glance
// (Stripe-style): pk_ for publishable, sk_ for secret.
const (
	publishableKeyPrefix = "pk_"
	secretKeyPrefix      = "sk_"
)

// AdminProject is the control-plane project row an operator creates. It is a
// driver-agnostic value type so the admin service and its tests depend on a
// contract, not the concrete postgres store type.
type AdminProject struct {
	ID             string
	StorageScopeID string
	Name           string
}

// AdminProjectCredential is the credential row an operator mints. Only the
// hash of the secret is persisted; the raw secret never round-trips through
// the store.
type AdminProjectCredential struct {
	ID         string
	ProjectID  string
	Kind       string
	PublicID   string
	SecretHash string
}

// ControlPlaneProjectStore is the narrow write side of the control-plane
// project registry the admin service needs. *pgrepo.ProjectStore satisfies
// it; injecting only these three methods keeps the service decoupled from
// the full store surface and trivially fakeable.
//
// EnsureAuthDomain is idempotent and seeds the domain VERIFIED at
// verifiedAtMs (operator-asserted — the operator vouches for the hostname,
// so it needs no DNS challenge).
type ControlPlaneProjectStore interface {
	CreateProject(ctx context.Context, p *AdminProject) (string, error)
	CreateProjectCredential(ctx context.Context, c *AdminProjectCredential) (string, error)
	EnsureAuthDomain(ctx context.Context, projectID, hostname string, isPrimary bool, verifiedAtMs int64) error
}

// ControlPlaneAdminService provisions control-plane resources on behalf of a
// platform operator authenticated by a shared secret.
type ControlPlaneAdminService struct {
	// secret is the shared admin secret. Empty disables the whole surface.
	secret      string
	projects    ControlPlaneProjectStore
	tenants     TenantStore
	memberships MembershipStore
	logger      *zap.Logger
	nowFunc     func() int64
}

// NewControlPlaneAdminService wires the admin service. An empty secret
// leaves the service constructed but DISABLED: every method returns
// ErrUnimplemented (so the handler maps it to CodeUnimplemented). A nil
// logger defaults to a no-op. nowFunc is injected so the auth-domain
// verified-at stamp is deterministic in tests; it defaults to wall-clock
// epoch-millis.
func NewControlPlaneAdminService(
	secret string,
	projects ControlPlaneProjectStore,
	tenants TenantStore,
	memberships MembershipStore,
	logger *zap.Logger,
) *ControlPlaneAdminService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ControlPlaneAdminService{
		secret:      secret,
		projects:    projects,
		tenants:     tenants,
		memberships: memberships,
		logger:      logger,
		nowFunc:     func() int64 { return time.Now().UnixMilli() },
	}
}

// Enabled reports whether the admin surface is active (a non-empty secret is
// configured). The handler consults it to return Unimplemented up front
// without leaking, via the secret check, whether a secret happens to match.
func (s *ControlPlaneAdminService) Enabled() bool {
	return s.secret != ""
}

// authorize gates every admin RPC. When no secret is configured the surface
// is disabled (ErrUnimplemented). Otherwise the presented secret must match
// the configured one in constant time; a blank or mismatched secret is
// ErrPermissionDenied. The constant-time compare ensures a near-miss secret
// is indistinguishable, by timing, from a wildly wrong one.
func (s *ControlPlaneAdminService) authorize(presented string) error {
	if s.secret == "" {
		return ErrUnimplemented
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(s.secret)) != 1 {
		return ErrPermissionDenied
	}
	return nil
}

// AdminCreateProject provisions a new control-plane project mapped onto the
// given physical storage scope, and returns its id. storage_scope_id is
// required and globally unique (a duplicate surfaces ErrAlreadyExists).
func (s *ControlPlaneAdminService) AdminCreateProject(ctx context.Context, secret, name, storageScopeID string) (string, error) {
	if err := s.authorize(secret); err != nil {
		return "", err
	}
	storageScopeID = strings.TrimSpace(storageScopeID)
	if storageScopeID == "" {
		return "", fmt.Errorf("%w: missing storage_scope_id", ErrInvalidArgument)
	}
	return s.projects.CreateProject(ctx, &AdminProject{
		StorageScopeID: storageScopeID,
		Name:           strings.TrimSpace(name),
	})
}

// MintedCredential is the result of AdminCreateProjectCredential: the stored
// row's id and public lookup id, plus the RAW key shown exactly once. RawKey
// is empty for a publishable kind (which has no secret half).
type MintedCredential struct {
	ID       string
	PublicID string
	RawKey   string
}

// AdminCreateProjectCredential mints a lookup credential for a project. For a
// publishable kind it generates a public id only (no secret). For a secret
// kind it generates a public id AND a secret half: the secret's hash is
// stored, and the full "publicID.secret" raw key is returned ONCE — the only
// time it is ever shown, exactly like an API key. The public id is always the
// lookup key the project resolver matches on.
func (s *ControlPlaneAdminService) AdminCreateProjectCredential(ctx context.Context, secret, projectID, kind string) (*MintedCredential, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	kind, prefix, err := normalizeCredentialKind(kind)
	if err != nil {
		return nil, err
	}

	publicID := prefix + randomToken(adminPublicIDBytes)
	cred := &AdminProjectCredential{
		ProjectID: projectID,
		Kind:      kind,
		PublicID:  publicID,
	}
	out := &MintedCredential{PublicID: publicID}
	if kind == CredentialKindSecret {
		rawSecret := randomToken(adminSecretBytes)
		cred.SecretHash = sha256Hex(rawSecret)
		// The raw key is the public id and the secret joined; the caller
		// presents it whole, and the resolver looks up by the public-id half.
		out.RawKey = publicID + "." + rawSecret
	}

	id, err := s.projects.CreateProjectCredential(ctx, cred)
	if err != nil {
		return nil, err
	}
	out.ID = id
	return out, nil
}

// AdminAddProjectAuthDomain registers a serving hostname on a project,
// idempotently and seeded VERIFIED (the operator vouches for it). It lets an
// operator add branded/serving hostnames at runtime, complementing the
// GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS config-seed. A hostname already bound
// to a DIFFERENT project surfaces the store's conflict error.
func (s *ControlPlaneAdminService) AdminAddProjectAuthDomain(ctx context.Context, secret, projectID, hostname string, isPrimary bool) error {
	if err := s.authorize(secret); err != nil {
		return err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" {
		return fmt.Errorf("%w: missing hostname", ErrInvalidArgument)
	}
	return s.projects.EnsureAuthDomain(ctx, projectID, hostname, isPrimary, s.nowFunc())
}

// AdminCreateTenant provisions a tenant under a project and returns its id.
// An operator-created tenant is seeded CLAIMED, not latent: the operator
// vouches for it out-of-band, so it is immediately authoritative (its
// login policy and membership apply) without a domain-verification round.
func (s *ControlPlaneAdminService) AdminCreateTenant(ctx context.Context, secret, projectID, name, primaryDomain string) (string, error) {
	if err := s.authorize(secret); err != nil {
		return "", err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return "", fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	return s.tenants.CreateTenant(ctx, &Tenant{
		ProjectID:     projectID,
		Name:          strings.TrimSpace(name),
		PrimaryDomain: strings.ToLower(strings.TrimSpace(primaryDomain)),
		Status:        TenantStatusClaimed,
	})
}

// AdminAddTenantAdmin makes a user an owner/admin of a tenant (source=added),
// bootstrapping the first tenant administrator so a human can then self-serve
// (invite others, verify domains, manage members). The role defaults to
// owner — the highest privilege an operator would grant when standing up a
// tenant — and may be admin; plain member is rejected (this RPC bootstraps
// administration, not ordinary membership).
func (s *ControlPlaneAdminService) AdminAddTenantAdmin(ctx context.Context, secret, projectID, tenantID, userID, role string) (*TenantMembership, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	tenantID = strings.TrimSpace(tenantID)
	userID = strings.TrimSpace(userID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	if tenantID == "" {
		return nil, fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	if userID == "" {
		return nil, fmt.Errorf("%w: missing user_id", ErrInvalidArgument)
	}
	role, err := normalizeAdminRole(role)
	if err != nil {
		return nil, err
	}
	m := &TenantMembership{
		ProjectID: projectID,
		TenantID:  tenantID,
		UserID:    userID,
		Source:    MembershipSourceAdded,
		Role:      role,
		Status:    MembershipStatusActive,
	}
	id, err := s.memberships.UpsertMembership(ctx, m)
	if err != nil {
		return nil, err
	}
	m.ID = id
	return m, nil
}

// normalizeCredentialKind defaults a blank kind to publishable and returns
// the canonical kind plus its public-id prefix, rejecting an unknown one.
func normalizeCredentialKind(kind string) (canonical, prefix string, err error) {
	switch k := strings.TrimSpace(strings.ToLower(kind)); k {
	case "", CredentialKindPublishable:
		return CredentialKindPublishable, publishableKeyPrefix, nil
	case CredentialKindSecret:
		return CredentialKindSecret, secretKeyPrefix, nil
	default:
		return "", "", fmt.Errorf("%w: credential kind %q (want %q or %q)",
			ErrInvalidArgument, kind, CredentialKindPublishable, CredentialKindSecret)
	}
}

// normalizeAdminRole defaults a blank role to owner and rejects anything but
// owner/admin — AdminAddTenantAdmin bootstraps tenant administration, so it
// will not grant a plain-member role.
func normalizeAdminRole(role string) (string, error) {
	switch r := strings.TrimSpace(strings.ToLower(role)); r {
	case "", RoleOwner:
		return RoleOwner, nil
	case RoleAdmin:
		return RoleAdmin, nil
	default:
		return "", fmt.Errorf("%w: role %q (want %q or %q)",
			ErrInvalidArgument, role, RoleOwner, RoleAdmin)
	}
}
