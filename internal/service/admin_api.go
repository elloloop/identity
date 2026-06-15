package service

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
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

// authDomainVerifyTXTPrefix prefixes the DNS TXT value a customer publishes to
// prove control of a custom serving hostname. The full value is the prefix +
// hex(sha256(projectID + ":" + lower(hostname))) — deterministic per
// (project, hostname), so the server can both issue the challenge and re-issue
// the identical one on a retry without persisting a per-domain token (matching
// the tenant email-domain pattern in domain.go).
const authDomainVerifyTXTPrefix = "identity-auth-domain-verify="

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

// AdminProjectAuthDomain is a project's serving hostname as the admin service
// reads it back. VerifiedAtMs is 0 until ownership is proven; a domain with 0
// does NOT resolve requests.
type AdminProjectAuthDomain struct {
	Hostname     string
	IsPrimary    bool
	VerifiedAtMs int64
}

// ControlPlaneProjectStore is the narrow write side of the control-plane
// project registry the admin service needs. *pgrepo.ProjectStore satisfies
// it; injecting only this method set keeps the service decoupled from the
// full store surface and trivially fakeable.
//
// EnsureAuthDomain is idempotent and seeds the domain VERIFIED at
// verifiedAtMs (operator-asserted — the operator vouches for the hostname,
// so it needs no DNS challenge). The customer-facing custom-domain methods
// (CreateAuthDomain / GetAuthDomain / ListAuthDomains / SetAuthDomainVerified)
// instead register a domain UNVERIFIED and flip it only after a DNS-TXT
// ownership proof.
type ControlPlaneProjectStore interface {
	CreateProject(ctx context.Context, p *AdminProject) (string, error)
	CreateProjectCredential(ctx context.Context, c *AdminProjectCredential) (string, error)
	EnsureAuthDomain(ctx context.Context, projectID, hostname string, isPrimary bool, verifiedAtMs int64) error

	// CreateAuthDomain registers an UNVERIFIED serving hostname (verifiedAtMs
	// is 0). A hostname already bound to any project surfaces ErrAlreadyExists.
	CreateAuthDomain(ctx context.Context, projectID, hostname string, isPrimary bool) error
	// GetAuthDomain returns a project's own auth-domain, or (nil, nil) when the
	// project has no such hostname.
	GetAuthDomain(ctx context.Context, projectID, hostname string) (*AdminProjectAuthDomain, error)
	// ListAuthDomains returns every auth-domain of a project, primary-first.
	ListAuthDomains(ctx context.Context, projectID string) ([]*AdminProjectAuthDomain, error)
	// SetAuthDomainVerified stamps verifiedAtMs (> 0) on a project's own
	// auth-domain, making it resolve. A hostname the project does not own
	// surfaces ErrNotFound.
	SetAuthDomainVerified(ctx context.Context, projectID, hostname string, verifiedAtMs int64) error
	// SetPrimaryAuthDomain promotes a project's VERIFIED auth-domain to its
	// primary serving host, atomically demoting the current primary in one
	// transaction so the per-project primary uniqueness is never violated. An
	// unverified target surfaces ErrAuthDomainNotVerified; a hostname the
	// project does not own surfaces ErrNotFound.
	SetPrimaryAuthDomain(ctx context.Context, projectID, hostname string) (*AdminProjectAuthDomain, error)
}

// ControlPlaneAdminService provisions control-plane resources on behalf of a
// platform operator authenticated by a shared secret.
type ControlPlaneAdminService struct {
	// secret is the shared admin secret. Empty disables the whole surface.
	secret      string
	projects    ControlPlaneProjectStore
	tenants     TenantStore
	memberships MembershipStore
	// admins backs the zero-config first-admin bootstrap. nil when this build
	// has no control plane (entdb/memory), which makes CreateFirstPlatformAdmin
	// return ErrUnimplemented.
	admins PlatformAdminStore
	// resolver is the DNS TXT-lookup boundary VerifyProjectAuthDomain uses to
	// confirm a custom domain's ownership challenge. Injected so tests drive
	// the present/absent paths without real DNS.
	resolver DNSResolver
	// audit records control-plane security events. Currently it captures
	// BLOCKED first-admin bootstrap attempts (a call after an admin already
	// exists) so a closed-bootstrap probe is visible in the audit trail. nil
	// is tolerated (best-effort): NewControlPlaneAdminService installs a
	// no-op logger so call sites never nil-check.
	audit   *audit.Logger
	logger  *zap.Logger
	nowFunc func() int64
}

// NewControlPlaneAdminService wires the admin service. An empty secret
// leaves the service constructed but DISABLED: every method returns
// ErrUnimplemented (so the handler maps it to CodeUnimplemented). A nil
// logger defaults to a no-op. A nil resolver defaults to net.DefaultResolver,
// matching DomainService. A nil auditLog defaults to a no-op audit.Logger so
// blocked-bootstrap recording stays best-effort. nowFunc is injected so the
// auth-domain verified-at stamp is deterministic in tests; it defaults to
// wall-clock epoch-millis.
func NewControlPlaneAdminService(
	secret string,
	projects ControlPlaneProjectStore,
	tenants TenantStore,
	memberships MembershipStore,
	admins PlatformAdminStore,
	resolver DNSResolver,
	auditLog *audit.Logger,
	logger *zap.Logger,
) *ControlPlaneAdminService {
	if logger == nil {
		logger = zap.NewNop()
	}
	if auditLog == nil {
		auditLog = audit.NewLogger(nil, "", zap.NewNop())
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &ControlPlaneAdminService{
		secret:      secret,
		projects:    projects,
		tenants:     tenants,
		memberships: memberships,
		admins:      admins,
		resolver:    resolver,
		audit:       auditLog,
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

// RegisteredAuthDomain is the result of AddProjectAuthDomain: the registered
// (still-UNVERIFIED) domain plus the deterministic DNS TXT challenge the
// caller must publish before VerifyProjectAuthDomain succeeds.
type RegisteredAuthDomain struct {
	Domain   *AdminProjectAuthDomain
	TXTName  string
	TXTValue string
}

// AddProjectAuthDomain registers a CUSTOMER-owned serving hostname on a
// project, UNVERIFIED, and returns the DNS TXT challenge to publish. Unlike
// AdminAddProjectAuthDomain (operator-vouched, seeded verified), the domain
// does NOT resolve requests until VerifyProjectAuthDomain proves ownership.
// Re-adding an already-registered hostname returns its existing record and
// the same deterministic challenge, so a caller can re-fetch the TXT value
// without a conflict. A hostname owned by a DIFFERENT project surfaces the
// store's ErrAlreadyExists.
//
// isPrimary=true is rejected with ErrInvalidArgument: a custom domain is always
// added NON-primary here, because an unverified host must not resolve, let
// alone drive branded links. To make a custom domain primary, add it
// non-primary, verify it, then call SetPrimaryAuthDomain — which promotes only
// a verified domain and atomically demotes the current primary.
func (s *ControlPlaneAdminService) AddProjectAuthDomain(ctx context.Context, secret, projectID, hostname string, isPrimary bool) (*RegisteredAuthDomain, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	if isPrimary {
		return nil, fmt.Errorf("%w: a custom auth-domain is added non-primary; verify it, then call SetPrimaryAuthDomain to promote it", ErrInvalidArgument)
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	hostname, err := normalizeAuthHostname(hostname)
	if err != nil {
		return nil, err
	}

	existing, err := s.projects.GetAuthDomain(ctx, projectID, hostname)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		if err := s.projects.CreateAuthDomain(ctx, projectID, hostname, isPrimary); err != nil {
			return nil, err
		}
		existing, err = s.projects.GetAuthDomain(ctx, projectID, hostname)
		if err != nil {
			return nil, err
		}
		if existing == nil {
			return nil, fmt.Errorf("%w: auth domain not found after create", ErrNotFound)
		}
	}

	name, value := authDomainTXTChallenge(projectID, hostname)
	return &RegisteredAuthDomain{Domain: existing, TXTName: name, TXTValue: value}, nil
}

// VerifyProjectAuthDomain checks the DNS TXT ownership challenge for a
// project's custom auth-domain and, on success, stamps verified_at_ms so the
// hostname resolves. A missing/mismatched TXT record leaves the domain
// unverified and surfaces ErrPermissionDenied (a verification failure the
// caller can retry); a hostname the project does not own is ErrNotFound. An
// already-verified domain is idempotent — re-verifying re-checks DNS and
// returns the current record.
func (s *ControlPlaneAdminService) VerifyProjectAuthDomain(ctx context.Context, secret, projectID, hostname string) (*AdminProjectAuthDomain, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	hostname, err := normalizeAuthHostname(hostname)
	if err != nil {
		return nil, err
	}

	d, err := s.projects.GetAuthDomain(ctx, projectID, hostname)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, fmt.Errorf("%w: auth domain", ErrNotFound)
	}

	if err := s.checkAuthDomainTXT(ctx, projectID, hostname); err != nil {
		return nil, err
	}

	// Stamp only when not already verified, so a re-verify does not move the
	// timestamp; either way return the current record.
	if d.VerifiedAtMs <= 0 {
		if err := s.projects.SetAuthDomainVerified(ctx, projectID, hostname, s.nowFunc()); err != nil {
			return nil, err
		}
		d, err = s.projects.GetAuthDomain(ctx, projectID, hostname)
		if err != nil {
			return nil, err
		}
		if d == nil {
			return nil, fmt.Errorf("%w: auth domain", ErrNotFound)
		}
	}
	return d, nil
}

// SetPrimaryAuthDomain promotes a VERIFIED custom auth-domain to the project's
// primary serving host. The store demotes the current primary and promotes the
// target in a SINGLE transaction, so the per-project primary uniqueness is
// never violated, even under concurrent promotions. Only a verified domain may
// be promoted (an unverified target is ErrAuthDomainNotVerified); a hostname
// the project does not own is ErrNotFound. The returned record reflects the
// newly-promoted (now primary) host, which the resolver's primaryAuthHostname /
// PrimaryAuthDomain then surfaces.
func (s *ControlPlaneAdminService) SetPrimaryAuthDomain(ctx context.Context, secret, projectID, hostname string) (*AdminProjectAuthDomain, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	hostname, err := normalizeAuthHostname(hostname)
	if err != nil {
		return nil, err
	}
	return s.projects.SetPrimaryAuthDomain(ctx, projectID, hostname)
}

// ListProjectAuthDomains returns every auth-domain of a project, primary-first
// (the store's ordering), so a caller sees both verified and pending domains.
func (s *ControlPlaneAdminService) ListProjectAuthDomains(ctx context.Context, secret, projectID string) ([]*AdminProjectAuthDomain, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	return s.projects.ListAuthDomains(ctx, projectID)
}

// checkAuthDomainTXT resolves the hostname's TXT records and confirms the
// deterministic challenge is present. An absent/mismatched challenge (or a
// lookup failure — NXDOMAIN, SERVFAIL, timeout) is ErrPermissionDenied: a
// verification failure the caller can retry, not an internal fault.
func (s *ControlPlaneAdminService) checkAuthDomainTXT(ctx context.Context, projectID, hostname string) error {
	_, want := authDomainTXTChallenge(projectID, hostname)
	records, err := s.resolver.LookupTXT(ctx, hostname)
	if err != nil {
		s.logger.Info("auth_domain_verify_lookup_failed", zap.String("hostname", hostname), zap.Error(err))
		return fmt.Errorf("%w: DNS TXT challenge not found for %s", ErrPermissionDenied, hostname)
	}
	for _, rec := range records {
		if strings.TrimSpace(rec) == want {
			return nil
		}
	}
	return fmt.Errorf("%w: DNS TXT challenge not found for %s", ErrPermissionDenied, hostname)
}

// authDomainTXTChallenge returns the TXT record name and value a custom serving
// hostname must publish to prove ownership, under the auth-domain prefix.
func authDomainTXTChallenge(projectID, hostname string) (name, value string) {
	return txtOwnershipChallenge(authDomainVerifyTXTPrefix, projectID, hostname)
}

// normalizeAuthHostname validates a custom serving hostname.
func normalizeAuthHostname(hostname string) (string, error) {
	return normalizeHostname("hostname", hostname)
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

// BootstrappedAdmin is the result of CreateFirstPlatformAdmin: the created
// admin's id and canonical email, plus GeneratedPassword — a server-minted
// password shown EXACTLY once, and only when the caller supplied no password.
// When the caller supplied their own password, GeneratedPassword is empty.
type BootstrappedAdmin struct {
	ID                string
	Email             string
	GeneratedPassword string
}

// CreateFirstPlatformAdmin is the zero-config bootstrap that establishes the
// FIRST platform admin on a fresh deployment. It is the one Admin RPC that is
// NOT secret-gated: a brand-new deployer has configured nothing yet, so
// gating it on GATEWAY_ADMIN_API_SECRET would make standing up the first
// operator impossible. Instead it is self-securing — it succeeds ONLY while
// the platform_admins table is empty and PERMANENTLY closes
// (ErrPlatformAdminExists → FailedPrecondition) once any admin exists, so it
// can never be replayed to escalate privilege on a provisioned deployment.
//
// The emptiness check and the insert are one atomic, serialized store
// operation (admins.CreateFirstPlatformAdmin), so two concurrent bootstraps
// create exactly one admin and the loser is rejected — there is no
// check-then-write window.
//
// When password is blank the server generates a strong one and returns it
// once in GeneratedPassword; when supplied it must satisfy the password
// strength policy (else ErrWeakPassword → InvalidArgument). Only the bcrypt
// hash is ever stored. When no control plane is wired (entdb/memory have no
// platform_admins table) it returns ErrUnimplemented.
func (s *ControlPlaneAdminService) CreateFirstPlatformAdmin(ctx context.Context, email, password string) (*BootstrappedAdmin, error) {
	if s.admins == nil {
		return nil, ErrUnimplemented
	}
	email = strings.TrimSpace(email)
	if err := validateEmailFormat(email); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidArgument, err.Error())
	}
	canonicalEmail := canonicalizeEmail(email)

	// Unlocked fast-path: on a provisioned deployment the bootstrap is
	// permanently closed, and that closed state is the overwhelmingly common
	// case (every probe after the first real bootstrap). An unlocked
	// CountPlatformAdmins lets that path skip the advisory-lock transaction —
	// and the bcrypt hash below — entirely. It is a pure OPTIMISATION, never
	// the correctness gate: the authoritative emptiness check is the atomic,
	// serialized CreateFirstPlatformAdmin recount below, so a concurrent first
	// bootstrap that slips past this read is still rejected race-safely.
	if n, err := s.admins.CountPlatformAdmins(ctx); err == nil && n > 0 {
		s.recordBootstrapBlocked(ctx, canonicalEmail)
		return nil, ErrPlatformAdminExists
	}

	// A blank password means "generate one"; a supplied one must be strong.
	// The generated password is returned to the caller exactly once.
	generated := ""
	if strings.TrimSpace(password) == "" {
		password = generateTempPassword()
		generated = password
	} else if err := validatePasswordStrength(password); err != nil {
		return nil, err
	}

	hash, err := passwords.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hashing bootstrap admin password: %w", err)
	}

	admin := &PlatformAdmin{
		Email:        canonicalEmail,
		PasswordHash: hash,
		Status:       PlatformAdminStatusActive,
		CreatedAtMs:  s.nowFunc(),
	}
	created, err := s.admins.CreateFirstPlatformAdmin(ctx, admin)
	if err != nil {
		return nil, err
	}
	if !created {
		// The table was not empty: an admin already exists, so the bootstrap
		// is permanently closed. This is the privilege-escalation guard — and
		// the authoritative one (the locked recount races safe, unlike the
		// unlocked pre-check above). Record it too: a request that lost the
		// pre-check race but is still a closed-bootstrap probe must be visible.
		s.recordBootstrapBlocked(ctx, canonicalEmail)
		return nil, ErrPlatformAdminExists
	}

	s.logger.Info("platform_admin_bootstrapped", zap.String("admin_id", admin.ID), zap.String("email", canonicalEmail))
	return &BootstrappedAdmin{
		ID:                admin.ID,
		Email:             canonicalEmail,
		GeneratedPassword: generated,
	}, nil
}

// recordBootstrapBlocked emits a best-effort audit event for a first-admin
// bootstrap attempt that was rejected because the platform is already
// provisioned (an admin exists). The bootstrap RPC is unauthenticated and
// ungated, so a probe against the closed endpoint carries no actor identity —
// the event records the attempted email and lands under the control-plane
// default project (the audit Logger's boot-default binding), making
// closed-bootstrap probes visible in the audit trail.
//
// TODO(login): once a platform-admin LOGIN path consumes platform_admins,
// enforce PlatformAdmin.TOTPRequired there — an admin flagged TOTPRequired
// must complete a second factor before a session is minted. There is no login
// path yet, so this hardening pass deliberately does not build one; the flag
// is persisted by the store and waits for that slice.
func (s *ControlPlaneAdminService) recordBootstrapBlocked(ctx context.Context, attemptedEmail string) {
	s.audit.Log(
		ctx, audit.EventPlatformAdminBootstrapBlocked,
		audit.WithSuccess(false),
		audit.WithDetails(map[string]any{"attempted_email": attemptedEmail}),
	)
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
