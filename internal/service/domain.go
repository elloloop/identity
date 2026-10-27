package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
)

// DomainService implements the redesign's tenant domain-verification RPCs:
// a tenant admin registers an email domain, publishes the verification
// challenge, then proves ownership — which claims the (until-then latent)
// tenant and makes the verifier its owner.
//
// It is project-scoped governance: every operation resolves the caller's
// Project from the request context and rejects when none is present. It is
// available only on the postgres control-plane driver; memory
// deployments construct no DomainService and the handler returns
// Unimplemented.

// domainVerifyTXTPrefix is the prefix of the DNS TXT record value a
// tenant publishes to prove control of a domain. The full value is
// deterministic per (project, tenant, domain) — derivable by the server
// without persisting a per-domain token — see dnsTXTChallenge.
const domainVerifyTXTPrefix = "identity-domain-verify="

// ErrDomainAttemptsLimited is returned when a tenant has already made the
// configured number of domain registrations and verifications in the
// current window (GATEWAY_TENANT_DOMAIN_ATTEMPTS_MAX_PER_TENANT per
// GATEWAY_TENANT_DOMAIN_ATTEMPTS_WINDOW_SECONDS). Mapped to
// CodeResourceExhausted.
var ErrDomainAttemptsLimited = errors.New("too many domain registrations and verifications from this tenant recently; try again later")

// DNSResolver looks up DNS TXT records. It is the single I/O boundary of
// VerifyDomain, injected so callers (and tests) can supply the lookup
// implementation instead of always hitting real DNS. *net.Resolver
// satisfies it; the embedding API (identityserver.Options.DNSResolver)
// threads a custom one through for full-stack tests against a real DB.
type DNSResolver interface {
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

// DomainService verifies tenant email domains within a project.
type DomainService struct {
	domains     DomainStore
	tenants     TenantStore
	memberships MembershipStore
	resolver    DNSResolver
	cfg         *config.Config
	logger      *zap.Logger
	// audit records SetDomainJoin changes (WithAudit); nil records nothing.
	audit   *audit.Logger
	nowFunc func() time.Time
}

// NewDomainService wires a DomainService. resolver may be nil, in which
// case net.DefaultResolver is used — callers inject a custom resolver to
// drive the TXT-present / TXT-absent paths without touching real DNS.
func NewDomainService(
	domains DomainStore,
	tenants TenantStore,
	memberships MembershipStore,
	resolver DNSResolver,
	cfg *config.Config,
	logger *zap.Logger,
) *DomainService {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &DomainService{
		domains:     domains,
		tenants:     tenants,
		memberships: memberships,
		resolver:    resolver,
		cfg:         cfg,
		logger:      logger,
		nowFunc:     time.Now,
	}
}

// CreatedDomain is the result of CreateDomain: the pending domain plus the
// DNS TXT challenge the caller must publish before VerifyDomain succeeds.
// TXTName/TXTValue are empty for the email method (verified out-of-band).
type CreatedDomain struct {
	Domain   *Domain
	TXTName  string
	TXTValue string
}

// CreateDomain registers a pending email domain on a tenant. callerID must
// already be an owner/admin member of the tenant. For the DNS-TXT method it
// returns the deterministic challenge (TXT name + value) the caller
// publishes; VerifyDomain later checks for it. Each call counts against the
// tenant's domain-attempt cap, refused or not, so the ALREADY_EXISTS answer
// for a name another tenant verified cannot be used to sweep a project's
// verified domains.
func (s *DomainService) CreateDomain(ctx context.Context, callerID, tenantID, domain, method string) (*CreatedDomain, error) {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return nil, err
	}
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	normDomain, err := normalizeDomain(domain)
	if err != nil {
		return nil, err
	}
	method, err = normalizeVerificationMethod(method)
	if err != nil {
		return nil, err
	}

	if _, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID); err != nil {
		return nil, err
	}
	if err := s.recordAttempt(ctx, projectID, tenantID); err != nil {
		return nil, err
	}

	d := &Domain{
		ProjectID:          projectID,
		TenantID:           tenantID,
		Domain:             normDomain,
		VerificationMethod: method,
		Status:             DomainStatusPending,
	}
	id, err := s.domains.CreateDomain(ctx, d)
	if err != nil {
		return nil, err
	}
	d.ID = id

	out := &CreatedDomain{Domain: d}
	if method == DomainVerificationDNSTXT {
		out.TXTName, out.TXTValue = dnsTXTChallenge(projectID, tenantID, normDomain)
	}
	return out, nil
}

// VerifyDomain proves control of a pending domain and, on success, marks
// the domain verified, claims its tenant when it is still latent, and makes
// the caller an owner (an owner already keeps the membership they have).
//
// AuthZ: callerID must be an owner/admin member of the tenant — EXCEPT
// when the tenant is still latent with no members yet, in which case
// verification is open and the first verifier becomes its owner. A
// suspended tenant verifies nothing: claiming it would lift the suspension.
//
// Every write here can move agent governance (migration 0046), so none is
// made that changes nothing: a failed check marks only an unverified claim
// failed — a verified domain whose record has lapsed stays verified until an
// operator acts — and a claimed tenant is not claimed again. Each call that
// reaches the DNS check counts against the tenant's domain-attempt cap.
//
// Only the DNS-TXT method is implemented; the email method returns
// ErrUnimplemented rather than faking success.
func (s *DomainService) VerifyDomain(ctx context.Context, callerID, domainID string) (*Domain, error) {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return nil, err
	}
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	domainID = strings.TrimSpace(domainID)
	if domainID == "" {
		return nil, fmt.Errorf("%w: missing domain_id", ErrInvalidArgument)
	}

	d, err := s.domains.GetDomain(ctx, projectID, domainID)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, fmt.Errorf("%w: domain", ErrNotFound)
	}
	t, err := s.tenants.GetTenant(ctx, projectID, d.TenantID)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, fmt.Errorf("%w: tenant", ErrNotFound)
	}

	if err := s.authorizeVerify(ctx, projectID, t, callerID); err != nil {
		return nil, err
	}

	switch d.VerificationMethod {
	case DomainVerificationDNSTXT:
		// fall through to the DNS check below.
	case DomainVerificationEmail:
		return nil, fmt.Errorf("%w: email domain verification", ErrUnimplemented)
	default:
		return nil, fmt.Errorf("%w: verification method %q", ErrInvalidArgument, d.VerificationMethod)
	}
	if err := s.recordAttempt(ctx, projectID, t.ID); err != nil {
		return nil, err
	}

	if err := s.checkDNSTXT(ctx, projectID, d); err != nil {
		// A missing/mismatched challenge is a verification failure, not an
		// infrastructure error: record it on an unverified claim and surface
		// PermissionDenied.
		if d.Status != DomainStatusVerified {
			if setErr := s.domains.SetDomainStatus(ctx, projectID, d.ID, DomainStatusFailed, 0); setErr != nil {
				s.logger.Warn("domain_verify_set_failed", zap.String("domain_id", d.ID), zap.Error(setErr))
			}
		}
		return nil, err
	}

	if err := s.domains.SetDomainStatus(ctx, projectID, d.ID, DomainStatusVerified, 0); err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			return nil, fmt.Errorf("%w: %s is verified by another tenant", ErrAlreadyExists, d.Domain)
		}
		return nil, err
	}
	if t.Status == TenantStatusLatent {
		if _, err := s.tenants.SetTenantStatus(ctx, projectID, t.ID, TenantStatusLatent, TenantStatusClaimed); err != nil {
			return nil, err
		}
	}
	if _, _, err := s.memberships.GrantMembership(ctx, &TenantMembership{
		ProjectID: projectID,
		TenantID:  t.ID,
		UserID:    callerID,
		Source:    MembershipSourceAdded,
		Role:      RoleOwner,
		Status:    MembershipStatusActive,
	}); err != nil {
		return nil, err
	}

	verified, err := s.domains.GetDomain(ctx, projectID, d.ID)
	if err != nil {
		return nil, err
	}
	return verified, nil
}

// ListTenantDomains returns every domain bound to a tenant. callerID must
// be an owner/admin member of the tenant.
func (s *DomainService) ListTenantDomains(ctx context.Context, callerID, tenantID string) ([]*Domain, error) {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return nil, err
	}
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	if _, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID); err != nil {
		return nil, err
	}
	return s.domains.ListDomainsByTenant(ctx, projectID, tenantID)
}

// authorizeVerify enforces VerifyDomain's access rule: an owner/admin
// member normally, but an open first-verify on a latent tenant that has no
// members yet (the bootstrap case that makes the verifier its first owner).
// A suspended tenant verifies nothing, since verifying would claim it and
// lift the suspension: requireTenantAdmin refuses it, and it is not latent.
func (s *DomainService) authorizeVerify(ctx context.Context, projectID string, t *Tenant, callerID string) error {
	_, err := s.requireTenantAdmin(ctx, projectID, t.ID, callerID)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrPermissionDenied) {
		return err
	}
	if t.Status != TenantStatusLatent {
		return err
	}
	members, err := s.memberships.ListMembershipsForTenant(ctx, projectID, t.ID)
	if err != nil {
		return err
	}
	if len(members) != 0 {
		return ErrPermissionDenied
	}
	return nil
}

// recordAttempt counts one domain registration or verification by tenantID
// against its cap, refusing it with ErrDomainAttemptsLimited past the cap.
func (s *DomainService) recordAttempt(ctx context.Context, projectID, tenantID string) error {
	cfg := configOrDefaults(s.cfg)
	now := s.nowFunc()
	err := s.domains.RecordDomainAttempt(ctx, DomainAttempt{
		ProjectID:     projectID,
		TenantID:      tenantID,
		AtMs:          now.UnixMilli(),
		MaxPerWindow:  cfg.TenantDomainAttemptsLimit(),
		WindowStartMs: now.Add(-cfg.TenantDomainAttemptsWindow()).UnixMilli(),
	})
	if errors.Is(err, ErrDomainAttemptsLimited) {
		s.logger.Info("tenant_domain_attempts_limited",
			zap.String("project_id", projectID), zap.String("tenant_id", tenantID))
	}
	return err
}

// requireTenantAdmin is authorizeTenantAdmin over this service's stores.
func (s *DomainService) requireTenantAdmin(ctx context.Context, projectID, tenantID, callerID string) (*TenantMembership, error) {
	return authorizeTenantAdmin(ctx, s.memberships, s.tenants, projectID, tenantID, callerID)
}

// checkDNSTXT resolves the domain's TXT records and confirms the
// registration's challenge is present: the one naming its tenant, or for a
// legacy registration also the project-wide one it was given. An
// absent/mismatched challenge is ErrPermissionDenied (a verification
// failure, not an infra error).
func (s *DomainService) checkDNSTXT(ctx context.Context, projectID string, d *Domain) error {
	domain := d.Domain
	_, tenantValue := dnsTXTChallenge(projectID, d.TenantID, domain)
	want := map[string]bool{tenantValue: true}
	if d.LegacyTXTChallenge {
		_, legacyValue := legacyDNSTXTChallenge(projectID, domain)
		want[legacyValue] = true
	}
	records, err := s.resolver.LookupTXT(ctx, domain)
	if err != nil {
		// A lookup error (NXDOMAIN, SERVFAIL, timeout) means the challenge
		// is not provably published — treat it as a verification failure
		// the caller can retry, not an internal server fault.
		s.logger.Info("domain_verify_lookup_failed", zap.String("domain", domain), zap.Error(err))
		return fmt.Errorf("%w: DNS TXT challenge not found for %s", ErrPermissionDenied, domain)
	}
	for _, rec := range records {
		if want[strings.TrimSpace(rec)] {
			return nil
		}
	}
	return fmt.Errorf("%w: DNS TXT challenge not found for %s", ErrPermissionDenied, domain)
}

// requireProject resolves the caller's project, rejecting when none is in
// the request context.
func (s *DomainService) requireProject(ctx context.Context) (string, error) {
	if scope := ProjectScopeFromContext(ctx); scope != nil && scope.ProjectID != "" {
		return scope.ProjectID, nil
	}
	return "", fmt.Errorf("%w: no project in request scope", ErrPermissionDenied)
}

// txtOwnershipChallenge returns the TXT record name and value a host must
// publish to prove ownership, under the given verification prefix. The name is
// the host itself; the value is deterministic per (scope, host), so no
// per-host token is stored. scope is whoever the proof is for: the project for
// a custom auth domain (authDomainTXTChallenge in admin_api.go), the project
// and tenant for an email domain (dnsTXTChallenge) — the same proof shape,
// differing by prefix and scope.
func txtOwnershipChallenge(prefix, scope, host string) (name, value string) {
	digest := sha256Hex(scope + ":" + strings.ToLower(host))
	return host, prefix + digest
}

// dnsTXTChallenge returns the TXT record name and value tenantID publishes
// to prove it controls an email domain. The value names the tenant as well
// as the project, because several tenants may hold a claim on one domain:
// the record the domain's owner publishes then verifies the owner's claim
// and no one else's. Each part is length-prefixed, so no two distinct
// (project, tenant) pairs share a value.
func dnsTXTChallenge(projectID, tenantID, domain string) (name, value string) {
	scope := fmt.Sprintf("%d:%s:%d:%s", len(projectID), projectID, len(tenantID), tenantID)
	return txtOwnershipChallenge(domainVerifyTXTPrefix, scope, domain)
}

// legacyDNSTXTChallenge is the project-wide value CreateDomain handed out
// while a domain could have only one claim in a project. A registration
// made then (Domain.LegacyTXTChallenge) still verifies with it; it is never
// handed out again, so no later claim can be verified by it.
func legacyDNSTXTChallenge(projectID, domain string) (name, value string) {
	return txtOwnershipChallenge(domainVerifyTXTPrefix, projectID, domain)
}

// normalizeHostname lower-cases, trims, and strips a trailing dot from a host,
// rejecting blanks and anything with whitespace, a scheme, an '@', or no dot at
// all — the shape a real fully-qualified hostname/domain must take. label names
// the value in error messages ("domain" / "hostname"). Shared by email-domain
// (normalizeDomain) and custom auth-domain (normalizeAuthHostname) validation.
func normalizeHostname(label, host string) (string, error) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return "", fmt.Errorf("%w: missing %s", ErrInvalidArgument, label)
	}
	if strings.ContainsAny(h, " \t/@:") || !strings.Contains(h, ".") {
		return "", fmt.Errorf("%w: invalid %s %q", ErrInvalidArgument, label, host)
	}
	return h, nil
}

// normalizeDomain validates an email domain.
func normalizeDomain(domain string) (string, error) {
	return normalizeHostname("domain", domain)
}

// normalizeVerificationMethod defaults a blank method to DNS-TXT and
// rejects an unknown one.
func normalizeVerificationMethod(method string) (string, error) {
	switch m := strings.TrimSpace(strings.ToLower(method)); m {
	case "", DomainVerificationDNSTXT:
		return DomainVerificationDNSTXT, nil
	case DomainVerificationEmail:
		return DomainVerificationEmail, nil
	default:
		return "", fmt.Errorf("%w: verification_method %q (want %q or %q)",
			ErrInvalidArgument, method, DomainVerificationDNSTXT, DomainVerificationEmail)
	}
}

// isAdminRole reports whether role grants tenant administration (owner or
// admin). Plain members may not manage domains.
func isAdminRole(role string) bool {
	return role == RoleOwner || role == RoleAdmin
}
