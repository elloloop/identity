package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/elloloop/identity/pkg/audit"
)

// Joining by domain: a tenant admin lets the people whose verified email is
// on one of the tenant's verified domains join it themselves (SetDomainJoin);
// such a person finds the tenant (ListJoinableTenants) and joins it
// (JoinTenantByDomain) without an invitation. It is off on every domain
// until an admin turns it on. A signup on a verified domain still joins as
// auto-formation always did (TenantAutoFormStore); this is for the accounts
// auto-formation never joined, such as those made before the domain was
// verified.

// JoinableTenant is a tenant the caller may join by their verified email's
// domain: only its id and name, which the caller needs to choose it.
type JoinableTenant struct {
	TenantID string
	Name     string
}

// WithAudit wires the audit trail SetDomainJoin records into. A nil logger
// (the default) records nothing.
func (s *DomainService) WithAudit(l *audit.Logger) *DomainService {
	s.audit = l
	return s
}

// WithDomains wires the domain store ListJoinableTenants and
// JoinTenantByDomain read the caller's verified domain from. Without it
// (nil, the default) both are ErrUnimplemented.
func (s *MembershipService) WithDomains(d DomainStore) *MembershipService {
	s.domains = d
	return s
}

// SetDomainJoin turns joining by a domain on or off: while it is on and the
// domain is verified, a person whose verified email is on it may join the
// domain's tenant with JoinTenantByDomain. callerID must be an owner or admin
// of the domain's tenant, and the tenant must not be suspended. The setting
// may be made on a domain that is not verified yet, and takes effect once it
// is. Turning it off ends no membership.
//
// A change is recorded as EventDomainJoinSet, with callerID as actor and the
// domain as target. Asking for the value the domain already has returns it
// unchanged and records nothing, so a retry is safe.
func (s *DomainService) SetDomainJoin(ctx context.Context, callerID, domainID string, allowJoin bool, ip, userAgent string) (*Domain, error) {
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
	if _, err := s.requireTenantAdmin(ctx, projectID, d.TenantID, callerID); err != nil {
		return nil, err
	}
	changed, err := s.domains.SetDomainAllowJoin(ctx, projectID, d.ID, allowJoin)
	if err != nil {
		return nil, err
	}
	if !changed {
		d.AllowJoin = allowJoin
		return d, nil
	}
	if s.audit != nil {
		s.audit.Log(ctx, audit.EventDomainJoinSet,
			audit.WithActor(callerID), audit.WithTarget(d.ID),
			audit.WithIP(ip), audit.WithUserAgent(userAgent),
			audit.WithSuccess(true), audit.WithDetails(map[string]any{
				"project_id": projectID,
				"tenant_id":  d.TenantID,
				"domain":     d.Domain,
				"allow_join": allowJoin,
			}),
		)
	}
	updated, err := s.domains.GetDomain(ctx, projectID, d.ID)
	if err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, fmt.Errorf("%w: domain", ErrNotFound)
	}
	return updated, nil
}

// ListJoinableTenants returns the tenant callerID may join by their verified
// email's domain, if there is one they do not already belong to: the claimed
// tenant that has verified that domain and lets it join. A project holds a
// verified domain on one tenant at most, so the list has at most one entry
// today. An account that could not join (an unverified email, a public
// provider's domain, an anonymous, agent or inactive account) gets an empty
// list, as does one already an active member.
func (s *MembershipService) ListJoinableTenants(ctx context.Context, callerID string) ([]*JoinableTenant, error) {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return nil, err
	}
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	if s.domains == nil {
		return nil, ErrUnimplemented
	}
	caller, err := s.users.GetUserInProject(ctx, projectID, callerID)
	if err != nil {
		return nil, err
	}
	if caller == nil {
		return nil, fmt.Errorf("%w: caller", ErrNotFound)
	}
	if !isPermanentPerson(caller) || !isActiveStatus(caller.Status) {
		return []*JoinableTenant{}, nil
	}
	t, _, err := s.joinableTenant(ctx, projectID, caller)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return []*JoinableTenant{}, nil
	}
	m, err := s.memberships.GetMembership(ctx, projectID, t.ID, callerID)
	if err != nil {
		return nil, err
	}
	if m != nil && m.Status == MembershipStatusActive {
		return []*JoinableTenant{}, nil
	}
	return []*JoinableTenant{{TenantID: t.ID, Name: t.Name}}, nil
}

// JoinTenantByDomain makes callerID a member of tenantID through their
// verified email's domain: the membership is an active member one with
// source MembershipSourceDomain, so it ends when the email leaves the domain
// (migration 0047), as one auto-formation made would. tenantID must be the
// claimed tenant that has verified that domain and lets it join (see
// SetDomainJoin); every other tenant, an unknown one included, is
// ErrPermissionDenied, so the call reveals nothing about tenants the caller
// cannot join. The caller must be an active, signed-up person, and an
// unverified email is ErrEmailVerificationRequired.
//
// A join is recorded as EventTenantJoinedByDomain. Joining a tenant the
// caller already belongs to returns their membership unchanged, whatever its
// role or source, and records nothing; two joins racing for one account may
// both record, and make one membership between them.
func (s *MembershipService) JoinTenantByDomain(ctx context.Context, callerID, tenantID, ip, userAgent string) (*TenantMembership, error) {
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
	if s.domains == nil {
		return nil, ErrUnimplemented
	}
	caller, err := s.users.GetUserInProject(ctx, projectID, callerID)
	if err != nil {
		return nil, err
	}
	if caller == nil {
		return nil, fmt.Errorf("%w: caller", ErrNotFound)
	}
	if !isPermanentPerson(caller) || !isActiveStatus(caller.Status) {
		return nil, fmt.Errorf("%w: only an active, signed-up person may join a tenant", ErrPermissionDenied)
	}
	if !caller.EmailVerified {
		return nil, fmt.Errorf("%w: verify your email before joining a tenant by its domain", ErrEmailVerificationRequired)
	}
	t, d, err := s.joinableTenant(ctx, projectID, caller)
	if err != nil {
		return nil, err
	}
	if t == nil || t.ID != tenantID {
		return nil, fmt.Errorf("%w: your email's domain does not let you join this tenant", ErrPermissionDenied)
	}
	held, err := s.memberships.GetMembership(ctx, projectID, tenantID, callerID)
	if err != nil {
		return nil, err
	}
	if held != nil && held.Status == MembershipStatusActive {
		return held, nil
	}

	m, _, err := s.memberships.GrantMembership(ctx, &TenantMembership{
		ProjectID: projectID,
		TenantID:  tenantID,
		UserID:    callerID,
		Source:    MembershipSourceDomain,
		Role:      RoleMember,
	})
	if err != nil {
		return nil, err
	}
	if s.audit != nil {
		s.audit.Log(ctx, audit.EventTenantJoinedByDomain,
			audit.WithActor(callerID), audit.WithTarget(callerID),
			audit.WithIP(ip), audit.WithUserAgent(userAgent),
			audit.WithSuccess(true), audit.WithDetails(map[string]any{
				"project_id": projectID,
				"tenant_id":  tenantID,
				"domain":     d.Domain,
			}),
		)
	}
	return m, nil
}

// joinableTenant returns the tenant user's verified email's domain lets
// them join, and that domain: the claimed tenant that has verified the
// domain, while the domain allows joining. It returns nil, nil, nil when
// there is none: the email is unverified or on a public provider's domain,
// no tenant has verified the domain, the domain does not allow joining, or
// its tenant is latent or suspended.
func (s *MembershipService) joinableTenant(ctx context.Context, projectID string, user *User) (*Tenant, *Domain, error) {
	domain := verifiedEmailDomain(user)
	if domain == "" || s.config().IsPublicEmailDomain(domain) {
		return nil, nil, nil
	}
	d, err := s.domains.GetVerifiedDomain(ctx, projectID, domain)
	if err != nil || d == nil || !d.AllowJoin {
		return nil, nil, err
	}
	t, err := s.tenants.GetTenant(ctx, projectID, d.TenantID)
	if err != nil || t == nil || t.Status != TenantStatusClaimed {
		return nil, nil, err
	}
	return t, d, nil
}
