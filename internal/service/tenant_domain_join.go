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
// auto-formation always did (TenantAutoFormStore). Auto-formation runs only
// at signup, so this is for the people on the domain it left outside the
// tenant: those who signed up into the latent tenant auto-formation made
// for the domain before another tenant verified it, those whose email moved
// onto the domain after signup, and those whose domain membership ended
// when their email left the domain, since moving back does not rejoin.

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
// unchanged and records nothing, so a retry is safe. A domain removed while
// the call runs is ErrNotFound.
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
	updated, changed, err := s.domains.SetDomainAllowJoin(ctx, projectID, d.ID, allowJoin)
	if err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, fmt.Errorf("%w: domain", ErrNotFound)
	}
	if changed && s.audit != nil {
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
	if !isActivePerson(caller) {
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
// Joining a tenant the caller already belongs to, as ListMyTenants counts
// membership, returns their membership unchanged, whatever its role or
// source, and records nothing. That is checked before whether the domain
// lets them join, so it holds after joining is turned off too, and a retry
// gets the same answer. A join is recorded as EventTenantJoinedByDomain,
// once: of two joins racing for one account, one makes the membership and
// records it, and the other returns it.
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
	if !isActivePerson(caller) {
		return nil, fmt.Errorf("%w: only an active, signed-up person may join a tenant", ErrPermissionDenied)
	}
	held, err := s.heldMembership(ctx, projectID, tenantID, caller)
	if err != nil {
		return nil, err
	}
	if held != nil {
		return held, nil
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

	m, changed, err := s.memberships.GrantMembership(ctx, &TenantMembership{
		ProjectID: projectID,
		TenantID:  tenantID,
		UserID:    callerID,
		Source:    MembershipSourceDomain,
		Role:      RoleMember,
	})
	if err != nil {
		return nil, err
	}
	if changed && s.audit != nil {
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

// heldMembership returns the membership user holds in tenantID when it is
// one ListMyTenants counts (an active membership of a claimed tenant, one
// from the email's domain only while that domain is verified on the
// tenant), and nil otherwise.
func (s *MembershipService) heldMembership(ctx context.Context, projectID, tenantID string, user *User) (*TenantMembership, error) {
	active, err := s.memberships.GetActiveTenantForUser(ctx, projectID, tenantID, user.ID, verifiedEmailDomain(user))
	if err != nil || active == nil {
		return nil, err
	}
	return s.memberships.GetMembership(ctx, projectID, tenantID, user.ID)
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
