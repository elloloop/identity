package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// maxManagedAddressChecks bounds the addresses one CheckManagedAddresses
// call may name.
const maxManagedAddressChecks = 100

// What CheckManagedAddresses found for an address, beside the holders
// ManagedSetupStore.ManagedAddressHolders reports (ManagedAddressFree,
// ManagedAddressManagedByThis, ManagedAddressHeldOutsideTheTenant).
const (
	// ManagedAddressDomainUnverified: the domain is not verified for the
	// tenant, so nothing about the address was looked up.
	ManagedAddressDomainUnverified = "domain_unverified"
	// ManagedAddressInvalid: the username or the address is not valid, or
	// the project holds no managed account there (its own account domain,
	// or an address its deny layer refuses).
	ManagedAddressInvalid = "invalid"
)

// ErrManagedAddressCheckLimited refuses a CheckManagedAddresses call past
// the tenant's budget for the window
// (GATEWAY_RATE_LIMIT_MANAGED_ADDRESS_CHECK_PER_TENANT). Mapped to
// CodeResourceExhausted.
var ErrManagedAddressCheckLimited = errors.New("too many address checks for this tenant recently; try again later")

// WithManagedAddressCheckBudget caps the CheckManagedAddresses calls made
// against one tenant to perTenant per windowMs, and returns the service for
// chaining. Without it the check is unimplemented.
func (s *MembershipService) WithManagedAddressCheckBudget(perTenant int, windowMs int64) *MembershipService {
	s.addressChecks = newProbeBudget(windowMs, perTenant)
	return s
}

// ManagedAddressQuery is one address CheckManagedAddresses is asked about.
type ManagedAddressQuery struct {
	Username string
	Domain   string
}

// ManagedAddressCheck is what CheckManagedAddresses found for Query.
type ManagedAddressCheck struct {
	Query  ManagedAddressQuery
	Status string
}

// CheckManagedAddresses says, for each of queries in order, whether a
// managed account of tenantID could be created there now, writing nothing.
// callerID must be an active owner or admin of a tenant that may be
// governed. The server, project and tenant must admit managed accounts
// (ErrManagedAccountsNotAdmitted). An address on a domain not verified for
// tenantID is ManagedAddressDomainUnverified and nothing about it is looked
// up, so no tenant can probe addresses on another tenant's domain; the rest
// are answered as CreateTenantInvitation would decide them. Between 1 and
// maxManagedAddressChecks addresses may be named (ErrInvalidArgument). The
// answer is a point in time: creation decides again under its locks.
func (s *MembershipService) CheckManagedAddresses(ctx context.Context, callerID, tenantID string, queries []ManagedAddressQuery) ([]ManagedAddressCheck, error) {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return nil, err
	}
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	if s.managedSetups == nil || s.domains == nil || s.addressChecks == nil {
		return nil, ErrUnimplemented
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	if len(queries) == 0 || len(queries) > maxManagedAddressChecks {
		return nil, fmt.Errorf("%w: name between 1 and %d addresses", ErrInvalidArgument, maxManagedAddressChecks)
	}
	if _, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID); err != nil {
		return nil, err
	}
	scope := ProjectScopeFromContext(ctx)
	if err := requireManagedAccountsAdmitted(ctx, s.cfg, s.tenants, scope, tenantID); err != nil {
		return nil, err
	}
	if !s.addressChecks.reserve(projectID+"|"+tenantID, s.nowFunc().UnixMilli()) {
		s.logger.Info("managed_address_check_limited",
			zap.String("project_id", projectID), zap.String("tenant_id", tenantID), zap.String("user_id", callerID))
		return nil, ErrManagedAddressCheckLimited
	}
	verified, err := s.verifiedDomainsOf(ctx, projectID, tenantID)
	if err != nil {
		return nil, err
	}

	out := make([]ManagedAddressCheck, len(queries))
	addresses := make([]string, len(queries))
	var lookUp []string
	for i, q := range queries {
		out[i].Query = q
		address, domain, err := managedAccountAddress(q.Username, q.Domain)
		switch {
		case err != nil:
			out[i].Status = ManagedAddressInvalid
		case !verified[domain]:
			out[i].Status = ManagedAddressDomainUnverified
		case refuseProjectAddress(s.cfg, scope, address, domain) != nil:
			out[i].Status = ManagedAddressInvalid
		default:
			addresses[i] = address
			lookUp = append(lookUp, address)
		}
	}
	if len(lookUp) > 0 {
		holders, err := s.managedSetups.ManagedAddressHolders(ctx, projectID, tenantID, lookUp)
		if err != nil {
			return nil, err
		}
		for i, address := range addresses {
			if address != "" {
				out[i].Status = holders[address]
			}
		}
	}
	s.logger.Info("managed_address_check",
		zap.String("project_id", projectID), zap.String("tenant_id", tenantID),
		zap.String("user_id", callerID), zap.Int("addresses", len(queries)), zap.Int("looked_up", len(lookUp)))
	return out, nil
}

// verifiedDomainsOf is the set of domains verified for tenantID.
func (s *MembershipService) verifiedDomainsOf(ctx context.Context, projectID, tenantID string) (map[string]bool, error) {
	domains, err := s.domains.ListDomainsByTenant(ctx, projectID, tenantID)
	if err != nil {
		return nil, err
	}
	verified := map[string]bool{}
	for _, d := range domains {
		if d.Status == DomainStatusVerified {
			verified[strings.ToLower(d.Domain)] = true
		}
	}
	return verified, nil
}
