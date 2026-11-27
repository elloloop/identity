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

// ManagedAddressInvalid is what CheckManagedAddresses answers, beside the
// holders ManagedSetupStore.ManagedAddressHolders reports, for an address
// whose username or form is not valid, or where the project holds no
// managed account (its own account domain, or an address its deny layer
// refuses). Nothing about such an address is looked up.
const ManagedAddressInvalid = "invalid"

// ErrManagedAddressCheckLimited refuses a CheckManagedAddresses call past
// the tenant's budget for the window
// (GATEWAY_RATE_LIMIT_MANAGED_ADDRESS_CHECK_PER_TENANT). Mapped to
// CodeResourceExhausted.
var ErrManagedAddressCheckLimited = errors.New("too many address checks for this tenant recently; try again later")

// WithManagedAddressCheckBudget caps the addresses CheckManagedAddresses
// looks up for one tenant to perTenant per windowMs, and returns the service
// for chaining. Without it the check is unimplemented.
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
// (ErrManagedAccountsNotAdmitted). An address that is not valid, or that the
// project refuses, is ManagedAddressInvalid; every other is answered by
// ManagedSetupStore.ManagedAddressHolders, which looks up only addresses on
// domains verified for tenantID (the rest are
// ManagedAddressDomainUnverified), against the request's project's accounts
// and recovery emails, so no tenant can probe another tenant's domain.
// Between 1 and maxManagedAddressChecks addresses may be named
// (ErrInvalidArgument), and each address handed to the store spends one unit
// of the tenant's budget for the window (ErrManagedAddressCheckLimited), on
// top of the per-IP cap the server applies. The answer is a point in time:
// creation decides again under its locks. Each refusal is logged as
// managed_address_check_refused with its reason, and each answer as
// managed_address_check with a count per status.
func (s *MembershipService) CheckManagedAddresses(ctx context.Context, callerID string, signIn SessionSignIn, tenantID string, queries []ManagedAddressQuery) ([]ManagedAddressCheck, error) {
	projectID, err := s.requireProject(ctx)
	tenantID = strings.TrimSpace(tenantID)
	fields := []zap.Field{zap.String("project_id", projectID), zap.String("tenant_id", tenantID), zap.String("user_id", callerID)}
	refuse := func(reason string, err error) ([]ManagedAddressCheck, error) {
		s.logger.Info("managed_address_check_refused", append(fields, zap.String("reason", reason), zap.Error(err))...)
		return nil, err
	}
	if err != nil {
		return refuse("no_project", err)
	}
	if callerID == "" {
		return refuse("unauthenticated", ErrUnauthenticated)
	}
	if s.managedSetups == nil || s.addressChecks == nil {
		return refuse("unavailable", ErrUnimplemented)
	}
	if tenantID == "" {
		return refuse("invalid_argument", fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument))
	}
	if len(queries) == 0 || len(queries) > maxManagedAddressChecks {
		return refuse("invalid_argument", fmt.Errorf("%w: name between 1 and %d addresses", ErrInvalidArgument, maxManagedAddressChecks))
	}
	if _, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID, signIn); err != nil {
		return refuse("not_permitted", err)
	}
	scope := ProjectScopeFromContext(ctx)
	if err := requireManagedAccountsAdmitted(ctx, s.cfg, s.tenants, scope, tenantID); err != nil {
		return refuse("policy", err)
	}

	out := make([]ManagedAddressCheck, len(queries))
	addresses := make([]string, len(queries))
	var lookUp []string
	for i, q := range queries {
		out[i].Query = q
		address, domain, err := managedAccountAddress(q.Username, q.Domain)
		if err != nil || refuseProjectAddress(s.cfg, scope, address, domain) != nil {
			out[i].Status = ManagedAddressInvalid
			continue
		}
		addresses[i] = address
		lookUp = append(lookUp, address)
	}
	if len(lookUp) > 0 {
		if !s.addressChecks.reserveUnits(projectID+"|"+tenantID, len(lookUp), s.nowFunc().UnixMilli()) {
			return refuse("limited", ErrManagedAddressCheckLimited)
		}
		holders, err := s.managedSetups.ManagedAddressHolders(ctx, projectID, tenantID, lookUp)
		if err != nil {
			return refuse("store_error", err)
		}
		for i, address := range addresses {
			if address != "" {
				out[i].Status = holders[address]
			}
		}
	}
	counts := map[string]int{}
	for _, c := range out {
		counts[c.Status]++
	}
	s.logger.Info("managed_address_check", append(fields,
		zap.Int("addresses", len(queries)), zap.Int("looked_up", len(lookUp)),
		zap.Int("free", counts[ManagedAddressFree]),
		zap.Int("managed_by_this_tenant", counts[ManagedAddressManagedByThis]),
		zap.Int("unavailable", counts[ManagedAddressHeldOutsideTheTenant]),
		zap.Int("domain_unverified", counts[ManagedAddressDomainUnverified]),
		zap.Int("invalid", counts[ManagedAddressInvalid]))...)
	return out, nil
}
