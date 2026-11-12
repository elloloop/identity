package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/elloloop/identity/pkg/audit"
)

// MaxPhoneMatchHashes bounds one MatchTenantMemberPhones batch, so one call is
// one statement probing a set of bounded size.
const MaxPhoneMatchHashes = 3000

// ErrPhoneMatchLimited is returned when a directory_reader credential has
// made its window's MatchTenantMemberPhones calls against a tenant
// (GATEWAY_RATE_LIMIT_PHONE_MATCH_PER_TENANT). Mapped to
// CodeResourceExhausted.
var ErrPhoneMatchLimited = errors.New("too many phone matches against this tenant; try again later")

// errTenantNotReadable refuses a tenant the credential's project does not
// hold, without saying whether another project holds it.
var errTenantNotReadable = fmt.Errorf("%w: the credential may not read this tenant", ErrPermissionDenied)

// phoneMatchRefusedTenant is the audit reason of a match against a tenant
// the credential's project does not hold.
const phoneMatchRefusedTenant = "tenant_not_in_project"

// WithTenantMemberPhones wires MatchTenantMemberPhones over members, letting
// each credential make perTenant calls per windowMs against each tenant.
func (s *DirectoryService) WithTenantMemberPhones(members TenantMemberPhoneMatcher, perTenant int, windowMs int64) *DirectoryService {
	s.members = members
	s.phoneMatches = newProbeBudget(windowMs, perTenant)
	return s
}

// MatchTenantMemberPhones returns the members of tenantID, in the project
// presentedKey belongs to, whose verified phone number hashes to one of
// phoneHashes (TenantMemberPhoneMatcher says who counts). The request is
// checked before the credential is read, as LookupUsers checks its batch,
// and the credential's budget for the tenant is spent before anything about
// the tenant is read. The hashes are compared and dropped: neither they nor
// the accounts matched reach the audit trail, which records the tenant and
// how many were asked for and matched.
func (s *DirectoryService) MatchTenantMemberPhones(ctx context.Context, presentedKey, tenantID string, phoneHashes [][]byte) ([]string, error) {
	if s.members == nil {
		return nil, ErrUnimplemented
	}
	publicID, secret, err := splitDirectoryKey(presentedKey)
	if err != nil {
		return nil, err
	}
	tenantID, wanted, err := phoneMatchRequest(tenantID, phoneHashes)
	if err != nil {
		return nil, err
	}
	cred, err := s.authenticate(ctx, audit.EventDirectoryPhoneMatch, publicID, secret)
	if err != nil {
		return nil, err
	}
	if !s.phoneMatches.reserve(cred.ID+"|"+tenantID, time.Now().UnixMilli()) {
		return nil, ErrPhoneMatchLimited
	}
	ctx = WithProjectScope(ctx, &ProjectScope{ProjectID: cred.ProjectID})
	matched, err := s.members.MatchTenantMemberPhones(ctx, cred.ProjectID, tenantID, wanted)
	if errors.Is(err, ErrNotFound) {
		s.audit.Log(ctx, audit.EventDirectoryPhoneMatch,
			audit.WithActor(credentialActor(cred)),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"tenant_id": tenantID, "reason": phoneMatchRefusedTenant}),
		)
		return nil, errTenantNotReadable
	}
	if err != nil {
		return nil, err
	}
	s.audit.Log(ctx, audit.EventDirectoryPhoneMatch,
		audit.WithActor(credentialActor(cred)),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"tenant_id": tenantID,
			"requested": len(wanted),
			"matched":   len(matched),
		}),
	)
	return matched, nil
}

// phoneMatchRequest validates a match request: a tenant id of a shape a
// tenant could have, and 1 to MaxPhoneMatchHashes SHA-256 digests. It returns
// the id trimmed and the digests de-duplicated, first occurrence first.
func phoneMatchRequest(tenantID string, phoneHashes [][]byte) (string, [][]byte, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return "", nil, fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	if err := checkTenantIDShape(tenantID); err != nil {
		return "", nil, err
	}
	if len(phoneHashes) == 0 {
		return "", nil, fmt.Errorf("%w: at least one phone number hash is required", ErrInvalidArgument)
	}
	if len(phoneHashes) > MaxPhoneMatchHashes {
		return "", nil, fmt.Errorf("%w: at most %d phone number hashes per match, got %d",
			ErrInvalidArgument, MaxPhoneMatchHashes, len(phoneHashes))
	}
	seen := make(map[[sha256.Size]byte]struct{}, len(phoneHashes))
	out := make([][]byte, 0, len(phoneHashes))
	for _, h := range phoneHashes {
		if len(h) != sha256.Size {
			return "", nil, fmt.Errorf("%w: each phone number hash must be a %d-byte SHA-256 digest", ErrInvalidArgument, sha256.Size)
		}
		key := [sha256.Size]byte(h)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, h)
	}
	return tenantID, out, nil
}
