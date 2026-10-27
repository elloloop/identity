package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/elloloop/identity/pkg/audit"
)

// Paging bounds for AdminListTenants. A project may hold a tenant for every
// company email domain that ever signed up, so the listing is always paged.
const (
	defaultTenantPageSize = 50
	maxTenantPageSize     = 200
)

// operatorReasonMaxRunes bounds the reason an operator gives for a change to
// a tenant, which the audit trail keeps.
const operatorReasonMaxRunes = 500

// ErrTenantStatusConflict is returned when an operator asks for a status
// change the tenant cannot make: it is in neither the status the change
// starts from nor the one it ends in (today, a latent tenant), or it is a
// suspended tenant with no creator and no owner or admin, which a restore
// would make selectable with no one answering for it. A tenant already in the
// status asked for is not a conflict: it is returned unchanged. Mapped to
// CodeFailedPrecondition.
var ErrTenantStatusConflict = errors.New("the tenant's status does not allow this change")

// ErrTenantStatusChanged is returned when another change to the tenant's
// status landed between an operator call's read and its compare-and-set,
// leaving the tenant in neither status. Retrying reads the new status.
// Mapped to CodeAborted.
var ErrTenantStatusChanged = errors.New("the tenant's status changed during the call; retry")

// TenantPage is one page of AdminListTenants: the tenants, newest first, and
// the cursor for the next page, empty on the last.
type TenantPage struct {
	Tenants    []*Tenant
	NextCursor string
}

// AdminGetTenant returns a tenant's own record. A tenant the project does not
// hold is ErrNotFound.
func (s *ControlPlaneAdminService) AdminGetTenant(ctx context.Context, secret, projectID, tenantID string) (*Tenant, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID, tenantID, err := requireTenantRef(projectID, tenantID)
	if err != nil {
		return nil, err
	}
	return s.getTenant(ctx, projectID, tenantID)
}

// AdminListTenants returns one page of a project's tenants, newest first,
// whatever their status. limit defaults to 50 and is capped at 200; cursor is
// the NextCursor of the previous page, and one that does not decode is
// ErrInvalidArgument. A cursor is a position, not a grant: it is not bound to
// the project it came from, and the listing is always of projectID's tenants
// alone. A project with no tenants, or one that does not exist, is an empty
// page.
func (s *ControlPlaneAdminService) AdminListTenants(ctx context.Context, secret, projectID string, limit int32, cursor string) (*TenantPage, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	var after *TenantPosition
	if cursor != "" {
		p, err := decodeTenantCursor(cursor)
		if err != nil {
			return nil, err
		}
		after = &p
	}
	size := tenantPageSize(limit)
	tenants, err := s.tenants.ListTenants(ctx, TenantListQuery{ProjectID: projectID, After: after, Limit: size + 1})
	if err != nil {
		return nil, err
	}
	if len(tenants) <= size {
		return &TenantPage{Tenants: tenants}, nil
	}
	tenants = tenants[:size]
	last := tenants[size-1]
	return &TenantPage{
		Tenants:    tenants,
		NextCursor: encodeTenantCursor(TenantPosition{CreatedAtMs: last.CreatedAtMs, ID: last.ID}),
	}, nil
}

// AdminSuspendTenant suspends a claimed tenant, recording reason, and the
// operator's ip and ua, in the audit trail. A suspended tenant keeps its
// domains, members and invitations, but its members can no longer choose it
// for a token, the tokens that chose it are refused within the tenant-status
// cache TTL, and its admins can no longer administer it. Suspending a
// suspended tenant changes nothing and records nothing. A latent tenant
// governs nothing, so suspending one is ErrTenantStatusConflict.
func (s *ControlPlaneAdminService) AdminSuspendTenant(ctx context.Context, secret, projectID, tenantID, reason, ip, ua string) (*Tenant, error) {
	return s.moveTenant(ctx, secret, tenantMove{
		projectID: projectID, tenantID: tenantID, reason: reason, ip: ip, ua: ua,
		from: TenantStatusClaimed, to: TenantStatusSuspended, event: audit.EventTenantSuspended,
	})
}

// AdminRestoreTenant moves a suspended tenant back to claimed, recording
// reason, and the operator's ip and ua, in the audit trail. Restoring a
// claimed tenant changes nothing and records nothing; restoring a latent one
// is ErrTenantStatusConflict, and so is restoring a suspended tenant that
// shows no sign of ever having been claimed (wasClaimed).
func (s *ControlPlaneAdminService) AdminRestoreTenant(ctx context.Context, secret, projectID, tenantID, reason, ip, ua string) (*Tenant, error) {
	return s.moveTenant(ctx, secret, tenantMove{
		projectID: projectID, tenantID: tenantID, reason: reason, ip: ip, ua: ua,
		from: TenantStatusSuspended, to: TenantStatusClaimed, event: audit.EventTenantRestored,
		admit: s.requireAnswerable,
	})
}

// tenantMove is one operator change of a tenant's status: the tenant, why,
// who asked from where, the move, and the event that records it. admit, when
// set, may refuse a tenant in from before it is moved.
type tenantMove struct {
	projectID, tenantID, reason, ip, ua string
	from, to                            string
	event                               audit.EventType
	admit                               func(context.Context, *Tenant) error
}

// moveTenant moves a tenant from one status to another for an operator and
// audits the move. A tenant already in m.to is returned unchanged, so an
// operator who retries after a lost response gets the same answer; only the
// call that changes the status records its reason.
func (s *ControlPlaneAdminService) moveTenant(ctx context.Context, secret string, m tenantMove) (*Tenant, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID, tenantID, err := requireTenantRef(m.projectID, m.tenantID)
	if err != nil {
		return nil, err
	}
	reason, err := normalizeText("reason", m.reason, operatorReasonMaxRunes)
	if err != nil {
		return nil, err
	}
	t, err := s.getTenant(ctx, projectID, tenantID)
	if err != nil {
		return nil, err
	}
	if t.Status == m.to {
		return t, nil
	}
	if t.Status != m.from {
		return nil, fmt.Errorf("%w: the tenant is %s", ErrTenantStatusConflict, t.Status)
	}
	if m.admit != nil {
		if err := m.admit(ctx, t); err != nil {
			return nil, err
		}
	}
	moved, err := s.tenants.SetTenantStatus(ctx, projectID, tenantID, m.from, m.to)
	if err != nil {
		return nil, err
	}
	if moved {
		s.audit.Log(WithProjectScope(ctx, &ProjectScope{ProjectID: projectID}), m.event,
			audit.WithSuccess(true), audit.WithIP(m.ip), audit.WithUserAgent(m.ua),
			audit.WithDetails(map[string]any{
				"project_id": projectID,
				"tenant_id":  tenantID,
				"reason":     reason,
			}))
	}
	if t, err = s.getTenant(ctx, projectID, tenantID); err != nil {
		return nil, err
	}
	if !moved && t.Status != m.to {
		return nil, fmt.Errorf("%w: the tenant is now %s", ErrTenantStatusChanged, t.Status)
	}
	return t, nil
}

// requireAnswerable refuses to restore a suspended tenant that no one answers
// for: no person created it, and it has no owner or admin. A latent tenant
// suspended in SQL before the operator RPCs looks like that, and restoring it
// would make claimed a tenant whose domain no one verified, closing it to
// the first verifier; so does a tenant an operator made with
// AdminCreateTenant and never gave an admin, and a tenant whose owners and
// admins were all deleted. The operator appoints an owner with
// AdminRecoverTenantOwnership, which is audited, or adds an admin with
// AdminAddTenantAdmin, and restores the tenant then. A tenant claimed by a
// domain's verification has the owner or admin who verified it.
func (s *ControlPlaneAdminService) requireAnswerable(ctx context.Context, t *Tenant) error {
	if t.CreatedBy != "" {
		return nil
	}
	members, err := s.memberships.ListMembershipsForTenant(ctx, t.ProjectID, t.ID)
	if err != nil {
		return err
	}
	for _, m := range members {
		if m.Role == RoleOwner || m.Role == RoleAdmin {
			return nil
		}
	}
	return fmt.Errorf("%w: the tenant has no creator, owner or admin; appoint an owner with AdminRecoverTenantOwnership before restoring it", ErrTenantStatusConflict)
}

// getTenant reads a tenant the operator named, refusing one the project does
// not hold with ErrNotFound.
func (s *ControlPlaneAdminService) getTenant(ctx context.Context, projectID, tenantID string) (*Tenant, error) {
	t, err := s.tenants.GetTenant(ctx, projectID, tenantID)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, fmt.Errorf("%w: tenant", ErrNotFound)
	}
	return t, nil
}

// requireTenantRef trims an operator's project and tenant ids and refuses
// either blank.
func requireTenantRef(projectID, tenantID string) (string, string, error) {
	projectID = strings.TrimSpace(projectID)
	tenantID = strings.TrimSpace(tenantID)
	if projectID == "" {
		return "", "", fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	if tenantID == "" {
		return "", "", fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	return projectID, tenantID, nil
}

// tenantPageSize is the page AdminListTenants serves for a requested limit:
// the default for zero or less, the maximum past it.
func tenantPageSize(limit int32) int {
	switch {
	case limit <= 0:
		return defaultTenantPageSize
	case limit > maxTenantPageSize:
		return maxTenantPageSize
	default:
		return int(limit)
	}
}

// encodeTenantCursor makes the opaque cursor that resumes a listing after p.
func encodeTenantCursor(p TenantPosition) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(p.CreatedAtMs, 10) + "." + p.ID))
}

// decodeTenantCursor reads a cursor encodeTenantCursor made, and refuses one
// it could not have made with ErrInvalidArgument: a listing that silently
// restarted on a bad cursor would page forever. A tenant id is valid UTF-8
// with no NUL, which Postgres would refuse as a query argument, so an id
// that is not is refused here rather than failing as an internal error.
func decodeTenantCursor(cursor string) (TenantPosition, error) {
	malformed := fmt.Errorf("%w: malformed cursor", ErrInvalidArgument)
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return TenantPosition{}, malformed
	}
	ms, id, ok := strings.Cut(string(raw), ".")
	createdAtMs, err := strconv.ParseInt(ms, 10, 64)
	if !ok || err != nil || createdAtMs < 0 || id == "" ||
		!utf8.ValidString(id) || strings.ContainsRune(id, 0) {
		return TenantPosition{}, malformed
	}
	return TenantPosition{CreatedAtMs: createdAtMs, ID: id}, nil
}
