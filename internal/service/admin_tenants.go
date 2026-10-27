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
// change the tenant's current status does not allow: suspending a tenant
// that is not claimed, or restoring one that is not suspended. Mapped to
// CodeFailedPrecondition.
var ErrTenantStatusConflict = errors.New("the tenant's status does not allow this change")

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

// AdminSuspendTenant suspends a claimed tenant, recording reason in the
// audit trail. A suspended tenant keeps its domains, members and invitations,
// but its members can no longer choose it for a token, the tokens that chose
// it are refused, and its admins can no longer administer it. Suspending a
// suspended tenant changes nothing and records nothing. A latent tenant
// governs nothing, so suspending one is ErrTenantStatusConflict.
func (s *ControlPlaneAdminService) AdminSuspendTenant(ctx context.Context, secret, projectID, tenantID, reason string) (*Tenant, error) {
	return s.moveTenant(ctx, secret, projectID, tenantID, reason, TenantStatusClaimed, TenantStatusSuspended, audit.EventTenantSuspended)
}

// AdminRestoreTenant moves a suspended tenant back to claimed, recording
// reason in the audit trail. Restoring a claimed tenant changes nothing and
// records nothing; restoring a latent one is ErrTenantStatusConflict.
func (s *ControlPlaneAdminService) AdminRestoreTenant(ctx context.Context, secret, projectID, tenantID, reason string) (*Tenant, error) {
	return s.moveTenant(ctx, secret, projectID, tenantID, reason, TenantStatusSuspended, TenantStatusClaimed, audit.EventTenantRestored)
}

// moveTenant moves a tenant from one status to another for an operator and
// audits the move as event. A tenant already in to is returned unchanged, so
// an operator who retries after a lost response gets the same answer.
func (s *ControlPlaneAdminService) moveTenant(ctx context.Context, secret, projectID, tenantID, reason, from, to string, event audit.EventType) (*Tenant, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID, tenantID, err := requireTenantRef(projectID, tenantID)
	if err != nil {
		return nil, err
	}
	reason, err = normalizeText("reason", reason, operatorReasonMaxRunes)
	if err != nil {
		return nil, err
	}
	t, err := s.getTenant(ctx, projectID, tenantID)
	if err != nil {
		return nil, err
	}
	if t.Status == to {
		return t, nil
	}
	if t.Status != from {
		return nil, fmt.Errorf("%w: the tenant is %s", ErrTenantStatusConflict, t.Status)
	}
	moved, err := s.tenants.SetTenantStatus(ctx, projectID, tenantID, from, to)
	if err != nil {
		return nil, err
	}
	if moved {
		s.audit.Log(WithProjectScope(ctx, &ProjectScope{ProjectID: projectID}), event, audit.WithSuccess(true), audit.WithDetails(map[string]any{
			"project_id": projectID,
			"tenant_id":  tenantID,
			"reason":     reason,
		}))
	}
	if t, err = s.getTenant(ctx, projectID, tenantID); err != nil {
		return nil, err
	}
	if !moved && t.Status != to {
		// Another change landed between the read and the write.
		return nil, fmt.Errorf("%w: the tenant is %s", ErrTenantStatusConflict, t.Status)
	}
	return t, nil
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
