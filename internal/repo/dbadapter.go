package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/service"
)

const entDBApplyWaitTimeoutMs int32 = 5000

// NewDBAdapter exposes the SDK's raw transport as service.DB. The
// service.DB contract is already the transport contract: tenant id,
// actor, numeric type ids, field-id-keyed filters, and raw
// entdb.Operation batches. Going through the SDK's typed Query/Get
// helpers here loses node ids on query results, so the adapter must
// delegate to the raw transport instead of translating through typed
// witnesses.
//
// tenant-shard-db v1.14.0 (#528) exposes *DbClient.Transport() as a
// public read-only accessor, so the adapter reaches through it
// directly. Before v1.14.0 identity used an unsafe-reflection helper
// to do the same — that helper is gone.
func NewDBAdapter(client *sdk.DbClient) (service.DB, error) {
	if client == nil {
		return nil, errors.New("entdb: nil db client")
	}
	return &dbAdapter{transport: client.Transport()}, nil
}

// NewTenantAdmin wraps an EntDB SDK client as a service.TenantAdmin
// — the narrow surface OrganizationSignup needs to provision a new
// tenant + its first admin user. Idempotent on ALREADY_EXISTS
// (necessary when the same signup is retried after a partial failure).
//
// Uses the raw Transport calls (which the SDK's Admin handle is a
// thin shim over) so the adapter stays testable with a fake Transport.
func NewTenantAdmin(client *sdk.DbClient) (service.TenantAdmin, error) {
	if client == nil {
		return nil, errors.New("entdb: nil db client")
	}
	return &tenantAdmin{transport: client.Transport()}, nil
}

// PostgresTenantAdmin is a service.TenantAdmin implementation for the
// postgres driver. Postgres has no cross-tenant global registry — the
// "tenant" is just a value in the `tenant_id` column — so the operations
// are intentionally lightweight: CreateTenant tracks the registered
// tenant ids in memory (the slug uniqueness check is enforced by the
// per-tenant Repository's CreateOrganization unique index); the
// promote / remove calls are no-ops because postgres has no storage-
// layer membership concept.
type PostgresTenantAdmin struct {
	mu      sync.Mutex
	tenants map[string]struct{}
}

// NewPostgresTenantAdmin returns a TenantAdmin suitable for the
// postgres driver. Tenant uniqueness is enforced by both the in-memory
// set here AND the organizations.(tenant_id, slug) unique index.
func NewPostgresTenantAdmin() *PostgresTenantAdmin {
	return &PostgresTenantAdmin{tenants: map[string]struct{}{}}
}

func (a *PostgresTenantAdmin) CreateTenant(_ context.Context, tenantID, _ string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.tenants[tenantID]; ok {
		return service.ErrAlreadyExists
	}
	a.tenants[tenantID] = struct{}{}
	return nil
}

func (a *PostgresTenantAdmin) PromoteTenantMember(_ context.Context, _, _, _ string) error {
	return nil
}

func (a *PostgresTenantAdmin) RemoveTenantMember(_ context.Context, _, _ string) error {
	return nil
}

type tenantAdmin struct {
	transport sdk.Transport
}

const tenantAdminActor = "system:admin"

func (a *tenantAdmin) CreateTenant(ctx context.Context, tenantID, displayName string) error {
	if _, err := a.transport.CreateTenant(ctx, tenantAdminActor, tenantID, displayName); err != nil {
		if dbAdapterIsAlreadyExists(err) {
			return service.ErrAlreadyExists
		}
		return err
	}
	return nil
}

func (a *tenantAdmin) PromoteTenantMember(ctx context.Context, tenantID, userID, role string) error {
	if err := a.transport.ChangeMemberRole(ctx, tenantAdminActor, tenantID, userID, role); err != nil {
		// Tolerate "already at this role" idempotently. The upstream
		// signal is *sdk.EntDBError with code ALREADY_EXISTS (handled
		// by dbAdapterIsAlreadyExists) or a FailedPrecondition that
		// also stringifies with the role name when the server thinks
		// the member is already in that role; match the second
		// variant on the status message text.
		if dbAdapterIsAlreadyExists(err) {
			return nil
		}
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "already") && strings.Contains(msg, role) {
			return nil
		}
		return err
	}
	return nil
}

func (a *tenantAdmin) RemoveTenantMember(ctx context.Context, tenantID, userID string) error {
	if err := a.transport.RemoveTenantMember(ctx, tenantAdminActor, tenantID, userID); err != nil {
		// Tolerate "member not present" on rollback so re-runs stay
		// idempotent. tenant-shard-db v1.14.0 surfaces this as the
		// typed *sdk.NotFoundError (Code == "NOT_FOUND"); some legacy
		// paths still come through as a FailedPrecondition with a
		// status message containing "no membership", so match that
		// too.
		var nf *sdk.NotFoundError
		if errors.As(err, &nf) {
			return nil
		}
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "no membership") {
			return nil
		}
		return err
	}
	return nil
}

type dbAdapter struct {
	transport sdk.Transport
}

func (a *dbAdapter) GetNode(ctx context.Context, tenantID, actor string, typeID int, nodeID string) (*sdk.Node, error) {
	return a.transport.GetNode(ctx, tenantID, actor, typeID, nodeID)
}

func (a *dbAdapter) QueryNodes(ctx context.Context, tenantID, actor string, typeID int, filter map[string]any) ([]*sdk.Node, error) {
	// limit=0: auto-follow the keyset cursor to the complete set
	// (tenant-shard-db v1.24.0+, ADR-029). Without it the SDK truncates
	// at the server's per-page cap.
	return a.transport.QueryNodes(ctx, tenantID, actor, typeID, filter, 0)
}

func (a *dbAdapter) ExecuteAtomic(ctx context.Context, tenantID, actor string, ops []sdk.Operation) (*sdk.CommitResult, error) {
	// The EntDB SDK Transport accepts an idempotencyKey we don't use
	// (no service flow needs cross-request retry safety today); pass
	// "" to keep the call shape but not expose it through our interface.
	result, err := a.transport.ExecuteAtomic(ctx, tenantID, actor, "", ops)
	if err != nil {
		return nil, err
	}
	if err := a.waitForApplied(ctx, tenantID, actor, result, len(ops)); err != nil {
		return nil, err
	}
	return result, nil
}

func (a *dbAdapter) GetEdgesFrom(ctx context.Context, tenantID, actor, fromNodeID string, edgeTypeID int) ([]*sdk.Edge, error) {
	return a.transport.GetEdgesFrom(ctx, tenantID, actor, fromNodeID, edgeTypeID)
}

func (a *dbAdapter) GetEdgesTo(ctx context.Context, tenantID, actor, toNodeID string, edgeTypeID int) ([]*sdk.Edge, error) {
	return a.transport.GetEdgesTo(ctx, tenantID, actor, toNodeID, edgeTypeID)
}

func (a *dbAdapter) SearchNodes(ctx context.Context, tenantID, actor string, typeID int, query string) ([]*sdk.Node, error) {
	return a.transport.SearchNodes(ctx, tenantID, actor, typeID, query)
}

// RegisterUserInTenant registers userID globally and adds it as a
// tenant member with the given role. v1.12+ enforces that every actor
// be a registered user and a tenant member before issuing tenant-
// scoped writes of their own; the typed entRepository.CreateUser path
// has its own wiring for this, but the raw service.DB path (admin
// invites, system bookkeeping) needs the same registration step on
// any user it creates outside the typed repo.
//
// Uses the raw Transport.CreateUser / Transport.AddTenantMember
// calls directly rather than going through *sdk.DbClient.Admin().
// The Admin handle is a thin shim over those same Transport methods
// and going through the transport keeps the adapter testable with a
// fake Transport.
func (a *dbAdapter) RegisterUserInTenant(ctx context.Context, tenantID, userID, email, name, role string) error {
	if userID == "" {
		return errors.New("entdb: RegisterUserInTenant: empty user id")
	}
	// The global registry's Admin.CreateUser rejects empty name with
	// VALIDATION_ERROR; default to the local-part of the email so
	// flows that don't carry a display name still register cleanly.
	if name == "" {
		name = userID
		if i := strings.IndexByte(email, '@'); email != "" && i > 0 {
			name = email[:i]
		}
	}
	const adminActor = "system:admin"
	if _, err := a.transport.CreateUser(ctx, adminActor, userID, email, name); err != nil && !dbAdapterIsAlreadyExists(err) {
		return fmt.Errorf("entdb: register user %q: %w", userID, err)
	}
	if err := a.transport.AddTenantMember(ctx, adminActor, tenantID, userID, role); err != nil && !dbAdapterIsAlreadyExists(err) {
		return fmt.Errorf("entdb: add tenant member %q: %w", userID, err)
	}
	return nil
}

// dbAdapterIsAlreadyExists reports whether err is the upstream's
// ALREADY_EXISTS signal. tenant-shard-db v1.14.0 wraps the gRPC
// status into the typed *EntDBError (Code == "ALREADY_EXISTS") and
// the typed *UniqueConstraintError (which embeds EntDBError with the
// "UNIQUE_CONSTRAINT" code but is still produced for the same
// AlreadyExists status). Match on both so the duplicate-tolerant
// idempotency guard works for either path.
func dbAdapterIsAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	var entErr *sdk.EntDBError
	if errors.As(err, &entErr) {
		if entErr.Code == "ALREADY_EXISTS" {
			return true
		}
	}
	var uce *sdk.UniqueConstraintError
	return errors.As(err, &uce)
}

func (a *dbAdapter) waitForApplied(ctx context.Context, tenantID, actor string, result *sdk.CommitResult, opCount int) error {
	if result == nil {
		return errors.New("entdb: nil commit result")
	}
	if !result.Success {
		if result.Error != "" {
			return fmt.Errorf("entdb: commit failed: %s", result.Error)
		}
		return errors.New("entdb: commit failed")
	}
	if opCount == 0 || result.Applied {
		return nil
	}
	if result.Receipt == nil || result.Receipt.StreamPosition == "" {
		return errors.New("entdb: commit returned before apply without stream position")
	}
	reached, current, err := a.transport.WaitForOffset(
		ctx,
		tenantID,
		actor,
		result.Receipt.StreamPosition,
		entDBApplyWaitTimeoutMs,
	)
	if err != nil {
		return fmt.Errorf("entdb: wait for commit apply: %w", err)
	}
	if !reached {
		return fmt.Errorf(
			"entdb: commit apply timeout waiting for %q; current offset %q",
			result.Receipt.StreamPosition,
			current,
		)
	}
	result.Applied = true
	return nil
}
