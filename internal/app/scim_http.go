package app

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/events"
	"github.com/elloloop/identity/pkg/scim"
)

// scimHandler mounts the inbound SCIM 2.0 server (#260) under /scim/v2/. It
// is registered only when GATEWAY_SCIM_ENABLED is true (see register); when
// disabled the routes are never added and the mux 404s, leaving the headless
// RPCs untouched. Every request must carry the configured bearer token, and
// every SCIM operation is scoped to the single configured project (projectID,
// from GATEWAY_SCIM_PROJECT_ID) — NOT the project the request's Host/auth-domain
// resolves to. The deployment-wide bearer token therefore authorizes exactly
// one project's user pool: it can never read or mutate another project's users,
// no matter which auth-domain it is presented against.
type scimHandler struct {
	repo        service.Repository
	projectID   string
	bearerToken string
	// audit records the account-lifecycle audit entries a SCIM mutation
	// produces, using the SAME audit.Logger the admin/gRPC paths write through
	// (nil ⇒ no audit, matching the best-effort contract).
	audit *audit.Logger
	// publisher emits the user.* lifecycle events a SCIM mutation produces, via
	// the SAME service.EmitUserEvent construction site the admin/gRPC paths use
	// (nil ⇒ the no-op publisher).
	publisher events.Publisher
	// tenantID stamps the lifecycle event's TenantID, mirroring the admin path
	// (Config.DefaultTenantID).
	tenantID string
	logger   *zap.Logger
}

// register wires the SCIM routes onto mux when enabled is true. The bearer
// auth wrapper runs before the SCIM provider so an unauthenticated request
// never reaches the store.
func (h *scimHandler) register(mux *http.ServeMux, enabled bool) {
	if !enabled {
		return
	}
	mux.Handle("/scim/v2/", h.authenticate(h.scimProvider()))
}

// validateSCIMProject fails boot when GATEWAY_SCIM_PROJECT_ID does not name a
// real, ACTIVE control-plane project, so a typo surfaces as a clear startup
// error rather than a 500 on the first SCIM request. lookup is the driver's
// control-plane project-by-id read; it is nil on drivers without a control
// plane (memory), where there is nothing to verify against and the check is a
// no-op — matching how the native-OAuth product→project validation and
// ensureDefaultProject skip the memory driver.
func validateSCIMProject(lookup service.NativeOAuthProjectStore, projectID string) error {
	if lookup == nil {
		return nil
	}
	proj, err := lookup.ActiveProjectByID(context.Background(), projectID)
	if err != nil {
		return fmt.Errorf("scim: verify GATEWAY_SCIM_PROJECT_ID %q: %w", projectID, err)
	}
	if proj == nil {
		return fmt.Errorf("scim: GATEWAY_SCIM_PROJECT_ID %q does not name an active project", projectID)
	}
	return nil
}

// scimProvider builds the scim.Provider over the repository bound to the single
// configured project. The binding is fixed (it does NOT read the request's
// resolved project), so the deployment-wide bearer token is constrained to that
// one project's users — the cross-project provisioning hole. The bound repo is
// built once and reused: every SCIM request shares the same project scope.
func (h *scimHandler) scimProvider() http.Handler {
	repo := service.ProjectBoundRepository(h.repo, h.projectID)
	store := &repoSCIMStore{
		repo:      repo,
		audit:     h.audit,
		publisher: h.publisher,
		projectID: h.projectID,
		tenantID:  h.tenantID,
		logger:    h.logger,
	}
	return scim.NewProvider(store).Handler()
}

// authenticate enforces the SCIM bearer token using a constant-time compare.
// A missing or wrong token is a 401 with a SCIM-shaped JSON error.
//
// On success it pins the request to the configured project by OVERWRITING any
// ProjectScope the upstream project-resolution middleware injected from the
// request's Host/auth-domain. This is the same fixed binding the store's
// repository uses, so an audit write — which resolves its project from the
// request scope — lands under GATEWAY_SCIM_PROJECT_ID and never the
// Host-resolved project. It is what keeps the deployment-wide bearer token
// constrained to exactly one project across BOTH the data write and its audit.
func (h *scimHandler) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, prefix)), []byte(h.bearerToken)) != 1 {
			w.Header().Set("Content-Type", "application/scim+json")
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"detail":"invalid or missing bearer token","status":"401"}`))
			return
		}
		ctx := service.WithProjectScope(r.Context(), &service.ProjectScope{ProjectID: h.projectID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// repoSCIMStore adapts service.Repository to scim.Store. It maps the SCIM
// User core schema onto the host User model: userName ⇒ email, externalId ⇒
// ExternalID, name ⇒ a single Name field is not stored (the host has only a
// display Name), so given/family are joined into Name and split back out on
// read for round-tripping. active is the inverse of the "deactivated" status;
// deactivation also revokes sessions + refresh tokens to take effect at once,
// matching AdminService.DeactivateUser.
//
// Every mutation records the SAME audit entry and emits the SAME user.*
// lifecycle event the equivalent admin/gRPC operation does, so a SCIM offboard
// fires the downstream-deprovisioning webhooks an admin-driven one would. The
// event is built through the one shared site (service.EmitUserEvent), not
// reimplemented here. audit/publisher are nil-tolerant (best-effort).
type repoSCIMStore struct {
	repo      service.Repository
	audit     *audit.Logger
	publisher events.Publisher
	projectID string
	tenantID  string
	logger    *zap.Logger
}

const (
	statusActive      = "active"
	statusDeactivated = "deactivated"
)

// scimAuditActor is the fixed actor recorded on a SCIM-driven audit entry: the
// SCIM surface has no user principal (its sole credential is the deployment-wide
// bearer token), so the acting identity is the SCIM system. scimAuditSource tags
// the entry's details so the audit trail distinguishes SCIM-driven lifecycle
// changes from admin/gRPC ones.
const (
	scimAuditActor  = "system:scim"
	scimAuditSource = "scim"
)

// logAudit records a best-effort SCIM audit entry, mirroring the admin path's
// audit.Logger.Log call shape. A nil logger is a no-op.
func (s *repoSCIMStore) logAudit(ctx context.Context, event audit.EventType, targetID string, details map[string]any) {
	if s.audit == nil {
		return
	}
	opts := []audit.Option{
		audit.WithActor(scimAuditActor),
		audit.WithTarget(targetID),
		audit.WithSuccess(true),
	}
	if details != nil {
		opts = append(opts, audit.WithDetails(details))
	}
	s.audit.Log(ctx, event, opts...)
}

// emitLifecycle publishes one user.* lifecycle event through the shared
// construction site. A nil publisher is a no-op.
func (s *repoSCIMStore) emitLifecycle(ctx context.Context, t events.EventType, u *service.User) {
	service.EmitUserEvent(ctx, s.publisher, s.logger, s.projectID, s.tenantID, t, u)
}

// emitUserChange records the audit entry + lifecycle event for a PUT/PATCH,
// mirroring AdminService's UNCONDITIONAL-on-target-state behavior so the
// deprovisioning signal is never lost:
//
//   - deactivating (the request set active:false) → user_deactivated audit +
//     user.deactivated event, emitted REGARDLESS of the pre-write state. This
//     is the fix for the retry-after-partial-failure hole: if the status write
//     committed but revocation failed on a prior attempt, the row is already
//     "deactivated", yet a retry — whose request still sets active:false — must
//     re-emit user.deactivated (a transition-gated check would misclassify it
//     as a no-op profile update and permanently drop the deprovision signal).
//   - reactivating (the request set active:true on a previously-deactivated
//     account) → user_reactivated audit + user.updated event.
//   - any other change → user.updated event only (matching
//     AdminService.UpdateUser, which records no audit entry).
//
// deactivating/reactivating are derived from the REQUESTED target state by the
// caller, not from the observed transition.
func (s *repoSCIMStore) emitUserChange(ctx context.Context, deactivating, reactivating bool, updated *service.User) {
	switch {
	case deactivating:
		s.logAudit(ctx, audit.EventUserDeactivated, updated.ID, map[string]any{"source": scimAuditSource})
		s.emitLifecycle(ctx, events.EventUserDeactivated, updated)
	case reactivating:
		s.logAudit(ctx, audit.EventUserReactivated, updated.ID, map[string]any{"source": scimAuditSource})
		s.emitLifecycle(ctx, events.EventUserUpdated, updated)
	default:
		s.emitLifecycle(ctx, events.EventUserUpdated, updated)
	}
}

// isActiveStatus reports whether a host status string is an active (non-
// deactivated) account, the inverse of the "deactivated" sentinel.
func isActiveStatus(status string) bool {
	return !strings.EqualFold(status, statusDeactivated)
}

func (s *repoSCIMStore) CreateUser(ctx context.Context, u scim.User) (scim.User, error) {
	status := statusActive
	if !u.Active {
		status = statusDeactivated
	}
	su := &service.User{
		Email:      u.Email,
		Name:       joinName(u.GivenName, u.FamilyName),
		ExternalID: u.ExternalID,
		Status:     status,
		Role:       "member",
	}
	id, err := s.repo.CreateUser(ctx, su)
	if err != nil {
		return scim.User{}, mapStoreErr(err)
	}
	su.ID = id

	// Mirror AdminService.InviteUser(createImmediately): a provisioned user
	// records a user_invited audit entry and emits user.created so downstream
	// SaaS can provision access.
	s.logAudit(ctx, audit.EventUserInvited, id, map[string]any{"source": scimAuditSource, "email": su.Email})
	s.emitLifecycle(ctx, events.EventUserCreated, su)

	return toSCIMUser(su), nil
}

// loadSCIMAddressable resolves the user behind a SCIM id, or ErrNotFound.
//
// Anonymous accounts are deliberately absent from this surface. They hold no
// email, and RFC 7643 §4.1.1 makes userName REQUIRED and unique — so
// exporting one yields a resource with an empty userName, and the list
// filter excludes them for that reason. Every by-id method resolves through
// here so the store answers consistently: a write that "repaired" a blank
// userName would give the account a real address while is_anonymous stayed
// true, making it email-loginable AND still matched by the retention sweep,
// which hard-deletes it with its sessions. UpgradeAnonymousAccount is the
// one path that attaches an identity and clears the flag together.
func (s *repoSCIMStore) loadSCIMAddressable(ctx context.Context, id string) (*service.User, error) {
	u, err := s.repo.GetUser(ctx, id)
	if err != nil {
		return nil, mapStoreErr(err)
	}
	if u == nil || u.IsAnonymous {
		return nil, scim.ErrNotFound
	}
	return u, nil
}

func (s *repoSCIMStore) GetUser(ctx context.Context, id string) (scim.User, error) {
	u, err := s.loadSCIMAddressable(ctx, id)
	if err != nil {
		return scim.User{}, err
	}
	return toSCIMUser(u), nil
}

func (s *repoSCIMStore) ReplaceUser(ctx context.Context, id string, u scim.User) (scim.User, error) {
	existing, err := s.loadSCIMAddressable(ctx, id)
	if err != nil {
		return scim.User{}, err
	}
	status := statusActive
	if !u.Active {
		status = statusDeactivated
	}
	fields := map[string]any{
		"email":       u.Email,
		"name":        joinName(u.GivenName, u.FamilyName),
		"external_id": u.ExternalID,
		"status":      status,
		// Stamp updated_at so meta.lastModified reflects this write.
		"updated_at": time.Now().UnixMilli(),
	}
	if err := s.repo.UpdateUser(ctx, id, fields); err != nil {
		return scim.User{}, mapStoreErr(err)
	}
	// A PUT that flips the user to inactive must take effect immediately, the
	// same as a PATCH active:false — otherwise a deprovisioned account keeps
	// its live sessions and refresh tokens until they expire.
	if !u.Active {
		if err := s.revokeUserAccess(ctx, id); err != nil {
			return scim.User{}, err
		}
	}
	updated, err := s.repo.GetUser(ctx, id)
	if err != nil {
		return scim.User{}, mapStoreErr(err)
	}
	if updated == nil {
		return scim.User{}, scim.ErrNotFound
	}
	// A PUT always carries the full target active state, so a false deactivates
	// and a true on a previously-deactivated account reactivates.
	wasActive := isActiveStatus(existing.Status)
	s.emitUserChange(ctx, !u.Active, u.Active && !wasActive, updated)
	return toSCIMUser(updated), nil
}

// revokeUserAccess kills a user's live sessions and refresh tokens so a
// deactivation takes effect at once rather than at token expiry. It mirrors
// AdminService.DeactivateUser and backs both the PATCH active:false and the
// PUT (ReplaceUser) deactivation paths.
func (s *repoSCIMStore) revokeUserAccess(ctx context.Context, id string) error {
	if err := s.repo.DeleteRefreshTokensForUser(ctx, id); err != nil {
		return mapStoreErr(err)
	}
	if err := s.repo.RevokeSessionsForUser(ctx, id, time.Now().UnixMilli()); err != nil {
		return mapStoreErr(err)
	}
	return nil
}

// PatchUser applies a SCIM PATCH partial update: only the non-nil fields of
// patch are written, mirroring the ReplaceUser attribute mapping (userName /
// email → email, given/family → display name, externalId → external_id, active
// → status). The current display name is read first so a patch of only
// givenName (or familyName) preserves the other half. Setting active false
// revokes sessions + refresh tokens, exactly like the PUT deactivation path.
func (s *repoSCIMStore) PatchUser(ctx context.Context, id string, patch scim.UserPatch) (scim.User, error) {
	existing, err := s.loadSCIMAddressable(ctx, id)
	if err != nil {
		return scim.User{}, err
	}

	fields := map[string]any{}
	// userName and email both map to the host email column; an explicit email
	// wins when both are present.
	if patch.UserName != nil {
		fields["email"] = *patch.UserName
	}
	if patch.Email != nil {
		fields["email"] = *patch.Email
	}
	if patch.ExternalID != nil {
		fields["external_id"] = *patch.ExternalID
	}
	if patch.GivenName != nil || patch.FamilyName != nil {
		given, family := splitDisplayName(existing.Name)
		if patch.GivenName != nil {
			given = *patch.GivenName
		}
		if patch.FamilyName != nil {
			family = *patch.FamilyName
		}
		fields["name"] = joinName(given, family)
	}
	deactivate := false
	if patch.Active != nil {
		if *patch.Active {
			fields["status"] = statusActive
		} else {
			fields["status"] = statusDeactivated
			deactivate = true
		}
	}
	// Stamp updated_at so meta.lastModified reflects the change.
	fields["updated_at"] = time.Now().UnixMilli()

	if err := s.repo.UpdateUser(ctx, id, fields); err != nil {
		return scim.User{}, mapStoreErr(err)
	}
	if deactivate {
		if err := s.revokeUserAccess(ctx, id); err != nil {
			return scim.User{}, err
		}
	}
	updated, err := s.repo.GetUser(ctx, id)
	if err != nil {
		return scim.User{}, mapStoreErr(err)
	}
	if updated == nil {
		return scim.User{}, scim.ErrNotFound
	}
	// The deactivation / reactivation events derive from the REQUESTED target
	// state (patch.Active / the deactivate flag above), not the observed
	// transition, so a retry after a partial-failure deactivation re-emits
	// user.deactivated rather than misclassifying the already-deactivated row as
	// a plain profile update. An absent active leaves the account state
	// unchanged (a profile-only patch).
	reactivating := patch.Active != nil && *patch.Active && !isActiveStatus(existing.Status)
	s.emitUserChange(ctx, deactivate, reactivating, updated)
	return toSCIMUser(updated), nil
}

func (s *repoSCIMStore) DeleteUser(ctx context.Context, id string) error {
	existing, err := s.loadSCIMAddressable(ctx, id)
	if err != nil {
		return err
	}
	if err := s.repo.DeleteUser(ctx, id); err != nil {
		return mapStoreErr(err)
	}

	// Mirror AdminService.DeleteUser: a hard delete records a user_deleted audit
	// entry and is a deprovisioning signal, so it emits user.deactivated for
	// downstream access removal.
	s.logAudit(ctx, audit.EventUserDeleted, id, map[string]any{"source": scimAuditSource})
	existing.Status = statusDeactivated
	s.emitLifecycle(ctx, events.EventUserDeactivated, existing)

	return nil
}

func (s *repoSCIMStore) ListUsers(ctx context.Context, f scim.ListFilter) ([]scim.User, int, error) {
	// userName maps to email; both filter the same column.
	email := f.Email
	if email == "" {
		email = f.UserName
	}
	offset := f.StartIndex - 1
	if offset < 0 {
		offset = 0
	}
	filter := service.UserListFilter{
		Email:      email,
		ExternalID: f.ExternalID,
		Offset:     offset,
		Limit:      f.Count, // the provider always supplies a clamped, positive page size
	}
	// totalResults is the count of ALL matching rows, computed in the DB
	// independently of the page window — so it reflects the whole project and
	// is never truncated to the page size or the MaxUserListLimit cap. The page
	// itself is fetched with the real offset/limit, so a client can page beyond
	// the first 500 users.
	total, err := s.repo.CountUsers(ctx, filter)
	if err != nil {
		return nil, 0, mapStoreErr(err)
	}
	// count=0 (RFC 7644 §3.4.2.4) is a totals-only request: the provider emits
	// zero resources, so skip the page SELECT entirely rather than fetch and
	// discard a window.
	if f.Count == 0 {
		return nil, total, nil
	}
	page, err := s.repo.ListUsers(ctx, filter)
	if err != nil {
		return nil, 0, mapStoreErr(err)
	}
	out := make([]scim.User, 0, len(page))
	for _, u := range page {
		out = append(out, toSCIMUser(u))
	}
	return out, total, nil
}

func toSCIMUser(u *service.User) scim.User {
	given, family := splitDisplayName(u.Name)
	return scim.User{
		ID:         u.ID,
		ExternalID: u.ExternalID,
		UserName:   u.Email,
		Email:      u.Email,
		GivenName:  given,
		FamilyName: family,
		Active:     isActiveStatus(u.Status),
		CreatedAt:  u.CreatedAt,
		UpdatedAt:  u.UpdatedAt,
	}
}

func joinName(given, family string) string {
	return strings.TrimSpace(strings.TrimSpace(given) + " " + strings.TrimSpace(family))
}

func splitDisplayName(full string) (given, family string) {
	full = strings.TrimSpace(full)
	if full == "" {
		return "", ""
	}
	if i := strings.LastIndex(full, " "); i >= 0 {
		return strings.TrimSpace(full[:i]), strings.TrimSpace(full[i+1:])
	}
	return full, ""
}

// mapStoreErr translates service-layer sentinels to the SCIM store sentinels
// the provider understands. service.ErrAlreadyExists ⇒ 409; everything else
// is surfaced as an internal error by the provider.
func mapStoreErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, service.ErrAlreadyExists):
		return scim.ErrConflict
	case errors.Is(err, service.ErrNotFound):
		return scim.ErrNotFound
	default:
		return err
	}
}
