package app

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/service"
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
	logger      *zap.Logger
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

// scimProvider builds the scim.Provider over the repository bound to the single
// configured project. The binding is fixed (it does NOT read the request's
// resolved project), so the deployment-wide bearer token is constrained to that
// one project's users — the cross-project provisioning hole. The bound repo is
// built once and reused: every SCIM request shares the same project scope.
func (h *scimHandler) scimProvider() http.Handler {
	repo := service.ProjectBoundRepository(h.repo, h.projectID)
	store := &repoSCIMStore{repo: repo}
	return scim.NewProvider(store).Handler()
}

// authenticate enforces the SCIM bearer token using a constant-time compare.
// A missing or wrong token is a 401 with a SCIM-shaped JSON error.
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
		next.ServeHTTP(w, r)
	})
}

// repoSCIMStore adapts service.Repository to scim.Store. It maps the SCIM
// User core schema onto the host User model: userName ⇒ email, externalId ⇒
// ExternalID, name ⇒ a single Name field is not stored (the host has only a
// display Name), so given/family are joined into Name and split back out on
// read for round-tripping. active is the inverse of the "deactivated" status;
// deactivation also revokes sessions + refresh tokens to take effect at once,
// matching AdminService.DeactivateUser.
type repoSCIMStore struct {
	repo service.Repository
}

const (
	statusActive      = "active"
	statusDeactivated = "deactivated"
)

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
	return toSCIMUser(su), nil
}

func (s *repoSCIMStore) GetUser(ctx context.Context, id string) (scim.User, error) {
	u, err := s.repo.GetUser(ctx, id)
	if err != nil {
		return scim.User{}, mapStoreErr(err)
	}
	if u == nil {
		return scim.User{}, scim.ErrNotFound
	}
	return toSCIMUser(u), nil
}

func (s *repoSCIMStore) ReplaceUser(ctx context.Context, id string, u scim.User) (scim.User, error) {
	existing, err := s.repo.GetUser(ctx, id)
	if err != nil {
		return scim.User{}, mapStoreErr(err)
	}
	if existing == nil {
		return scim.User{}, scim.ErrNotFound
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
	return s.GetUser(ctx, id)
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

func (s *repoSCIMStore) SetActive(ctx context.Context, id string, active bool) (scim.User, error) {
	existing, err := s.repo.GetUser(ctx, id)
	if err != nil {
		return scim.User{}, mapStoreErr(err)
	}
	if existing == nil {
		return scim.User{}, scim.ErrNotFound
	}
	status := statusActive
	if !active {
		status = statusDeactivated
	}
	if err := s.repo.UpdateUser(ctx, id, map[string]any{"status": status}); err != nil {
		return scim.User{}, mapStoreErr(err)
	}
	if !active {
		// Kill sessions + refresh tokens so the suspension takes effect
		// immediately, not at token expiry (see revokeUserAccess).
		if err := s.revokeUserAccess(ctx, id); err != nil {
			return scim.User{}, err
		}
	}
	return s.GetUser(ctx, id)
}

func (s *repoSCIMStore) DeleteUser(ctx context.Context, id string) error {
	existing, err := s.repo.GetUser(ctx, id)
	if err != nil {
		return mapStoreErr(err)
	}
	if existing == nil {
		return scim.ErrNotFound
	}
	if err := s.repo.DeleteUser(ctx, id); err != nil {
		return mapStoreErr(err)
	}
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
		Active:     !strings.EqualFold(u.Status, statusDeactivated),
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
