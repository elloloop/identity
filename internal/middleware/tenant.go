package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

// TenantResolver resolves the per-request tenant in mode=multi and
// threads it through the request context so the service layer scopes
// every operation to the caller's tenant instead of a hardcoded
// default. It is wired only in mode=multi; mode=single never installs it
// (the tenant is always DefaultTenantID — a clean constant path).
//
// Resolution sources and precedence are config-driven (see
// config.TenantResolutionSourceList): "host" derives the tenant slug
// from a subdomain of GATEWAY_TENANT_HOST_BASE_DOMAIN; "jwt" reads the
// access token's "tenant" claim (surfaced by the auth middleware via
// AuthenticatedTenantHeader). When both sources are configured the first
// non-empty one wins and the other is cross-checked for a conflict —
// a host that disagrees with a JWT's tenant is a cross-tenant token
// reuse and is rejected.
//
// Membership: for an authenticated request the resolved tenant must
// contain the caller as an organisation member (slice 1's
// ListOrganizationsForUser); a mismatch yields PermissionDenied.
type TenantResolver struct {
	sources       []string
	baseDomain    string
	repoForTenant service.RepositoryForTenant
	logger        *zap.Logger
}

// NewTenantResolver builds the middleware from the multi-mode config and
// the per-tenant repository factory. repoForTenant must be non-nil in
// mode=multi (app.New enforces this at boot). The returned function is a
// no-op pass-through when the deployment is not in mode=multi, so the
// single-tenant request path is untouched.
func NewTenantResolver(cfg *config.Config, repoForTenant service.RepositoryForTenant, logger *zap.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	if cfg == nil || !cfg.IsMultiMode() {
		return func(next http.Handler) http.Handler { return next }
	}
	tr := &TenantResolver{
		sources:       cfg.TenantResolutionSourceList(),
		baseDomain:    strings.ToLower(strings.TrimSpace(cfg.TenantHostBaseDomain)),
		repoForTenant: repoForTenant,
		logger:        logger,
	}
	return tr.middleware
}

func (tr *TenantResolver) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// OrganizationSignup provisions a brand-new tenant; there is no
		// tenant to resolve yet and the service uses its own per-tenant
		// repository factory. Let it through with no scope.
		if isTenantProvisioningPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		hostTenant := ""
		if tr.usesHost() {
			hostTenant = tr.tenantFromHost(r)
		}
		jwtTenant := ""
		if tr.usesJWT() {
			jwtTenant = r.Header.Get(AuthenticatedTenantHeader)
		}

		resolved, ok := tr.pick(hostTenant, jwtTenant)
		if !ok {
			// host and jwt disagree — a cross-tenant token reuse.
			writeConnectError(w, http.StatusForbidden, "permission_denied",
				"tenant mismatch between host and token")
			return
		}

		userID := r.Header.Get(AuthenticatedUserIDHeader)

		// Unauthenticated paths (login, password reset, …) precede
		// membership: the caller is proving identity, not asserting it.
		// They still get a tenant scope when one resolved (login must
		// look the user up in the host's tenant), but skip the member
		// check.
		if userID == "" {
			if resolved == "" {
				// Authenticated paths require a tenant; unauthenticated
				// ones tolerate its absence (e.g. a JWKS fetch on the
				// apex domain). Pass through with no scope.
				next.ServeHTTP(w, r)
				return
			}
			tr.serveWithScope(w, r, next, resolved)
			return
		}

		// Authenticated request: a tenant must resolve.
		if resolved == "" {
			writeConnectError(w, http.StatusForbidden, "permission_denied",
				"unable to resolve tenant for request")
			return
		}

		repo := tr.repoForTenant(resolved)
		if repo == nil {
			tr.logger.Error("tenant_repo_factory_nil", zap.String("tenant_id", resolved))
			writeConnectError(w, http.StatusServiceUnavailable, "unavailable",
				"tenant backend unavailable")
			return
		}

		member, err := tr.isMember(r.Context(), repo, userID)
		if err != nil {
			tr.logger.Error("tenant_membership_check_failed",
				zap.String("tenant_id", resolved), zap.Error(err))
			writeConnectError(w, http.StatusServiceUnavailable, "unavailable",
				"tenant membership check failed")
			return
		}
		if !member {
			writeConnectError(w, http.StatusForbidden, "permission_denied",
				"user is not a member of the resolved tenant")
			return
		}

		ctx := service.WithTenantScope(r.Context(), tenantScope(resolved, repo))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// tenantScope pairs the resolved tenant id with its scoped Repository
// and, when the backend's per-tenant Repository also implements the raw
// service.DB interface (the postgres driver, whose DB binds to a single
// tenant), the matching scoped DB. The entdb driver's per-tenant
// Repository is not a DB — its DB routes by the per-call tenant id — so
// DB stays nil there and the raw-node services pass the tenant id
// through the boot-time DB.
func tenantScope(tenantID string, repo service.Repository) *service.TenantScope {
	scope := &service.TenantScope{TenantID: tenantID, Repo: repo}
	if db, ok := repo.(service.DB); ok {
		scope.DB = db
	}
	return scope
}

// serveWithScope injects a tenant scope (without a membership check) and
// continues. Used for unauthenticated, tenant-scoped paths such as
// PasswordLogin where the user is not yet authenticated but the request
// must operate inside the host-resolved tenant.
func (tr *TenantResolver) serveWithScope(w http.ResponseWriter, r *http.Request, next http.Handler, tenant string) {
	repo := tr.repoForTenant(tenant)
	if repo == nil {
		tr.logger.Error("tenant_repo_factory_nil", zap.String("tenant_id", tenant))
		writeConnectError(w, http.StatusServiceUnavailable, "unavailable", "tenant backend unavailable")
		return
	}
	ctx := service.WithTenantScope(r.Context(), tenantScope(tenant, repo))
	next.ServeHTTP(w, r.WithContext(ctx))
}

func (tr *TenantResolver) usesHost() bool { return tr.hasSource(config.TenantSourceHost) }
func (tr *TenantResolver) usesJWT() bool  { return tr.hasSource(config.TenantSourceJWT) }

func (tr *TenantResolver) hasSource(name string) bool {
	for _, s := range tr.sources {
		if s == name {
			return true
		}
	}
	return false
}

// pick applies the configured precedence. The first source in
// tr.sources that produced a non-empty tenant wins. When both sources
// produced a non-empty value they must agree; a disagreement returns
// ok=false so the caller rejects the request.
func (tr *TenantResolver) pick(hostTenant, jwtTenant string) (string, bool) {
	if hostTenant != "" && jwtTenant != "" && hostTenant != jwtTenant {
		return "", false
	}
	for _, src := range tr.sources {
		switch src {
		case config.TenantSourceHost:
			if hostTenant != "" {
				return hostTenant, true
			}
		case config.TenantSourceJWT:
			if jwtTenant != "" {
				return jwtTenant, true
			}
		}
	}
	return "", true
}

// tenantFromHost extracts the leading subdomain label when the request
// host is a direct subdomain of the configured base domain. The apex
// domain itself, an unrelated host, or a multi-label prefix all yield
// "" (no tenant), which the caller treats per path.
func (tr *TenantResolver) tenantFromHost(r *http.Request) string {
	if tr.baseDomain == "" {
		return ""
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" || host == tr.baseDomain {
		return ""
	}
	suffix := "." + tr.baseDomain
	if !strings.HasSuffix(host, suffix) {
		return ""
	}
	label := strings.TrimSuffix(host, suffix)
	// Only a single subdomain label maps to a tenant; deeper nesting
	// (a.b.base) is not a tenant address.
	if label == "" || strings.Contains(label, ".") {
		return ""
	}
	return label
}

// isMember reports whether userID belongs to any organisation in the
// repo's tenant. Identity↔tenant is 1:1 (decision log §2), so any
// organisation membership inside the resolved tenant proves the caller
// belongs to that tenant.
func (tr *TenantResolver) isMember(ctx context.Context, repo service.Repository, userID string) (bool, error) {
	orgs, err := repo.ListOrganizationsForUser(ctx, userID)
	if err != nil {
		return false, err
	}
	return len(orgs) > 0, nil
}

// isTenantProvisioningPath reports whether path creates a tenant rather
// than operating within one (OrganizationSignup). Such requests have no
// tenant to resolve.
func isTenantProvisioningPath(path string) bool {
	return path == "/identity.IdentityService/OrganizationSignup"
}

// writeConnectError emits the same JSON error shape the auth middleware
// uses so Connect maps the HTTP status onto the matching RPC code
// (401 → Unauthenticated, 403 → PermissionDenied, 503 → Unavailable). It
// is shared by the tenant- and project-resolution middleware.
func writeConnectError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	http.Error(w, `{"code":"`+code+`","message":"`+msg+`"}`, status)
}
