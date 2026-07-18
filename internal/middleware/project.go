package middleware

import (
	"net"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/oauth"
)

// ProjectKeyHeader carries a project's publishable/secret credential
// public id. When present, it is the highest-precedence resolution source
// — an explicit key that does not resolve is an error, not a fallback.
const ProjectKeyHeader = "X-Project-Key"

// ProjectResolver resolves the per-request project ahead of tenant
// resolution and threads it through the request context as a
// service.ProjectScope. Resolution precedence:
//
//  1. the X-Project-Key credential header — or, on the hosted OAuth
//     routes only, the project_key request parameter / the plaintext key
//     prefix of the OAuth state (browser redirects cannot carry headers).
//     An explicit, invalid key is rejected — it is not silently
//     downgraded to the default;
//  2. the request Host, matched against a project auth-domain;
//  3. the configured default project (zero-config single-project pin).
//
// The resolver is the postgres control-plane store. Deployments whose
// driver has no control plane pass a nil resolver: every request then pins
// to the default project (steps 1–2 are skipped). When no default project
// is configured AND nothing resolves, the request passes through with no
// scope rather than being rejected, so non-project deployments are
// untouched.
type ProjectResolver struct {
	defaultProjectID      string
	defaultScopeID        string
	defaultPrimaryAuthDom string
	resolver              service.ProjectResolver
	logger                *zap.Logger
}

// NewProjectResolver builds the middleware. defaultProjectID /
// defaultScopeID are the default project's id and storage scope (the
// configured GATEWAY_DEFAULT_PROJECT_ID / GATEWAY_DEFAULT_TENANT_ID);
// defaultPrimaryAuthDomain is the default project's primary serving
// hostname (the first GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS entry), carried
// on the default-pin scope so branded links work zero-config without a
// per-request lookup. resolver may be nil (drivers without a control
// plane). When there is nothing to do — no resolver and no default project
// — the returned middleware is a no-op pass-through.
func NewProjectResolver(defaultProjectID, defaultScopeID, defaultPrimaryAuthDomain string, resolver service.ProjectResolver, logger *zap.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	if resolver == nil && defaultProjectID == "" {
		return func(next http.Handler) http.Handler { return next }
	}
	pr := &ProjectResolver{
		defaultProjectID:      defaultProjectID,
		defaultScopeID:        defaultScopeID,
		defaultPrimaryAuthDom: defaultPrimaryAuthDomain,
		resolver:              resolver,
		logger:                logger,
	}
	return pr.middleware
}

func (pr *ProjectResolver) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope, ok := pr.resolve(w, r)
		if !ok {
			return // resolve already wrote the error response
		}
		next.ServeHTTP(w, r.WithContext(service.WithProjectScope(r.Context(), scope)))
	})
}

// resolve returns the project scope to inject, or ok=false when it has
// already written an error response. A nil scope with ok=true means
// "pass through unscoped" (no default configured and nothing resolved).
func (pr *ProjectResolver) resolve(w http.ResponseWriter, r *http.Request) (*service.ProjectScope, bool) {
	ctx := r.Context()

	// 1. Explicit credential key — must resolve when present. Browser
	// redirects cannot carry the header, so the hosted OAuth routes also
	// accept the key from the request parameters (see oauthProjectKey);
	// an explicit key that does not resolve is rejected either way — it
	// is never silently downgraded to host/default resolution.
	key := r.Header.Get(ProjectKeyHeader)
	if key == "" && strings.HasPrefix(r.URL.Path, oauthPathPrefix) {
		var ok bool
		if key, ok = oauthProjectKey(w, r); !ok {
			writeConnectError(w, http.StatusBadRequest, "invalid_argument", "malformed form body")
			return nil, false
		}
	}
	if key != "" && pr.resolver != nil {
		rp, err := pr.resolver.ResolveByCredential(ctx, key)
		if err != nil {
			pr.logger.Error("project_resolve_by_key_failed", zap.Error(err))
			writeConnectError(w, http.StatusServiceUnavailable, "unavailable", "project resolution failed")
			return nil, false
		}
		if rp == nil {
			writeConnectError(w, http.StatusUnauthorized, "unauthenticated", "invalid project key")
			return nil, false
		}
		return scopeFromResolved(rp), true
	}

	// 2. Host → auth-domain.
	if pr.resolver != nil {
		if host := requestHost(r); host != "" {
			rp, err := pr.resolver.ResolveByHostname(ctx, host)
			if err != nil {
				pr.logger.Error("project_resolve_by_host_failed", zap.Error(err))
				writeConnectError(w, http.StatusServiceUnavailable, "unavailable", "project resolution failed")
				return nil, false
			}
			if rp != nil {
				return scopeFromResolved(rp), true
			}
		}
	}

	// 3. Default-project pin (zero-config). When no default is configured
	// and nothing resolved, pass through unscoped.
	if pr.defaultProjectID == "" {
		return nil, true
	}
	return &service.ProjectScope{
		ProjectID:         pr.defaultProjectID,
		StorageScopeID:    pr.defaultScopeID,
		PrimaryAuthDomain: pr.defaultPrimaryAuthDom,
	}, true
}

const (
	// oauthPathPrefix scopes the parameter-based project-key extraction to
	// the browser-facing hosted OAuth routes (/oauth/start, /oauth/callback)
	// — the only routes a key can arrive without the header.
	oauthPathPrefix = "/oauth/"
	// oauthFormMaxBytes bounds how much of a hosted-OAuth request body the
	// middleware will parse for the project key. It matches the callback
	// handler's own body cap so the limit holds end-to-end — the middleware
	// parses first, so an unbounded read here would defeat the handler's.
	oauthFormMaxBytes = 1 << 20
)

// oauthProjectKey extracts the project key a hosted OAuth request carries in
// its parameters: the explicit project_key (start), else the plaintext prefix
// of the composite state (callback — the provider echoes state verbatim, so
// the key BeginHostedOAuth prefixed survives the round-trip; the signed
// project_id claim inside the token is verified by CompleteHostedOAuth).
// ok=false means the form body was malformed or oversized.
//
// Only the URL query and an application/x-www-form-urlencoded body are
// consulted (ParseForm): Apple's form_post callback is urlencoded, and never
// invoking the multipart parser here keeps attacker-controlled bodies from
// spilling to memory or disk beyond the cap.
func oauthProjectKey(w http.ResponseWriter, r *http.Request) (key string, ok bool) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, oauthFormMaxBytes)
	}
	if err := r.ParseForm(); err != nil {
		return "", false
	}
	if key := r.Form.Get("project_key"); key != "" {
		return key, true
	}
	key, _ = oauth.SplitProjectKeyState(r.Form.Get("state"))
	return key, true
}

func scopeFromResolved(rp *service.ResolvedProject) *service.ProjectScope {
	return &service.ProjectScope{
		ProjectID:          rp.ID,
		StorageScopeID:     rp.StorageScopeID,
		PrimaryAuthDomain:  rp.PrimaryAuthDomain,
		CORSAllowedOrigins: rp.CORSAllowedOrigins,
		Branding:           rp.Branding,
		Passkey:            rp.Passkey,
		LoginDefaults:      rp.LoginDefaults,
		OAuth:              rp.OAuth,
	}
}

// requestHost returns the lower-cased request host with any port stripped,
// or "" when there is no host.
func requestHost(r *http.Request) string {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

// writeConnectError emits the same JSON error shape the auth middleware
// uses so Connect maps the HTTP status onto the matching RPC code
// (401 → Unauthenticated, 403 → PermissionDenied, 503 → Unavailable). It
// is shared by the project-resolution and project-scope-guard middleware.
func writeConnectError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	http.Error(w, `{"code":"`+code+`","message":"`+msg+`"}`, status)
}
