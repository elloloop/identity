package middleware

import (
	"errors"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/service"
	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

// Stable reason codes emitted on auth_refused warnings and attached to 4xx/5xx
// request log lines.
//
// #nosec G101 -- stable log reason identifiers, not credentials.
const (
	ReasonMissingBearer        = "missing_bearer"
	ReasonTokenMalformed       = "token_malformed"
	ReasonTokenSignature       = "token_signature"
	ReasonTokenExpired         = "token_expired"
	ReasonTokenIssuer          = "token_issuer"
	ReasonTokenAudience        = "token_audience"
	ReasonTokenPurposeRejected = "token_purpose_rejected"
	ReasonTokenTenantRejected  = "token_tenant_rejected"
	ReasonTokenTenantLookup    = "token_tenant_lookup"
	ReasonSessionLookupFailed  = "session_lookup_failed"
	ReasonSessionRevoked       = "session_revoked"
	ReasonTokenProjectMismatch = "token_project_mismatch"
)

func recordAuthRefusal(r *http.Request, logger *zap.Logger, reason string, claims *jwtpkg.Claims) {
	fields := requestRefusalFields(r, claims, time.Now())
	service.RecordRefusal(r.Context(), logger, "auth_refused", reason, fields...)
}

func recordTokenRefusal(r *http.Request, logger *zap.Logger, token string, claims *jwtpkg.Claims, err error) {
	if claims == nil {
		claims, _ = jwtpkg.PeekClaims(token)
	}
	recordAuthRefusal(r, logger, tokenRefusalReason(err), claims)
}

func recordProjectMismatchRefusal(r *http.Request, reqProjectID, tokenProject string) {
	fields := []zap.Field{
		zap.String("request_project_id", reqProjectID),
		zap.String("project_id", tokenProject),
	}
	if r.URL != nil && r.URL.Path != "" {
		fields = append(fields, zap.String("path", r.URL.Path))
	}
	if r.RemoteAddr != "" {
		fields = append(fields, zap.String("remote_addr", r.RemoteAddr))
	}
	if host := requestHost(r); host != "" {
		fields = append(fields, zap.String("host", host))
	}
	if tenantID := r.Header.Get(AuthenticatedTenantHeader); tenantID != "" {
		fields = append(fields, zap.String("tenant_id", tenantID))
	}
	if userID := r.Header.Get(AuthenticatedUserIDHeader); userID != "" {
		fields = append(fields, zap.String("user_id", userID))
	}
	if sessionID := r.Header.Get(AuthenticatedSessionIDHeader); sessionID != "" {
		fields = append(fields, zap.String("session_id", sessionID))
	}
	service.RecordRefusal(r.Context(), nil, "auth_refused", ReasonTokenProjectMismatch, fields...)
}

func tokenRefusalReason(err error) string {
	switch {
	case errors.Is(err, errTokenTenantLookup):
		return ReasonTokenTenantLookup
	case errors.Is(err, errTokenTenantRejected):
		return ReasonTokenTenantRejected
	case errors.Is(err, jwtpkg.ErrTokenPurposeRejected):
		return ReasonTokenPurposeRejected
	case errors.Is(err, jwtpkg.ErrTokenAudience):
		return ReasonTokenAudience
	case errors.Is(err, jwtpkg.ErrTokenIssuer):
		return ReasonTokenIssuer
	case errors.Is(err, jwtpkg.ErrTokenExpired):
		return ReasonTokenExpired
	case errors.Is(err, jwtpkg.ErrTokenSignature):
		return ReasonTokenSignature
	default:
		return ReasonTokenMalformed
	}
}

func requestRefusalFields(r *http.Request, claims *jwtpkg.Claims, now time.Time) []zap.Field {
	fields := make([]zap.Field, 0, 11)
	if r.URL != nil && r.URL.Path != "" {
		fields = append(fields, zap.String("path", r.URL.Path))
	}
	if r.RemoteAddr != "" {
		fields = append(fields, zap.String("remote_addr", r.RemoteAddr))
	}
	if host := requestHost(r); host != "" {
		fields = append(fields, zap.String("host", host))
	}
	if scope := service.ProjectScopeFromContext(r.Context()); scope != nil && scope.ProjectID != "" {
		fields = append(fields, zap.String("request_project_id", scope.ProjectID))
	}
	if claims == nil {
		return fields
	}
	if claims.Project != "" {
		fields = append(fields, zap.String("project_id", claims.Project))
	}
	if claims.Tenant != "" {
		fields = append(fields, zap.String("tenant_id", claims.Tenant))
	}
	if claims.Sub != "" {
		fields = append(fields, zap.String("user_id", claims.Sub))
	}
	if claims.SID != "" {
		fields = append(fields, zap.String("session_id", claims.SID))
	}
	if claims.Issuer != "" {
		fields = append(fields, zap.String("issuer", claims.Issuer))
	}
	nowSec := now.Unix()
	if claims.AuthTime > 0 {
		fields = append(fields, zap.Int64("auth_time_age_s", nowSec-claims.AuthTime))
	}
	if claims.ExpiresAt > 0 {
		fields = append(fields, zap.Int64("expiry_age_s", nowSec-claims.ExpiresAt))
	}
	return fields
}
