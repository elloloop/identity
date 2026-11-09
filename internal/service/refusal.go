package service

import (
	"context"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/elloloop/identity/internal/observability"
)

// RefusalInfo holds per-request refusal diagnostics and non-secret caller
// identity attributes shared between the HTTP middleware chain and the
// service layer. LoggingMiddleware attaches a mutable *RefusalInfo to the
// request context before invoking downstream handlers so any middleware or
// RPC that refuses a request can record a stable reason code and identity
// context for both the immediate refusal warning and the outer request log.
type RefusalInfo struct {
	Logger           *zap.Logger
	Reason           string
	Path             string
	RemoteAddr       string
	Host             string
	RequestProjectID string
	UserID           string
	ProjectID        string
	TenantID         string
	SessionID        string
	TraceID          string
}

type refusalInfoCtxKey struct{}

// WithRefusalInfo returns a child context carrying info. A nil info is a
// no-op.
func WithRefusalInfo(ctx context.Context, info *RefusalInfo) context.Context {
	if info == nil {
		return ctx
	}
	return context.WithValue(ctx, refusalInfoCtxKey{}, info)
}

// RefusalInfoFromContext returns the per-request RefusalInfo, or nil when
// none was injected.
func RefusalInfoFromContext(ctx context.Context) *RefusalInfo {
	info, _ := ctx.Value(refusalInfoCtxKey{}).(*RefusalInfo)
	return info
}

// RecordRefusal updates the request's RefusalInfo holder (when present in ctx)
// with reason and non-secret identity metadata, and emits one structured Warn
// log entry with msg, reason, host, request_project_id, trace_id, and any
// non-secret claims or refusal attributes. Raw tokens, cookies, codes, and
// secrets must never be passed to RecordRefusal.
func RecordRefusal(ctx context.Context, logger *zap.Logger, msg, reason string, fields ...zap.Field) {
	info := RefusalInfoFromContext(ctx)

	host := RequestHostFromContext(ctx)
	var reqProjectID string
	if scope := ProjectScopeFromContext(ctx); scope != nil {
		reqProjectID = scope.ProjectID
	}
	traceID := observability.TraceIDFromContext(ctx)

	var path, remoteAddr, projectID, tenantID, userID, sessionID string
	for _, f := range fields {
		if f.Type != zapcore.StringType || f.String == "" {
			continue
		}
		switch f.Key {
		case "host":
			host = f.String
		case "request_project_id":
			reqProjectID = f.String
		case "path":
			path = f.String
		case "remote_addr":
			remoteAddr = f.String
		case "project_id":
			projectID = f.String
		case "tenant_id":
			tenantID = f.String
		case "user_id":
			userID = f.String
		case "session_id":
			sessionID = f.String
		}
	}

	if info != nil {
		info.Reason = reason
		host = syncRefusalField(&info.Host, host)
		reqProjectID = syncRefusalField(&info.RequestProjectID, reqProjectID)
		path = syncRefusalField(&info.Path, path)
		remoteAddr = syncRefusalField(&info.RemoteAddr, remoteAddr)
		projectID = syncRefusalField(&info.ProjectID, projectID)
		tenantID = syncRefusalField(&info.TenantID, tenantID)
		userID = syncRefusalField(&info.UserID, userID)
		sessionID = syncRefusalField(&info.SessionID, sessionID)
		traceID = syncRefusalField(&info.TraceID, traceID)
		if logger == nil {
			logger = info.Logger
		}
	}

	if logger == nil {
		return
	}

	out := make([]zap.Field, 0, len(fields)+10)
	out = append(out,
		zap.String("reason", reason),
		zap.String("host", host),
		zap.String("request_project_id", reqProjectID),
	)
	if path != "" {
		out = append(out, zap.String("path", path))
	}
	if remoteAddr != "" {
		out = append(out, zap.String("remote_addr", remoteAddr))
	}
	if projectID != "" {
		out = append(out, zap.String("project_id", projectID))
	}
	if tenantID != "" {
		out = append(out, zap.String("tenant_id", tenantID))
	}
	if userID != "" {
		out = append(out, zap.String("user_id", userID))
	}
	if sessionID != "" {
		out = append(out, zap.String("session_id", sessionID))
	}
	if traceID != "" {
		out = append(out, zap.String(observability.TraceIDLogField, traceID))
	}
	for _, f := range fields {
		if isBaseRefusalField(f.Key) {
			continue
		}
		out = append(out, f)
	}
	logger.Warn(msg, out...)
}

func syncRefusalField(dst *string, val string) string {
	if val != "" {
		*dst = val
		return val
	}
	return *dst
}

func isBaseRefusalField(key string) bool {
	switch key {
	case "reason", "host", "request_project_id", "path", "remote_addr",
		"project_id", "tenant_id", "user_id", "session_id", observability.TraceIDLogField:
		return true
	default:
		return false
	}
}
