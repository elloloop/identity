package middleware

import (
	"net/http"
	"time"

	"go.opentelemetry.io/otel/propagation"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/observability"
	"github.com/elloloop/identity/internal/service"
)

// LoggingMiddleware logs every request's method, path, response status code,
// duration, and remote address using the provided zap logger. When a
// recording span is attached to the request context (either because the
// otelconnect interceptor created one or because an upstream proxy
// forwarded W3C TraceContext headers), the trace id is included so
// deployers can pivot from a log line to the full trace.
func LoggingMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ctx := r.Context()
			if observability.TraceIDFromContext(ctx) == "" && r.Header.Get("Traceparent") != "" {
				ctx = propagation.TraceContext{}.Extract(ctx, propagation.HeaderCarrier(r.Header))
			}
			info := &service.RefusalInfo{
				Logger:     logger,
				Path:       r.URL.Path,
				RemoteAddr: r.RemoteAddr,
				Host:       requestHost(r),
				TraceID:    observability.TraceIDFromContext(ctx),
			}
			ctx = service.WithRefusalInfo(ctx, info)
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r.WithContext(ctx))

			fields := []zap.Field{
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", wrapped.statusCode),
				zap.Duration("duration", time.Since(start)),
				zap.String("remote_addr", r.RemoteAddr),
			}
			if wrapped.statusCode >= http.StatusBadRequest {
				if info.Reason != "" {
					fields = append(fields, zap.String("reason", info.Reason))
				}
				if info.Host != "" {
					fields = append(fields, zap.String("host", info.Host))
				}
				if info.RequestProjectID != "" {
					fields = append(fields, zap.String("request_project_id", info.RequestProjectID))
				}
				if info.ProjectID != "" {
					fields = append(fields, zap.String("project_id", info.ProjectID))
				}
				if info.TenantID != "" {
					fields = append(fields, zap.String("tenant_id", info.TenantID))
				}
				if info.UserID != "" {
					fields = append(fields, zap.String("user_id", info.UserID))
				}
				if info.SessionID != "" {
					fields = append(fields, zap.String("session_id", info.SessionID))
				}
			}
			if info.TraceID != "" {
				fields = append(fields, zap.String(observability.TraceIDLogField, info.TraceID))
			}
			logger.Info("request", fields...)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code and delegates to the inner writer.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
