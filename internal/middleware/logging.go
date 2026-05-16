package middleware

import (
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/observability"
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
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			fields := []zap.Field{
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", wrapped.statusCode),
				zap.Duration("duration", time.Since(start)),
				zap.String("remote_addr", r.RemoteAddr),
			}
			if traceID := observability.TraceIDFromContext(r.Context()); traceID != "" {
				fields = append(fields, zap.String(observability.TraceIDLogField, traceID))
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
