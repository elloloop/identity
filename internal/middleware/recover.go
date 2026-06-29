package middleware

import (
	"net/http"
	"runtime/debug"

	"go.uber.org/zap"
)

// RecoverMiddleware catches panics in any downstream handler, logs them
// with the stack trace, and returns a generic 500 to the client.
//
// Connect-Go does not recover panics by itself — a nil deref in any RPC
// handler would otherwise crash the goroutine and propagate to the HTTP
// server. At a million requests/day even a 0.001 % panic rate hits real
// users; we prefer a logged 500 to an unexplained TCP reset.
func RecoverMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error(
						"http_handler_panic",
						zap.Any("panic", rec),
						zap.String("method", r.Method),
						zap.String("path", r.URL.Path),
						zap.ByteString("stack", debug.Stack()),
					)
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
