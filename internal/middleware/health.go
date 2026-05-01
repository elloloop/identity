package middleware

import (
	"net/http"
)

// HealthMiddleware handles /health, /healthz, and / before the request reaches
// the Connect handler. This keeps health probes (e.g. Azure Container Apps)
// cheap and independent of service readiness.
func HealthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/healthz" || r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
