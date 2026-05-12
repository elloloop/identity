package middleware

import (
	"context"
	"net/http"
	"time"
)

// ReadinessProbe checks that the dependencies needed to serve traffic are
// reachable. Implementations should be cheap and bounded — `/readyz` is hit
// from load balancers on every health interval.
type ReadinessProbe interface {
	Ready(ctx context.Context) error
}

// HealthMiddleware serves /livez (always 200 if the process is alive) and
// /readyz (200 only when probe.Ready returns nil). The legacy paths
// /health, /healthz, and / map to /livez for backwards compatibility.
//
// Pass a nil probe to disable readiness checks (the endpoint then always
// returns 200, useful for tests).
func HealthMiddleware(probe ReadinessProbe, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/livez", "/health", "/healthz", "/":
			writeJSON(w, http.StatusOK, `{"status":"ok"}`)
			return
		case "/readyz":
			if probe == nil {
				writeJSON(w, http.StatusOK, `{"status":"ok"}`)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := probe.Ready(ctx); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, `{"status":"not_ready"}`)
				return
			}
			writeJSON(w, http.StatusOK, `{"status":"ok"}`)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
