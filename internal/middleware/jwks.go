package middleware

import (
	"net/http"

	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

// JWKSMiddleware serves the /.well-known/jwks.json endpoint from the
// supplied [jwtpkg.KeyProvider]. The response contains the RSA public
// keys for every key the provider publishes so that third-party
// services can verify tokens without sharing a secret.
func JWKSMiddleware(kp jwtpkg.KeyProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/jwks.json" {
				jwksJSON, err := jwtpkg.JWKS(kp)
				if err != nil {
					http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "public, max-age=3600")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(jwksJSON)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
