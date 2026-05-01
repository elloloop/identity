package middleware

import (
	"net/http"

	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

// JWKSMiddleware serves the /.well-known/jwks.json endpoint from the key ring.
// The response contains the RSA public keys for all keys in the ring so that
// third-party services can verify tokens without sharing a secret.
func JWKSMiddleware(keyRing *jwtpkg.KeyRing) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/jwks.json" {
				jwksJSON, err := keyRing.JWKS()
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
