package middleware

import (
	"net/http"
	"strings"

	"github.com/elloloop/identity/internal/service"
)

// ProductHeader carries the slug of the product a request is authenticating
// FOR ("hold", "nesta", "account-portal", …). One account signs into every
// product in its project's pool, so the product is a per-request property, not
// a property of the project or the credential — it travels on the header.
const ProductHeader = "X-Product"

// NewProductResolver stamps the request's product slug into the context so the
// service layer can apply that product's guardrails (ProjectProductsConfig).
//
// A request with no X-Product header is a legacy client that predates the
// header, and is treated as defaultProduct (GATEWAY_DEFAULT_PRODUCT) — the
// deployment's primary app. Resolving one product for EVERY request, rather
// than reading the header per RPC, is what makes it impossible for a
// session-issuing path to be reachable without a product in scope.
//
// When no default product is configured and the header is absent the request
// carries no product, which matches no configured policy and so is
// unrestricted.
func NewProductResolver(defaultProduct string) func(http.Handler) http.Handler {
	fallback := normalizeProduct(defaultProduct)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			product := normalizeProduct(r.Header.Get(ProductHeader))
			if product == "" {
				product = fallback
			}
			next.ServeHTTP(w, r.WithContext(service.WithProduct(r.Context(), product)))
		})
	}
}

// normalizeProduct trims and lower-cases a slug so a client sending "Hold" or
// " hold " matches a policy authored as "hold". It mirrors the normalization
// ParseProjectConfig applies to the configured slugs, so both sides of the
// lookup are normalized exactly once.
func normalizeProduct(raw string) string {
	return strings.TrimSpace(strings.ToLower(raw))
}
