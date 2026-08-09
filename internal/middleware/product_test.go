package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elloloop/identity/internal/service"
)

// captureProduct runs one request through the product resolver and returns the
// slug the handler observed in its context.
func captureProduct(t *testing.T, defaultProduct, header string) string {
	t.Helper()
	var got string
	handler := NewProductResolver(defaultProduct)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = service.ProductFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/PasswordLogin", nil)
	if header != "" {
		req.Header.Set(ProductHeader, header)
	}
	handler.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func TestProductResolver_Resolution(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name           string
		defaultProduct string
		header         string
		want           string
	}{
		{"header_wins", "product-a", "product-b", "product-b"},
		// A client that predates the header is the deployment's primary app,
		// not "no product" — otherwise every legacy client escapes its
		// product's guardrails.
		{"absent_header_falls_back_to_default", "product-a", "", "product-a"},
		{"blank_header_falls_back_to_default", "product-a", "   ", "product-a"},
		// Slugs are case-insensitive identifiers, normalized on both sides of
		// the lookup so config authored as "Product-B" matches a header of "PRODUCT-B".
		{"header_normalized", "product-a", "  Product-B  ", "product-b"},
		{"default_normalized", " Product-A ", "", "product-a"},
		// No header and no configured default leaves the request unrestricted:
		// "" matches no configured product.
		{"no_default_no_header", "", "", ""},
		{"no_default_with_header", "", "product-b", "product-b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, captureProduct(t, tc.defaultProduct, tc.header))
		})
	}
}

func TestProductResolver_PassesRequestThrough(t *testing.T) {
	t.Parallel()
	handler := NewProductResolver("product-a")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/anything", nil))
	assert.Equal(t, http.StatusTeapot, rec.Code)
}
