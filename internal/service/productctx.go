package service

import "context"

type productCtxKey struct{}

// WithProduct returns a child context carrying the product slug a request is
// authenticating FOR. The product-resolution middleware calls this once per
// request with the X-Product header's value, or the deployment's default
// product slug when the header is absent (a legacy client).
//
// The product is distinct from the project: a project owns the account pool and
// resolves from a credential key or Host, while a product is one of the apps
// that pool signs into and travels on the request. One project therefore serves
// many products, each with its own guardrails (ProjectProductsConfig).
func WithProduct(ctx context.Context, slug string) context.Context {
	if slug == "" {
		return ctx
	}
	return context.WithValue(ctx, productCtxKey{}, slug)
}

// ProductFromContext returns the request's product slug, or "" when none was
// injected (a direct service call, or a deployment with no default product
// configured). "" matches no configured product, so it is unrestricted.
func ProductFromContext(ctx context.Context) string {
	slug, _ := ctx.Value(productCtxKey{}).(string)
	return slug
}
