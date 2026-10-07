package service

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// The pages that redeem an emailed password-reset or email-verification token,
// and the query parameters of the link to them. Together they are the contract
// with whatever serves those pages: the app at the app base URL (under
// appAuthPathPrefix), or the sign-in hub at GATEWAY_EMAIL_LINK_BASE_URL.
const (
	emailLinkPageResetPassword = "reset-password"
	emailLinkPageVerifyEmail   = "verify-email"

	// appAuthPathPrefix is where the pages sit below the app base URL when no
	// email-link base is configured.
	appAuthPathPrefix = "/auth/"

	emailLinkParamToken    = "token"
	emailLinkParamProduct  = "product"
	emailLinkParamRedirect = "redirect"
)

// productSlugPattern is the shape a product slug must have, once normalized
// (normalizeProductSlug), to be put on an emailed link: lower-case letters,
// digits, '-' and '_', starting with a letter or digit, at most 64 long.
var productSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// EmailLinkParams is what a caller may add to the link in a password-reset or
// email-verification email besides the token. Both fields are optional and are
// untrusted until checkEmailLinkParams admits them.
type EmailLinkParams struct {
	// Product is the slug of the product the request is for (e.g.
	// "acme"), with the semantics of the hosted hub's ?product= query.
	Product string
	// ReturnTo is the app URL the landing page sends the user back to.
	ReturnTo string
}

// emailLink is an EmailLinkParams that checkEmailLinkParams admitted: the
// product normalized and well-formed, the return_to on the allowlist. Email
// sends take this type rather than EmailLinkParams so that an unchecked URL
// cannot reach a message. The zero value adds nothing to the link.
type emailLink struct {
	product  string
	returnTo string
}

// checkEmailLinkParams admits the caller's link parameters or fails with
// ErrInvalidArgument. A return_to must match GATEWAY_OAUTH_ALLOWED_RETURN_URLS
// — the allowlist hosted OAuth and magic links share — so an email can never
// carry an attacker's redirect. The check reads only the request and the
// deployment's allowlist, so its answer is the same for every email address
// and cannot be used to probe for an account.
func (s *AuthService) checkEmailLinkParams(p EmailLinkParams) (emailLink, error) {
	product := normalizeProductSlug(p.Product)
	if product != "" && !productSlugPattern.MatchString(product) {
		s.logger.Info("email_link_product_rejected")
		return emailLink{}, fmt.Errorf("%w: product is not a valid product slug", ErrInvalidArgument)
	}
	returnTo := strings.TrimSpace(p.ReturnTo)
	if returnTo != "" && !s.returnAllow.Allows(returnTo) {
		s.logger.Info("email_link_return_to_rejected")
		return emailLink{}, fmt.Errorf("%w: return_to is not allowed", ErrInvalidArgument)
	}
	return emailLink{product: product, returnTo: returnTo}, nil
}

// emailLinkURL is the link to page that an email for the request in ctx
// carries: token plus the checked link parameters.
func (s *AuthService) emailLinkURL(ctx context.Context, page, token string, link emailLink) string {
	return buildEmailLink(s.emailLinkPageURL(ctx, page), token, link)
}

// emailLinkPageURL locates page. GATEWAY_EMAIL_LINK_BASE_URL, when set, wins
// over everything — including a project's primary auth domain, because the
// deployment serves these pages from that one place; otherwise the page is
// under /auth/ on the request's app base URL.
func (s *AuthService) emailLinkPageURL(ctx context.Context, page string) string {
	if base := strings.TrimRight(s.cfg.EmailLinkBaseURL, "/"); base != "" {
		return base + "/" + page
	}
	return s.appBaseURL(ctx) + appAuthPathPrefix + page
}

// buildEmailLink appends the token, then the product and the return_to (as
// "redirect") when present, each query-escaped. The order is fixed with the
// token first, so a link without either optional parameter is exactly
// "<page>?token=<token>".
func buildEmailLink(pageURL, token string, link emailLink) string {
	var b strings.Builder
	b.WriteString(pageURL)
	b.WriteString("?" + emailLinkParamToken + "=" + url.QueryEscape(token))
	if link.product != "" {
		b.WriteString("&" + emailLinkParamProduct + "=" + url.QueryEscape(link.product))
	}
	if link.returnTo != "" {
		b.WriteString("&" + emailLinkParamRedirect + "=" + url.QueryEscape(link.returnTo))
	}
	return b.String()
}
