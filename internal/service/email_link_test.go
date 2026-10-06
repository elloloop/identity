package service

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
)

const emailLinkTestToken = "0a1b2c3d4e5f"

// TestBuildEmailLink pins the link format: the token first, then product and
// redirect only when present, every value query-escaped so a return_to's own
// query, fragment or spaces cannot leak into the link's parameters.
func TestBuildEmailLink(t *testing.T) {
	t.Parallel()

	const page = "https://signin.example/reset-password"
	cases := []struct {
		name string
		link emailLink
		want string
	}{
		{
			name: "token only is the historical link",
			want: page + "?token=" + emailLinkTestToken,
		},
		{
			name: "product",
			link: emailLink{product: "acme"},
			want: page + "?token=" + emailLinkTestToken + "&product=acme",
		},
		{
			name: "return_to",
			link: emailLink{returnTo: "https://acme.example/home"},
			want: page + "?token=" + emailLinkTestToken + "&redirect=https%3A%2F%2Facme.example%2Fhome",
		},
		{
			name: "both, return_to with its own query and fragment",
			link: emailLink{product: "acme", returnTo: "https://acme.example/a b?x=1&y=2#top"},
			want: page + "?token=" + emailLinkTestToken +
				"&product=acme&redirect=https%3A%2F%2Facme.example%2Fa+b%3Fx%3D1%26y%3D2%23top",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := buildEmailLink(page, emailLinkTestToken, tc.link)
			if got != tc.want {
				t.Fatalf("buildEmailLink:\n got  %s\n want %s", got, tc.want)
			}
			// The page must read back exactly what was put in.
			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("link does not parse: %v", err)
			}
			q := u.Query()
			if q.Get(emailLinkParamToken) != emailLinkTestToken ||
				q.Get(emailLinkParamProduct) != tc.link.product ||
				q.Get(emailLinkParamRedirect) != tc.link.returnTo {
				t.Fatalf("round trip = %v, want token=%q product=%q redirect=%q",
					q, emailLinkTestToken, tc.link.product, tc.link.returnTo)
			}
		})
	}
}

// TestEmailLinkPageURL covers where a link points: GATEWAY_EMAIL_LINK_BASE_URL
// (trailing slash trimmed, path prefix kept) ahead of everything, including a
// project's primary auth domain; otherwise /auth/ on the request's app base.
func TestEmailLinkPageURL(t *testing.T) {
	t.Parallel()

	branded := WithProjectScope(context.Background(),
		&ProjectScope{ProjectID: "p", PrimaryAuthDomain: "auth.acme.example"})
	cases := []struct {
		name string
		base string
		ctx  context.Context
		want string
	}{
		{"no base, no project", "", context.Background(), "https://app.example/auth/verify-email"},
		{"no base, branded project", "", branded, "https://auth.acme.example/auth/verify-email"},
		{"base", "https://signin.example", context.Background(), "https://signin.example/verify-email"},
		{"base with trailing slash", "https://signin.example/", context.Background(), "https://signin.example/verify-email"},
		{"base with path prefix", "https://acme.example/account", context.Background(), "https://acme.example/account/verify-email"},
		{"base beats branded project", "https://signin.example", branded, "https://signin.example/verify-email"},
		{"loopback base", "http://localhost:3000", context.Background(), "http://localhost:3000/verify-email"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := &AuthService{cfg: &config.Config{AppBaseURL: "https://app.example", EmailLinkBaseURL: tc.base}}
			if got := s.emailLinkPageURL(tc.ctx, emailLinkPageVerifyEmail); got != tc.want {
				t.Fatalf("emailLinkPageURL = %q, want %q", got, tc.want)
			}
		})
	}
}

func newEmailLinkCheckService(t *testing.T, allowlist string) *AuthService {
	t.Helper()
	return &AuthService{logger: zap.NewNop(), returnAllow: ParseReturnAllowlist(allowlist)}
}

func TestCheckEmailLinkParams_Accepts(t *testing.T) {
	t.Parallel()

	s := newEmailLinkCheckService(t, "https://acme.example,https://app.example/learn")
	cases := []struct {
		name string
		in   EmailLinkParams
		want emailLink
	}{
		{"nothing", EmailLinkParams{}, emailLink{}},
		{
			"exact origin",
			EmailLinkParams{ReturnTo: "https://acme.example/home?x=1"},
			emailLink{returnTo: "https://acme.example/home?x=1"},
		},
		{
			"path prefix descendant",
			EmailLinkParams{ReturnTo: "https://app.example/learn/course/1"},
			emailLink{returnTo: "https://app.example/learn/course/1"},
		},
		{
			"return_to trimmed",
			EmailLinkParams{ReturnTo: "  https://acme.example/  "},
			emailLink{returnTo: "https://acme.example/"},
		},
		{"product normalized", EmailLinkParams{Product: " Acme "}, emailLink{product: "acme"}},
		{
			"product with digits, dash, underscore",
			EmailLinkParams{Product: "acme-kids_2"},
			emailLink{product: "acme-kids_2"},
		},
		{
			"product at the length limit",
			EmailLinkParams{Product: strings.Repeat("a", 64)},
			emailLink{product: strings.Repeat("a", 64)},
		},
		{
			"both",
			EmailLinkParams{Product: "acme", ReturnTo: "https://acme.example"},
			emailLink{product: "acme", returnTo: "https://acme.example"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := s.checkEmailLinkParams(tc.in)
			if err != nil {
				t.Fatalf("checkEmailLinkParams(%+v): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("checkEmailLinkParams(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckEmailLinkParams_Refuses(t *testing.T) {
	t.Parallel()

	s := newEmailLinkCheckService(t, "https://acme.example,https://app.example/learn")
	cases := []struct {
		name string
		in   EmailLinkParams
	}{
		{"unlisted origin", EmailLinkParams{ReturnTo: "https://evil.example/"}},
		{"look-alike host", EmailLinkParams{ReturnTo: "https://acme.example.evil.example/"}},
		{"http downgrade of a listed origin", EmailLinkParams{ReturnTo: "http://acme.example/"}},
		{"outside the path prefix", EmailLinkParams{ReturnTo: "https://app.example/admin"}},
		{"dot-dot out of the path prefix", EmailLinkParams{ReturnTo: "https://app.example/learn/../admin"}},
		{"userinfo", EmailLinkParams{ReturnTo: "https://user@acme.example/"}},
		{"relative", EmailLinkParams{ReturnTo: "/home"}},
		{"javascript scheme", EmailLinkParams{ReturnTo: "javascript:alert(1)"}},
		{"product with a space", EmailLinkParams{Product: "acme kids"}},
		{"product with a slash", EmailLinkParams{Product: "a/b"}},
		{"product starting with a dash", EmailLinkParams{Product: "-acme"}},
		{"product not ASCII", EmailLinkParams{Product: "tørtoise"}},
		{"product over the length limit", EmailLinkParams{Product: strings.Repeat("a", 65)}},
		{"good product, bad return_to", EmailLinkParams{Product: "acme", ReturnTo: "https://evil.example/"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := s.checkEmailLinkParams(tc.in); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("checkEmailLinkParams(%+v) err = %v, want ErrInvalidArgument", tc.in, err)
			}
		})
	}
}

// TestCheckEmailLinkParams_EmptyAllowlistRefusesEveryReturnTo: with
// GATEWAY_OAUTH_ALLOWED_RETURN_URLS unset nothing is trusted, so a return_to
// is refused rather than put into an email; a product alone still passes.
func TestCheckEmailLinkParams_EmptyAllowlistRefusesEveryReturnTo(t *testing.T) {
	t.Parallel()

	s := newEmailLinkCheckService(t, "")
	if _, err := s.checkEmailLinkParams(EmailLinkParams{ReturnTo: "https://acme.example/"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("return_to with an empty allowlist: err = %v, want ErrInvalidArgument", err)
	}
	if got, err := s.checkEmailLinkParams(EmailLinkParams{Product: "acme"}); err != nil || got.product != "acme" {
		t.Fatalf("product alone with an empty allowlist = %+v, %v", got, err)
	}
}
