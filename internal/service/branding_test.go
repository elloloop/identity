package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/email"
)

func TestResolveBranding_ZeroConfig_LegacyFromOnly(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{SMTPFrom: "legacy@example.com"}
	b := resolveBranding(context.Background(), cfg, "")

	// Nothing branded: From falls back to GATEWAY_SMTP_FROM and everything
	// else is empty so email output stays byte-compatible with today.
	assert.Equal(t, "legacy@example.com", b.from)
	assert.Empty(t, b.productName)
	assert.Empty(t, b.supportEmail)
	assert.Equal(t, "legacy@example.com", b.fromHeader())
}

func TestResolveBranding_GlobalDefaults(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		SMTPFrom:               "legacy@example.com",
		EmailBrandProductName:  "Global Product",
		EmailBrandFrom:         "brand@example.com",
		EmailBrandFromName:     "Global",
		EmailBrandSupportEmail: "support@example.com",
		EmailListUnsubscribe:   "<mailto:unsub@example.com>",
	}
	b := resolveBranding(context.Background(), cfg, "")

	assert.Equal(t, "Global Product", b.productName)
	assert.Equal(t, "brand@example.com", b.from)
	assert.Equal(t, `"Global" <brand@example.com>`, b.fromHeader())
	assert.Equal(t, "support@example.com", b.supportEmail)
	assert.Equal(t, "<mailto:unsub@example.com>", b.listUnsubscribe)
}

func TestResolveBranding_ProjectOverridesGlobal(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		SMTPFrom:              "legacy@example.com",
		EmailBrandProductName: "Global Product",
		EmailBrandFrom:        "brand@example.com",
	}
	ctx := WithProjectScope(context.Background(), &ProjectScope{
		Branding: ProjectBrandingConfig{
			ProductName:   "Kids",
			EmailFrom:     "no-reply@kids.example.com",
			EmailFromName: "Acme Kids",
			SupportEmail:  "help@kids.example.com",
		},
	})
	b := resolveBranding(ctx, cfg, "")

	// Per-project beats global default.
	assert.Equal(t, "Kids", b.productName)
	assert.Equal(t, "no-reply@kids.example.com", b.from)
	assert.Equal(t, `"Acme Kids" <no-reply@kids.example.com>`, b.fromHeader())
	assert.Equal(t, "help@kids.example.com", b.supportEmail)
}

func TestResolveBranding_PartialProject_FallsBackPerField(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		SMTPFrom:              "legacy@example.com",
		EmailBrandProductName: "Global Product",
	}
	ctx := WithProjectScope(context.Background(), &ProjectScope{
		Branding: ProjectBrandingConfig{EmailFrom: "p@example.com"},
	})
	b := resolveBranding(ctx, cfg, "")

	// EmailFrom is per-project; ProductName falls back to the global default.
	assert.Equal(t, "p@example.com", b.from)
	assert.Equal(t, "Global Product", b.productName)
}

// kidsProductScope is a project with its own branding whose "kids" product
// overrides part of it, so each tier of the precedence is observable.
func kidsProductScope() context.Context {
	return WithProjectScope(context.Background(), &ProjectScope{
		Branding: ProjectBrandingConfig{
			ProductName:   "Acme",
			EmailFrom:     "no-reply@acme.example.com",
			EmailFromName: "Acme",
		},
		Products: ProjectProductsConfig{
			"kids": {Branding: ProjectBrandingConfig{
				ProductName:   "Acme Kids",
				EmailFromName: "Acme Kids",
				LogoURL:       "https://kids.acme.example.com/logo.png",
			}},
			"teens": {MinimumAgeBand: MinimumAgeBandTeen},
		},
	})
}

func TestResolveBranding_ProductOverridesProjectPerField(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{SMTPFrom: "legacy@example.com", EmailBrandSupportEmail: "support@example.com"}
	b := resolveBranding(kidsProductScope(), cfg, "kids")

	// The product's fields win; each field it leaves empty falls back to the
	// project, then to the global default.
	assert.Equal(t, "Acme Kids", b.productName)
	assert.Equal(t, "https://kids.acme.example.com/logo.png", b.logoURL)
	assert.Equal(t, `"Acme Kids" <no-reply@acme.example.com>`, b.fromHeader())
	assert.Equal(t, "support@example.com", b.supportEmail)
}

func TestResolveBranding_ProductWithoutBrandingIsProjectBranding(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{SMTPFrom: "legacy@example.com"}
	project := resolveBranding(kidsProductScope(), cfg, "")
	assert.Equal(t, "Acme", project.productName)
	assert.Equal(t, `"Acme" <no-reply@acme.example.com>`, project.fromHeader())

	// A product with only a guardrail, and a product the project does not
	// know, both brand as the project.
	for _, product := range []string{"teens", "unknown"} {
		assert.Equal(t, project, resolveBranding(kidsProductScope(), cfg, product), product)
	}
}

// TestResolveBranding_LinkBase: the link base resolves like every other
// field, product over project over GATEWAY_EMAIL_LINK_BASE_URL, and stays
// empty when none is set so the link keeps the app base.
func TestResolveBranding_LinkBase(t *testing.T) {
	t.Parallel()

	scope := func(project, kids string) context.Context {
		return WithProjectScope(context.Background(), &ProjectScope{
			ProjectID: "p",
			Branding:  ProjectBrandingConfig{EmailLinkBaseURL: project},
			Products:  ProjectProductsConfig{"kids": {Branding: ProjectBrandingConfig{EmailLinkBaseURL: kids}}},
		})
	}
	for _, tc := range []struct {
		name, global, project, kids, product, want string
	}{
		{"none", "", "", "", "kids", ""},
		{"global", "https://signin.example", "", "", "kids", "https://signin.example"},
		{"project over global", "https://signin.example", "https://signin.acme.example", "", "kids", "https://signin.acme.example"},
		{"product over project", "https://signin.example", "https://signin.acme.example", "https://signin.kids.acme.example", "kids", "https://signin.kids.acme.example"},
		{"unnamed product gets the project's", "https://signin.example", "https://signin.acme.example", "https://signin.kids.acme.example", "", "https://signin.acme.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{EmailLinkBaseURL: tc.global}
			assert.Equal(t, tc.want, resolveBranding(scope(tc.project, tc.kids), cfg, tc.product).linkBaseURL)
		})
	}
}

func TestBranding_ApplyTo_SetsHeadersOnlyWhenConfigured(t *testing.T) {
	t.Parallel()

	// Unset: applyTo leaves the message's existing From and omits Reply-To /
	// List-Unsubscribe entirely.
	var unset resolvedBranding
	m := email.Message{From: "legacy@example.com"}
	unset.applyTo(&m)
	assert.Equal(t, "legacy@example.com", m.From)
	assert.Empty(t, m.ReplyTo)
	assert.Empty(t, m.ListUnsubscribe)

	// Set: applyTo overrides From and adds Reply-To + List-Unsubscribe.
	set := resolvedBranding{
		from:            "brand@example.com",
		fromName:        "Brand",
		supportEmail:    "help@example.com",
		listUnsubscribe: "<mailto:unsub@example.com>",
	}
	m2 := email.Message{From: "legacy@example.com"}
	set.applyTo(&m2)
	assert.Equal(t, `"Brand" <brand@example.com>`, m2.From)
	assert.Equal(t, "help@example.com", m2.ReplyTo)
	assert.Equal(t, "<mailto:unsub@example.com>", m2.ListUnsubscribe)
}

func TestBranding_FromHeader_QuotesSpecialChars(t *testing.T) {
	t.Parallel()

	b := resolvedBranding{from: "a@b.com", fromName: `Kids, Inc. "K"`}
	got := b.fromHeader()
	// The display name is quoted and inner quotes/backslashes escaped so a
	// comma cannot split the header into two addresses.
	assert.Equal(t, `"Kids, Inc. \"K\"" <a@b.com>`, got)
}
