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
	b := resolveBranding(context.Background(), cfg)

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
	b := resolveBranding(context.Background(), cfg)

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
			EmailFromName: "Glassa Kids",
			SupportEmail:  "help@kids.example.com",
		},
	})
	b := resolveBranding(ctx, cfg)

	// Per-project beats global default.
	assert.Equal(t, "Kids", b.productName)
	assert.Equal(t, "no-reply@kids.example.com", b.from)
	assert.Equal(t, `"Glassa Kids" <no-reply@kids.example.com>`, b.fromHeader())
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
	b := resolveBranding(ctx, cfg)

	// EmailFrom is per-project; ProductName falls back to the global default.
	assert.Equal(t, "p@example.com", b.from)
	assert.Equal(t, "Global Product", b.productName)
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
