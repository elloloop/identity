package service

import (
	"context"
	"strings"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/email"
)

// resolvedBranding is the effective transactional-email branding for a single
// send: the request's per-project branding (config_json branding.*) layered on
// top of the global GATEWAY_EMAIL_BRAND_* defaults, which themselves fall back
// to today's byte-compatible behaviour. It is the single place the "per-project
// first, global default next, legacy last" precedence is decided so every email
// send path stays consistent.
type resolvedBranding struct {
	productName     string
	from            string
	fromName        string
	logoURL         string
	primaryColor    string
	supportEmail    string
	listUnsubscribe string
}

// resolveBranding computes the effective branding for the request in ctx.
//
// Precedence per field: per-project value (when set) > global default
// (GATEWAY_EMAIL_BRAND_*) > legacy. For the From address the legacy fallback is
// GATEWAY_SMTP_FROM, preserving today's output for a zero-config deployment.
func resolveBranding(ctx context.Context, cfg *config.Config) resolvedBranding {
	var p ProjectBrandingConfig
	if scope := ProjectScopeFromContext(ctx); scope != nil {
		p = scope.Branding
	}
	pick := func(project, global string) string {
		if strings.TrimSpace(project) != "" {
			return project
		}
		return global
	}
	from := pick(p.EmailFrom, cfg.EmailBrandFrom)
	if strings.TrimSpace(from) == "" {
		from = cfg.SMTPFrom
	}
	return resolvedBranding{
		productName:     pick(p.ProductName, cfg.EmailBrandProductName),
		from:            from,
		fromName:        pick(p.EmailFromName, cfg.EmailBrandFromName),
		logoURL:         pick(p.LogoURL, cfg.EmailBrandLogoURL),
		primaryColor:    pick(p.PrimaryColor, cfg.EmailBrandPrimaryColor),
		supportEmail:    pick(p.SupportEmail, cfg.EmailBrandSupportEmail),
		listUnsubscribe: cfg.EmailListUnsubscribe,
	}
}

// fromHeader builds the From header value. When a display name is configured it
// produces "Name <addr>"; otherwise the bare address (today's output). Returns
// "" when no address is configured, matching today's behaviour of leaving the
// transport's default From in place.
func (b resolvedBranding) fromHeader() string {
	addr := strings.TrimSpace(b.from)
	if addr == "" {
		return ""
	}
	name := strings.TrimSpace(b.fromName)
	if name == "" {
		return addr
	}
	return formatAddress(name, addr)
}

// applyTo fills the branding-driven envelope fields (From, Reply-To,
// List-Unsubscribe) on a message. Body fields are set by the caller.
func (b resolvedBranding) applyTo(m *email.Message) {
	if h := b.fromHeader(); h != "" {
		m.From = h
	}
	if support := strings.TrimSpace(b.supportEmail); support != "" {
		m.ReplyTo = support
	}
	if lu := strings.TrimSpace(b.listUnsubscribe); lu != "" {
		m.ListUnsubscribe = lu
	}
}

// templateData merges the branding fields into a template data map so every
// email template can render product name, logo, colour, and support address.
// An unset field is added as an empty string, which templates render as today's
// output (the field simply does not appear). The caller's existing keys are
// preserved.
func (b resolvedBranding) templateData(data map[string]any) map[string]any {
	if data == nil {
		data = map[string]any{}
	}
	data["ProductName"] = b.productName
	data["LogoURL"] = b.logoURL
	data["PrimaryColor"] = b.primaryColor
	data["SupportEmail"] = b.supportEmail
	return data
}

// formatAddress renders a display-name + address pair as an RFC 5322 mailbox.
// The name is quoted so a comma or other special character cannot break the
// header. Mirrors mail.Address.String without allocating the struct per call
// for an empty name (handled by the caller).
func formatAddress(name, addr string) string {
	escaped := strings.ReplaceAll(name, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `" <` + addr + ">"
}
