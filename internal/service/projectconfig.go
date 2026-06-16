package service

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
)

// ProjectConfig is the typed view of a project's config_json blob. It is the
// single decode target for everything an operator can configure per project
// in the control plane, so callers never reach into a raw map. New
// per-project knobs are added as fields here, not as scattered map lookups.
//
// Unknown keys are tolerated (forward compatibility): a config written by a
// newer server still decodes on an older one, ignoring fields it does not
// understand.
type ProjectConfig struct {
	// CORS holds the project's browser cross-origin policy.
	CORS ProjectCORSConfig `json:"cors"`

	// Branding holds the project's transactional-email branding. Every field
	// is optional; an unset field falls back to the global
	// GATEWAY_EMAIL_BRAND_* default (and, when that too is unset, to today's
	// byte-compatible output). This lets one server brand two products
	// (e.g. a kids app and a B2B app) distinctly.
	Branding ProjectBrandingConfig `json:"branding"`

	// Passkey holds the project's WebAuthn relying-party identity. When set,
	// it overrides the global GATEWAY_PASSKEY_* values for this project so a
	// passkey registered under one product's domain validates under that
	// product's RP-ID. Empty fields fall back to the global value.
	Passkey ProjectPasskeyConfig `json:"passkey"`
}

// ProjectBrandingConfig is the per-project transactional-email branding.
// All fields are optional. ProductName/LogoURL/PrimaryColor/SupportEmail are
// threaded into email template data; EmailFrom/EmailFromName build the SMTP
// From header; SupportEmail also drives the Reply-To header.
type ProjectBrandingConfig struct {
	// ProductName is the human-facing product name shown in email bodies
	// (e.g. "Glassa Kids"). Empty falls back to the global default.
	ProductName string `json:"product_name"`

	// EmailFrom is the bare From address for this project's mail
	// (e.g. "no-reply@kids.example.com"). Empty falls back to the global
	// default (GATEWAY_EMAIL_BRAND_FROM, else GATEWAY_SMTP_FROM).
	EmailFrom string `json:"email_from"`

	// EmailFromName is the display name shown in the From header
	// (e.g. "Glassa Kids"). Empty falls back to the global default.
	EmailFromName string `json:"email_from_name"`

	// LogoURL is an absolute https URL to the product logo, shown in HTML
	// email. Empty omits the logo (today's behaviour).
	LogoURL string `json:"logo_url"`

	// PrimaryColor is a CSS colour (e.g. "#1a73e8") used to tint branded
	// HTML email. Empty falls back to the global default.
	PrimaryColor string `json:"primary_color"`

	// SupportEmail is the address users can reply to / contact. When set it
	// drives the Reply-To header and is shown in email footers. Empty omits
	// Reply-To.
	SupportEmail string `json:"support_email"`
}

// ProjectPasskeyConfig is the per-project WebAuthn relying-party identity.
type ProjectPasskeyConfig struct {
	// RPID is the WebAuthn relying-party id (an effective domain, no scheme
	// or port, e.g. "kids.example.com"). Empty falls back to the global
	// GATEWAY_PASSKEY_RP_ID.
	RPID string `json:"rp_id"`

	// RPName is the human-facing relying-party name. Empty falls back to the
	// global GATEWAY_PASSKEY_RP_NAME.
	RPName string `json:"rp_name"`

	// Origin is the expected WebAuthn origin (scheme+host(+port), e.g.
	// "https://kids.example.com"). Empty falls back to the global
	// GATEWAY_PASSKEY_ORIGIN.
	Origin string `json:"origin"`
}

// Validate checks the optional branding/passkey blocks are well-formed when
// set. It is invariant-only: every field stays optional (an unset field is
// valid and means "fall back to the global default"); a *set* field that is
// malformed is a configuration error the write path must reject rather than
// persist a value that would later produce a broken email or a passkey that
// silently never validates.
func (c ProjectConfig) Validate() error {
	if err := c.Branding.validate(); err != nil {
		return err
	}
	if err := c.Passkey.validate(); err != nil {
		return err
	}
	return nil
}

func (b ProjectBrandingConfig) validate() error {
	if b.EmailFrom != "" {
		if _, err := mail.ParseAddress(b.EmailFrom); err != nil {
			return fmt.Errorf("branding.email_from %q is not a valid address: %w", b.EmailFrom, err)
		}
	}
	if b.SupportEmail != "" {
		if _, err := mail.ParseAddress(b.SupportEmail); err != nil {
			return fmt.Errorf("branding.support_email %q is not a valid address: %w", b.SupportEmail, err)
		}
	}
	if b.LogoURL != "" {
		if err := validateHTTPSURL(b.LogoURL, "branding.logo_url"); err != nil {
			return err
		}
	}
	return nil
}

func (p ProjectPasskeyConfig) validate() error {
	if p.RPID != "" {
		// An RP-ID is a bare effective domain: no scheme, no port, no path.
		if strings.ContainsAny(p.RPID, "/:") {
			return fmt.Errorf("passkey.rp_id %q must be a bare domain (no scheme, port, or path)", p.RPID)
		}
	}
	if p.Origin != "" {
		if err := validateHTTPURL(p.Origin, "passkey.origin"); err != nil {
			return err
		}
	}
	return nil
}

func validateHTTPSURL(raw, field string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s %q is not a valid URL: %w", field, raw, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s %q must be an absolute https:// URL", field, raw)
	}
	return nil
}

func validateHTTPURL(raw, field string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s %q is not a valid URL: %w", field, raw, err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%s %q must be an absolute http(s):// origin", field, raw)
	}
	return nil
}

// ProjectCORSConfig is the per-project CORS policy. AllowedOrigins is layered
// on top of the global GATEWAY_ALLOWED_ORIGINS floor: a browser origin is
// accepted when it is in either set. Each entry must be a bare scheme+host(+port)
// origin (no path/query/fragment, lower-case http:// or https:// scheme); the
// project resolver validates them with middleware.ParseAllowedOrigins before
// they reach a request.
type ProjectCORSConfig struct {
	AllowedOrigins []string `json:"allowed_origins"`
}

// ParseProjectConfig decodes a project's config_json into the typed
// ProjectConfig. An empty or all-whitespace blob is the zero config (no
// per-project overrides) — the same meaning the store gives "" by normalising
// it to "{}". A malformed blob is a configuration error the caller must
// surface, never silently swallow.
func ParseProjectConfig(configJSON string) (ProjectConfig, error) {
	var cfg ProjectConfig
	if strings.TrimSpace(configJSON) == "" {
		return cfg, nil
	}
	dec := json.NewDecoder(strings.NewReader(configJSON))
	if err := dec.Decode(&cfg); err != nil {
		return ProjectConfig{}, fmt.Errorf("parse project config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return ProjectConfig{}, fmt.Errorf("parse project config: %w", err)
	}
	return cfg, nil
}
