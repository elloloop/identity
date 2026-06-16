package service

import (
	"encoding/json"
	"fmt"
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

	// Login holds the project-wide login-method defaults applied to users
	// who have NO claimed tenant (the common case for a consumer pool). A
	// tenant's LoginPolicy, when one applies, fully overrides these.
	Login ProjectLoginConfig `json:"login"`
}

// ProjectLoginConfig is the project-wide login-method default, layered UNDER
// any tenant LoginPolicy (tenant overrides project overrides global). It lets
// an operator constrain authentication for an ENTIRE project — e.g. a kids
// pool that disables passkeys/OAuth/SSO — for users whose email domain maps
// to no claimed tenant, who would otherwise get no restriction at all.
//
// The zero value is "no project-wide restriction", so an existing project
// with empty config_json behaves exactly as before.
type ProjectLoginConfig struct {
	// AllowedMethods is a comma-separated allow-list of login method tokens
	// (see service LoginMethod*). Empty means no project-wide restriction.
	AllowedMethods string `json:"allowed_methods"`
	// Require2FA forces a second factor after the primary method for every
	// user in the project who is not governed by a tenant policy.
	Require2FA bool `json:"require_2fa"`
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
	return cfg, nil
}
