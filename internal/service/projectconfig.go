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
