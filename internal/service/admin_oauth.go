package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/secretcrypto"
)

// This file adds the operator-authored write/read surface for a project's
// hosted/native OAuth providers — the authoring gap the per-project OAuth
// feature left open (an operator would otherwise have to hand-craft the
// AES-GCM ciphertext of each secret and splice it into config_json by hand).
//
// The operator sends PLAINTEXT secrets over the admin API (TLS); the service
// encrypts them with the configured GATEWAY_PROJECT_SECRETS_KEY (the same key
// the resolver decrypts with) and stores them in the project's config_json.
// Reads NEVER return secret material — they report presence via has_* flags.
//
// Every write is a JSON-level READ-MODIFY-WRITE that preserves every OTHER
// config key (branding/passkey/cors/login): UpdateProjectConfig replaces the
// whole blob, so the merge decodes the top level into a raw map, replaces only
// the one provider inside the "oauth" subtree, and re-marshals. The merged
// config is validated (ProjectConfig.Validate) before it is persisted, so a bad
// provider config is rejected at author time rather than tripping the login
// path later.

// OAuth provider keys, mirroring the login `provider` argument callers pass.
const (
	oauthProviderGoogle    = "google"
	oauthProviderMicrosoft = "microsoft"
	oauthProviderApple     = "apple"
	oauthProviderOIDC      = "oidc"
)

// oauthProviderKeys is the canonical (sorted) set of configurable provider
// keys, used to enumerate a project's providers deterministically.
var oauthProviderKeys = []string{oauthProviderApple, oauthProviderGoogle, oauthProviderMicrosoft, oauthProviderOIDC}

// ProjectOAuthProviderInput is the operator-supplied authoring input for one of
// a project's OAuth providers. Secret fields (ClientSecret, ApplePrivateKey)
// are PLAINTEXT — the service encrypts them with the configured secrets key
// before storage. An EMPTY secret on a write keeps the currently-stored secret,
// so non-secret fields can be edited without re-sending it.
type ProjectOAuthProviderInput struct {
	Provider        string
	ClientID        string
	ClientSecret    string
	NativeAudiences []string

	GoogleAuthorizationURL string
	GoogleTokenURL         string
	GoogleJWKSURL          string
	GoogleIssuer           string

	MicrosoftTenantID     string
	MicrosoftIssuerFormat string

	AppleTeamID     string
	AppleKeyID      string
	ApplePrivateKey string

	OIDCIssuer       string
	OIDCDiscoveryURL string
	OIDCScopes       string
}

// ProjectOAuthProviderView is the REDACTED read view of one configured provider:
// every non-secret field plus HasClientSecret / HasPrivateKey in place of any
// secret material. No ciphertext or plaintext ever appears here.
type ProjectOAuthProviderView struct {
	Provider        string
	ClientID        string
	HasClientSecret bool
	NativeAudiences []string

	GoogleAuthorizationURL string
	GoogleTokenURL         string
	GoogleJWKSURL          string
	GoogleIssuer           string

	MicrosoftTenantID     string
	MicrosoftIssuerFormat string

	AppleTeamID   string
	AppleKeyID    string
	HasPrivateKey bool

	OIDCIssuer       string
	OIDCDiscoveryURL string
	OIDCScopes       string
}

// AdminSetProjectOAuthProvider sets (or rotates) one of a project's OAuth
// providers. It encrypts any plaintext secret in the input, merges the provider
// into the project's config_json without disturbing any other config key, and
// returns the stored provider config with secrets REDACTED. project_id and a
// known provider key are required. An unknown project surfaces ErrNotFound.
func (s *ControlPlaneAdminService) AdminSetProjectOAuthProvider(ctx context.Context, secret, projectID string, in *ProjectOAuthProviderInput) (*ProjectOAuthProviderView, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	if in == nil {
		return nil, fmt.Errorf("%w: missing config", ErrInvalidArgument)
	}
	provider, err := normalizeOAuthProvider(in.Provider)
	if err != nil {
		return nil, err
	}

	top, oauthCfg, err := s.loadOAuthConfig(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if err := s.applyProvider(provider, in, &oauthCfg); err != nil {
		return nil, err
	}
	if err := s.storeOAuthConfig(ctx, projectID, top, oauthCfg); err != nil {
		return nil, err
	}
	s.audit.Log(ctx, audit.EventProjectOAuthProviderSet, audit.WithSuccess(true), audit.WithDetails(map[string]any{
		"project_id": projectID,
		"provider":   provider,
	}))
	return providerView(provider, oauthCfg), nil
}

// AdminDeleteProjectOAuthProvider removes one provider block from a project's
// config, leaving every other provider and every other config key intact. It is
// idempotent — removing an absent provider is a no-op. An unknown project
// surfaces ErrNotFound.
func (s *ControlPlaneAdminService) AdminDeleteProjectOAuthProvider(ctx context.Context, secret, projectID, provider string) error {
	if err := s.authorize(secret); err != nil {
		return err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	provider, err := normalizeOAuthProvider(provider)
	if err != nil {
		return err
	}

	top, oauthCfg, err := s.loadOAuthConfig(ctx, projectID)
	if err != nil {
		return err
	}
	switch provider {
	case oauthProviderGoogle:
		oauthCfg.Google = nil
	case oauthProviderMicrosoft:
		oauthCfg.Microsoft = nil
	case oauthProviderApple:
		oauthCfg.Apple = nil
	case oauthProviderOIDC:
		oauthCfg.OIDC = nil
	}
	if err := s.storeOAuthConfig(ctx, projectID, top, oauthCfg); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.EventProjectOAuthProviderRemoved, audit.WithSuccess(true), audit.WithDetails(map[string]any{
		"project_id": projectID,
		"provider":   provider,
	}))
	return nil
}

// AdminListProjectOAuthProviders lists a project's configured OAuth providers,
// ordered by provider key, with secrets REDACTED. An unknown project surfaces
// ErrNotFound.
func (s *ControlPlaneAdminService) AdminListProjectOAuthProviders(ctx context.Context, secret, projectID string) ([]*ProjectOAuthProviderView, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	_, oauthCfg, err := s.loadOAuthConfig(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*ProjectOAuthProviderView, 0, len(oauthProviderKeys))
	for _, key := range oauthProviderKeys {
		if _, ok := oauthCfg.provider(key); ok {
			out = append(out, providerView(key, oauthCfg))
		}
	}
	return out, nil
}

// loadOAuthConfig reads a project's config_json and splits it into the raw
// top-level map (so every non-oauth key round-trips untouched) and the typed
// oauth subtree (so a single provider can be replaced). An unknown project
// surfaces ErrNotFound from the store; a stored blob that is not a JSON object,
// or whose oauth subtree is malformed, is an ErrInvalidArgument.
func (s *ControlPlaneAdminService) loadOAuthConfig(ctx context.Context, projectID string) (map[string]json.RawMessage, ProjectOAuthConfig, error) {
	stored, err := s.projects.GetProjectConfig(ctx, projectID)
	if err != nil {
		return nil, ProjectOAuthConfig{}, err
	}
	top := map[string]json.RawMessage{}
	if strings.TrimSpace(stored) != "" {
		if err := json.Unmarshal([]byte(stored), &top); err != nil {
			return nil, ProjectOAuthConfig{}, fmt.Errorf("%w: stored project config is not a JSON object: %s", ErrInvalidArgument, err.Error())
		}
	}
	var oauthCfg ProjectOAuthConfig
	if raw, ok := top["oauth"]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &oauthCfg); err != nil {
			return nil, ProjectOAuthConfig{}, fmt.Errorf("%w: stored oauth config is malformed: %s", ErrInvalidArgument, err.Error())
		}
	}
	return top, oauthCfg, nil
}

// storeOAuthConfig re-marshals the merged oauth subtree back into the top-level
// map (dropping the "oauth" key entirely when no provider remains, so a project
// with no providers is not left with a dangling empty object), validates the
// whole merged config, and persists it. Validation happens on the FINAL blob so
// a malformed provider — or a stale invalid neighbouring key — is rejected
// before it is written.
func (s *ControlPlaneAdminService) storeOAuthConfig(ctx context.Context, projectID string, top map[string]json.RawMessage, oauthCfg ProjectOAuthConfig) error {
	if oauthCfg.hasAny() {
		raw, err := json.Marshal(oauthCfg)
		if err != nil {
			return fmt.Errorf("marshal oauth config: %w", err)
		}
		top["oauth"] = raw
	} else {
		delete(top, "oauth")
	}
	final, err := json.Marshal(top)
	if err != nil {
		return fmt.Errorf("marshal project config: %w", err)
	}
	finalJSON := string(final)
	if _, err := ParseProjectConfig(finalJSON); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidArgument, err.Error())
	}
	_, err = s.projects.UpdateProjectConfig(ctx, projectID, finalJSON)
	return err
}

// applyProvider builds the typed provider sub-struct from the input, encrypting
// any plaintext secret, and installs it on the oauth config, replacing whatever
// was there for that provider. An empty plaintext secret keeps the currently
// stored ciphertext for that provider (if any).
func (s *ControlPlaneAdminService) applyProvider(provider string, in *ProjectOAuthProviderInput, cfg *ProjectOAuthConfig) error {
	switch provider {
	case oauthProviderGoogle:
		keep := ""
		if cfg.Google != nil {
			keep = cfg.Google.ClientSecretEnc
		}
		enc, err := s.encryptOrKeep(in.ClientSecret, keep)
		if err != nil {
			return err
		}
		cfg.Google = &ProjectOAuthGoogle{
			ClientID:         strings.TrimSpace(in.ClientID),
			ClientSecretEnc:  enc,
			AuthorizationURL: strings.TrimSpace(in.GoogleAuthorizationURL),
			TokenURL:         strings.TrimSpace(in.GoogleTokenURL),
			JWKSURL:          strings.TrimSpace(in.GoogleJWKSURL),
			Issuer:           strings.TrimSpace(in.GoogleIssuer),
			NativeAudiences:  normalizeAudiences(in.NativeAudiences),
		}
	case oauthProviderMicrosoft:
		keep := ""
		if cfg.Microsoft != nil {
			keep = cfg.Microsoft.ClientSecretEnc
		}
		enc, err := s.encryptOrKeep(in.ClientSecret, keep)
		if err != nil {
			return err
		}
		cfg.Microsoft = &ProjectOAuthMicrosoft{
			ClientID:        strings.TrimSpace(in.ClientID),
			ClientSecretEnc: enc,
			TenantID:        strings.TrimSpace(in.MicrosoftTenantID),
			IssuerFormat:    strings.TrimSpace(in.MicrosoftIssuerFormat),
			NativeAudiences: normalizeAudiences(in.NativeAudiences),
		}
	case oauthProviderApple:
		keep := ""
		if cfg.Apple != nil {
			keep = cfg.Apple.PrivateKeyEnc
		}
		enc, err := s.encryptOrKeep(in.ApplePrivateKey, keep)
		if err != nil {
			return err
		}
		cfg.Apple = &ProjectOAuthApple{
			ClientID:        strings.TrimSpace(in.ClientID),
			TeamID:          strings.TrimSpace(in.AppleTeamID),
			KeyID:           strings.TrimSpace(in.AppleKeyID),
			PrivateKeyEnc:   enc,
			NativeAudiences: normalizeAudiences(in.NativeAudiences),
		}
	case oauthProviderOIDC:
		keep := ""
		if cfg.OIDC != nil {
			keep = cfg.OIDC.ClientSecretEnc
		}
		enc, err := s.encryptOrKeep(in.ClientSecret, keep)
		if err != nil {
			return err
		}
		cfg.OIDC = &ProjectOAuthOIDC{
			ClientID:        strings.TrimSpace(in.ClientID),
			ClientSecretEnc: enc,
			Issuer:          strings.TrimSpace(in.OIDCIssuer),
			DiscoveryURL:    strings.TrimSpace(in.OIDCDiscoveryURL),
			Scopes:          strings.TrimSpace(in.OIDCScopes),
		}
	}
	return nil
}

// encryptOrKeep encrypts a plaintext secret for at-rest storage, or returns the
// existing ciphertext unchanged when the operator supplied no new secret (an
// empty plaintext means "keep whatever is stored"). Encrypting requires the
// configured secrets key; a write that carries a secret with no key configured
// is ErrProjectSecretsKeyMissing.
func (s *ControlPlaneAdminService) encryptOrKeep(plaintext, existingEnc string) (string, error) {
	if plaintext == "" {
		return existingEnc, nil
	}
	if len(s.secretsKey) == 0 {
		return "", ErrProjectSecretsKeyMissing
	}
	return secretcrypto.Encrypt(plaintext, s.secretsKey)
}

// providerView renders the redacted read view of a single configured provider.
// The provider is assumed present in cfg (callers check first).
func providerView(provider string, cfg ProjectOAuthConfig) *ProjectOAuthProviderView {
	v := &ProjectOAuthProviderView{Provider: provider}
	switch provider {
	case oauthProviderGoogle:
		g := cfg.Google
		v.ClientID = g.ClientID
		v.HasClientSecret = g.ClientSecretEnc != ""
		v.NativeAudiences = g.NativeAudiences
		v.GoogleAuthorizationURL = g.AuthorizationURL
		v.GoogleTokenURL = g.TokenURL
		v.GoogleJWKSURL = g.JWKSURL
		v.GoogleIssuer = g.Issuer
	case oauthProviderMicrosoft:
		m := cfg.Microsoft
		v.ClientID = m.ClientID
		v.HasClientSecret = m.ClientSecretEnc != ""
		v.NativeAudiences = m.NativeAudiences
		v.MicrosoftTenantID = m.TenantID
		v.MicrosoftIssuerFormat = m.IssuerFormat
	case oauthProviderApple:
		a := cfg.Apple
		v.ClientID = a.ClientID
		v.HasPrivateKey = a.PrivateKeyEnc != ""
		v.NativeAudiences = a.NativeAudiences
		v.AppleTeamID = a.TeamID
		v.AppleKeyID = a.KeyID
	case oauthProviderOIDC:
		o := cfg.OIDC
		v.ClientID = o.ClientID
		v.HasClientSecret = o.ClientSecretEnc != ""
		v.OIDCIssuer = o.Issuer
		v.OIDCDiscoveryURL = o.DiscoveryURL
		v.OIDCScopes = o.Scopes
	}
	return v
}

// normalizeAudiences trims each native-audience entry and drops the empties,
// returning nil when nothing remains (so an all-blank list is stored as absent).
func normalizeAudiences(in []string) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeOAuthProvider lower-cases/trims a provider key and rejects any that
// is not one of the four configurable providers.
func normalizeOAuthProvider(provider string) (string, error) {
	switch k := strings.ToLower(strings.TrimSpace(provider)); k {
	case oauthProviderGoogle, oauthProviderMicrosoft, oauthProviderApple, oauthProviderOIDC:
		return k, nil
	default:
		return "", fmt.Errorf("%w: unknown oauth provider %q (want %q, %q, %q, or %q)",
			ErrInvalidArgument, provider, oauthProviderGoogle, oauthProviderMicrosoft, oauthProviderApple, oauthProviderOIDC)
	}
}
